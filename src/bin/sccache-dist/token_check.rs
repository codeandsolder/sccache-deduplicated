use anyhow::{Context, Result, bail};
use sccache::dist::http::{ClientAuthCheck, ClientVisibleMsg};
use sccache::http_client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::result::Result as StdResult;
use std::sync::Mutex;
use std::time::{Duration, Instant};

// https://auth0.com/docs/jwks
#[derive(Debug, Serialize, Deserialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Jwk {
    pub kid: String,
    kty: String,
    n: String,
    e: String,
}

impl Jwk {
    fn decoding_key(&self) -> Result<jwt::DecodingKey> {
        if self.kty != "RSA" {
            bail!("Cannot handle non-RSA JWK");
        }
        jwt::DecodingKey::from_rsa_components(&self.n, &self.e)
            .context("Failed to decode RSA JWK components")
    }
}

// Check a token is equal to a fixed string
pub struct EqCheck {
    s: String,
}

impl ClientAuthCheck for EqCheck {
    fn check(&self, token: &str) -> StdResult<(), ClientVisibleMsg> {
        if self.s == token {
            Ok(())
        } else {
            warn!("{}", fixed_token_mismatch_log_message());
            Err(ClientVisibleMsg::from_nonsensitive(
                "Fixed token mismatch".to_owned(),
            ))
        }
    }
}

const fn fixed_token_mismatch_log_message() -> &'static str {
    "User token did not match configured fixed token"
}

impl EqCheck {
    pub const fn new(s: String) -> Self {
        Self { s }
    }
}

// Don't check a token is valid (it may not even be a JWT) just forward it to
// an API and check for success
pub struct ProxyTokenCheck {
    client: wreq::Client,
    maybe_auth_cache: Option<Mutex<(HashMap<String, Instant>, Duration)>>,
    url: url::Url,
}

impl ClientAuthCheck for ProxyTokenCheck {
    fn check(&self, token: &str) -> StdResult<(), ClientVisibleMsg> {
        match self.check_token_with_forwarding(token) {
            Ok(()) => Ok(()),
            Err(e) => {
                warn!("Proxying token validation failed: {e}");
                Err(ClientVisibleMsg::from_nonsensitive(
                    "Validation with token forwarding failed".to_owned(),
                ))
            }
        }
    }
}

fn url_without_query(url: &url::Url) -> String {
    let mut safe = url.clone();
    safe.set_query(None);
    safe.set_fragment(None);
    safe.to_string()
}

fn cached_token_is_valid(
    auth_cache: &mut HashMap<String, Instant>,
    cache_duration: Duration,
    token: &str,
    now: Instant,
) -> bool {
    auth_cache.retain(|_, cached_at| now.saturating_duration_since(*cached_at) < cache_duration);
    auth_cache.contains_key(token)
}

impl ProxyTokenCheck {
    /// Build a proxy-backed token checker.
    ///
    /// # Errors
    ///
    /// Returns an error if the blocking HTTP client cannot be initialized.
    pub fn new(url: &str, cache_secs: Option<u64>) -> Result<Self> {
        let maybe_auth_cache: Option<Mutex<(HashMap<String, Instant>, Duration)>> =
            cache_secs.map(|secs| Mutex::new((HashMap::new(), Duration::from_secs(secs))));
        Ok(Self {
            client: wreq::Client::builder()
                .redirect(wreq::redirect::Policy::limited(10))
                .build()?,
            maybe_auth_cache,
            url: url.parse().context("Invalid proxy token validation URL")?,
        })
    }

    fn check_token_with_forwarding(&self, token: &str) -> Result<()> {
        trace!(
            "Validating token by forwarding to {}",
            url_without_query(&self.url)
        );
        // If the token is cached and not cache has not expired, return it
        if let Some(ref auth_cache) = self.maybe_auth_cache {
            let mut guard = auth_cache
                .lock()
                .map_err(|_| anyhow::anyhow!("proxy token auth cache mutex poisoned"))?;
            let (ref mut auth_cache, cache_duration) = *guard;
            let valid = cached_token_is_valid(auth_cache, cache_duration, token, Instant::now());
            drop(guard);
            if valid {
                return Ok(());
            }
        }
        // Make a request to another API, which as a side effect should actually check the token
        let res = http_client::io_runtime()?
            .block_on(
                self.client
                    .get(self.url.as_str())
                    .bearer_auth(token)
                    .timeout(http_client::AUTH_REQUEST_TIMEOUT)
                    .send(),
            )
            .context("Failed to make request to proxying url")?;
        if !res.status().is_success() {
            bail!(
                "Token forwarded to {} returned {}",
                url_without_query(&self.url),
                res.status()
            );
        }
        // Cache the token
        if let Some(ref auth_cache) = self.maybe_auth_cache {
            let mut guard = auth_cache
                .lock()
                .map_err(|_| anyhow::anyhow!("proxy token auth cache mutex poisoned"))?;
            let (ref mut auth_cache, _) = *guard;
            auth_cache.insert(token.to_owned(), Instant::now());
            drop(guard);
        }
        Ok(())
    }
}

// Check a JWT is valid
pub struct ValidJWTCheck {
    audience: String,
    issuer: String,
    keys: HashMap<String, jwt::DecodingKey>,
}

impl ClientAuthCheck for ValidJWTCheck {
    fn check(&self, token: &str) -> StdResult<(), ClientVisibleMsg> {
        match self.check_jwt_validity(token) {
            Ok(()) => Ok(()),
            Err(e) => {
                warn!("JWT validation failed: {e}");
                Err(ClientVisibleMsg::from_nonsensitive(
                    "JWT could not be validated".to_owned(),
                ))
            }
        }
    }
}

impl ValidJWTCheck {
    pub fn new(audience: String, issuer: String, jwks_url: &str) -> Result<Self> {
        let client = wreq::Client::builder()
            .redirect(wreq::redirect::Policy::limited(10))
            .build()?;
        let res = http_client::io_runtime()?
            .block_on(
                client
                    .get(jwks_url)
                    .timeout(http_client::AUTH_REQUEST_TIMEOUT)
                    .send(),
            )
            .context("Failed to make request to JWKs url")?;
        if !res.status().is_success() {
            bail!("Could not retrieve JWKs, HTTP error: {}", res.status())
        }
        let jwks: Jwks = http_client::io_runtime()?
            .block_on(http_client::read_bounded_json_async(
                res,
                http_client::JWKS_LIMIT,
            ))
            .context("Failed to parse JWKs json")?;
        let keys = jwks
            .keys
            .into_iter()
            .map(|k| k.decoding_key().map(|key| (k.kid, key)))
            .collect::<Result<_>>()
            .context("Failed to decode JWKs")?;
        Ok(Self {
            audience,
            issuer,
            keys,
        })
    }

    fn check_jwt_validity(&self, token: &str) -> Result<()> {
        #[derive(Deserialize)]
        struct Claims {}
        jsonwebtoken_btls::install()?;
        let header = jwt::decode_header(token).context("Could not decode jwt header")?;
        trace!("Validating JWT in scheduler");
        // Prepare validation
        let kid = header.kid.context("No kid found")?;
        let key = self.keys.get(&kid).context("kid not found in jwks")?;
        let mut validation = jwt::Validation::new(header.alg);
        validation.set_audience(&[&self.audience]);
        validation.set_issuer(&[&self.issuer]);
        // Decode the JWT, discarding any claims - we just care about validity
        let _tokendata = jwt::decode::<Claims>(token, key, &validation)
            .context("Unable to validate and decode jwt")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{cached_token_is_valid, fixed_token_mismatch_log_message, url_without_query};
    use std::collections::HashMap;
    use std::time::{Duration, Instant};

    #[test]
    fn validates_rsa_jwk_components_without_der_conversion() -> anyhow::Result<()> {
        // Test-only RSA public key and signed JWT; the private key is not retained.
        let jwk = super::Jwk {
            kid: "test".to_owned(),
            kty: "RSA".to_owned(),
            n: concat!(
                "plNihBM7dUlJfdSaIFLxbReVSGxLb2-",
                "9OSrK6Jr7z12UjAe7AhrKexVsxnwvcRNOS0_GFqoAyIGf7JzJwUH7Jk_Ygtpf3ge6SnUFqbqfLcaWpIR",
                "MVC8zo24qy5M2tIKhT3uC7bqImKO_LJG0SdlCj930p69s8moYcLbOQCzhyCthsMNrWSxKXrO4EfN6f5d",
                "oaKT8S1cbSj-ApIwobC35GRnDlKeLZNnLboaa3GWSus9_5b8jg1x_vVMz8HUwinq99vIvoJ7hNEAZuje",
                "4f8hoSnVldhfHEp3Z9VTI-gfly8RnLDruC4LR8xuHbxpH6WNKz10XNVyORN-VUpY9Vsx1Ew",
            )
            .to_owned(),
            e: "AQAB".to_owned(),
        };
        let key = jwk.decoding_key()?;
        let mut checker = super::ValidJWTCheck {
            audience: "audience".to_owned(),
            issuer: "issuer".to_owned(),
            keys: HashMap::from([(jwk.kid, key)]),
        };
        let token = concat!(
            "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3QifQ.eyJhdWQiOiJhdWRpZW5jZSIsImlzcyI6Imlzc3Vlc",
            "iIsImV4cCI6NDEwMjQ0NDgwMH0.Mgf7ZwwrkTLblGdVqC6HaRABjCQecb0L6cCpvtcT2b9TgryYV_pYa",
            "mnlCJHEcF6Ae1RGgPh48wf4nNQIli6StcNdVpI5sLytgpZZQ0Eo4hH6_OZrijD7oOu1Lh21ze1DxeSkt",
            "rUkPIlpf-Z-ecYjPhuGPpKRaIYQJR8ESC_HHwongLhIKIWX2I1_VpX9QMd5AwYO7U1NTDb0Ky7QaGP8M",
            "5kC3DnuJgJgmioxLJ-",
            "e9_1AwgBPU6UYfSWZDHmqPMLlCEG6X2aQwZBiRwHfuOzMvFbR2jNeV0gkftDGFfjliInZHTq8JFMIOsD",
            "yAy3S-YaCE9nc3TPZopV0JCgSPYKXZQ",
        );
        checker.check_jwt_validity(token)?;
        checker.audience = "other".to_owned();
        assert!(checker.check_jwt_validity(token).is_err());
        checker.audience = "audience".to_owned();
        checker.issuer = "other".to_owned();
        assert!(checker.check_jwt_validity(token).is_err());
        checker.issuer = "issuer".to_owned();
        checker.keys.clear();
        assert!(checker.check_jwt_validity(token).is_err());
        Ok(())
    }

    #[test]
    fn proxy_validation_url_logs_without_query_or_fragment() -> anyhow::Result<()> {
        let url: url::Url = "https://example.test/check?api_key=secret#fragment".parse()?;
        let safe = url_without_query(&url);
        assert_eq!(safe, "https://example.test/check");
        assert!(!safe.contains("secret"));
        assert!(!safe.contains("fragment"));
        Ok(())
    }

    #[test]
    fn proxy_token_cache_prunes_expired_entries() {
        let now = Instant::now();
        let mut cache = HashMap::from([
            ("expired".to_owned(), now - Duration::from_secs(20)),
            ("fresh".to_owned(), now - Duration::from_secs(2)),
        ]);

        assert!(cached_token_is_valid(
            &mut cache,
            Duration::from_secs(10),
            "fresh",
            now,
        ));
        assert!(!cache.contains_key("expired"));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn fixed_token_mismatch_log_has_no_token_material() {
        let message = fixed_token_mismatch_log_message();
        assert!(!message.contains("supplied-secret"));
        assert!(!message.contains("configured-secret"));
    }
}
