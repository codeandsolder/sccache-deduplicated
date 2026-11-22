use anyhow::{Context, Result, bail};
use base64::Engine;
use sccache::dist::http::{ClientAuthCheck, ClientVisibleMsg};
use sccache::util::{BASE64_URL_SAFE_ENGINE, new_reqwest_blocking_client};
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
    // https://github.com/lawliet89/biscuit/issues/96#issuecomment-399149872
    pub fn to_der_pkcs1(&self) -> Result<Vec<u8>> {
        if self.kty != "RSA" {
            bail!("Cannot handle non-RSA JWK")
        }

        // JWK is big-endian, openssl bignum from_slice is big-endian
        let n = BASE64_URL_SAFE_ENGINE
            .decode(&self.n)
            .context("Failed to base64 decode n")?;
        let e = BASE64_URL_SAFE_ENGINE
            .decode(&self.e)
            .context("Failed to base64 decode e")?;
        let n_bn = openssl::bn::BigNum::from_slice(&n)
            .context("Failed to create openssl bignum from n")?;
        let e_bn = openssl::bn::BigNum::from_slice(&e)
            .context("Failed to create openssl bignum from e")?;
        let pubkey = openssl::rsa::Rsa::from_public_components(n_bn, e_bn)
            .context("Failed to create pubkey from n and e")?;
        let der: Vec<u8> = pubkey
            .public_key_to_der_pkcs1()
            .context("Failed to convert public key to der pkcs1")?;
        Ok(der)
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

fn fixed_token_mismatch_log_message() -> &'static str {
    "User token did not match configured fixed token"
}

impl EqCheck {
    pub fn new(s: String) -> Self {
        Self { s }
    }
}

// Don't check a token is valid (it may not even be a JWT) just forward it to
// an API and check for success
pub struct ProxyTokenCheck {
    client: reqwest::blocking::Client,
    maybe_auth_cache: Option<Mutex<(HashMap<String, Instant>, Duration)>>,
    url: reqwest::Url,
}

impl ClientAuthCheck for ProxyTokenCheck {
    fn check(&self, token: &str) -> StdResult<(), ClientVisibleMsg> {
        match self.check_token_with_forwarding(token) {
            Ok(()) => Ok(()),
            Err(e) => {
                warn!("Proxying token validation failed: {}", e);
                Err(ClientVisibleMsg::from_nonsensitive(
                    "Validation with token forwarding failed".to_owned(),
                ))
            }
        }
    }
}

fn url_without_query(url: &reqwest::Url) -> String {
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
    pub fn new(url: String, cache_secs: Option<u64>) -> Result<Self> {
        let maybe_auth_cache: Option<Mutex<(HashMap<String, Instant>, Duration)>> =
            cache_secs.map(|secs| Mutex::new((HashMap::new(), Duration::from_secs(secs))));
        Ok(Self {
            client: new_reqwest_blocking_client()?,
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
            let mut auth_cache = auth_cache
                .lock()
                .map_err(|_| anyhow::anyhow!("proxy token auth cache mutex poisoned"))?;
            let (ref mut auth_cache, cache_duration) = *auth_cache;
            if cached_token_is_valid(auth_cache, cache_duration, token, Instant::now()) {
                return Ok(());
            }
        }
        // Make a request to another API, which as a side effect should actually check the token
        let res = self
            .client
            .get(self.url.clone())
            .bearer_auth(token)
            .send()
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
            let mut auth_cache = auth_cache
                .lock()
                .map_err(|_| anyhow::anyhow!("proxy token auth cache mutex poisoned"))?;
            let (ref mut auth_cache, _) = *auth_cache;
            auth_cache.insert(token.to_owned(), Instant::now());
        }
        Ok(())
    }
}

// Check a JWT is valid
pub struct ValidJWTCheck {
    audience: String,
    issuer: String,
    kid_to_pkcs1: HashMap<String, Vec<u8>>,
}

impl ClientAuthCheck for ValidJWTCheck {
    fn check(&self, token: &str) -> StdResult<(), ClientVisibleMsg> {
        match self.check_jwt_validity(token) {
            Ok(()) => Ok(()),
            Err(e) => {
                warn!("JWT validation failed: {}", e);
                Err(ClientVisibleMsg::from_nonsensitive(
                    "JWT could not be validated".to_owned(),
                ))
            }
        }
    }
}

impl ValidJWTCheck {
    pub fn new(audience: String, issuer: String, jwks_url: &str) -> Result<Self> {
        let res = reqwest::blocking::get(jwks_url).context("Failed to make request to JWKs url")?;
        if !res.status().is_success() {
            bail!("Could not retrieve JWKs, HTTP error: {}", res.status())
        }
        let jwks: Jwks = res.json().context("Failed to parse JWKs json")?;
        let kid_to_pkcs1 = jwks
            .keys
            .into_iter()
            .map(|k| k.to_der_pkcs1().map(|pkcs1| (k.kid, pkcs1)))
            .collect::<Result<_>>()
            .context("Failed to convert JWKs into pkcs1")?;
        Ok(Self {
            audience,
            issuer,
            kid_to_pkcs1,
        })
    }

    fn check_jwt_validity(&self, token: &str) -> Result<()> {
        let header = jwt::decode_header(token).context("Could not decode jwt header")?;
        trace!("Validating JWT in scheduler");
        // Prepare validation
        let kid = header.kid.context("No kid found")?;
        let pkcs1 = jwt::DecodingKey::from_rsa_der(
            self.kid_to_pkcs1
                .get(&kid)
                .context("kid not found in jwks")?,
        );
        let mut validation = jwt::Validation::new(header.alg);
        validation.set_audience(&[&self.audience]);
        validation.set_issuer(&[&self.issuer]);
        #[derive(Deserialize)]
        struct Claims {}
        // Decode the JWT, discarding any claims - we just care about validity
        let _tokendata = jwt::decode::<Claims>(token, &pkcs1, &validation)
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
    fn proxy_validation_url_logs_without_query_or_fragment() -> anyhow::Result<()> {
        let url: reqwest::Url = "https://example.test/check?api_key=secret#fragment".parse()?;
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
