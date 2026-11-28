//! Parsed cfg/check-cfg result identity. Rustc validates the original arguments
//! during dependency discovery; retain the raw specifications if this parser
//! encounters a newer grammar. No compiler invocation is needed for keying.
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};

use syn::{
    Ident, LitStr, Token,
    ext::IdentExt,
    parenthesized,
    parse::{Parse, ParseStream},
};

fn identifier(input: ParseStream<'_>) -> syn::Result<String> {
    Ok(input.call(Ident::parse_any)?.unraw().to_string())
}

struct Predicate {
    name: String,
    value: Option<String>,
}

impl Parse for Predicate {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let name = identifier(input)?;
        let value = if input.peek(Token![=]) {
            input.parse::<Token![=]>()?;
            Some(input.parse::<LitStr>()?.value())
        } else {
            None
        };
        Ok(Self { name, value })
    }
}

pub(super) fn predicate(value: &OsStr) -> OsString {
    let Some(parsed) = value
        .to_str()
        .and_then(|value| syn::parse_str::<Predicate>(value).ok())
    else {
        return value.to_owned();
    };
    parsed.value.map_or_else(
        || OsString::from(&parsed.name),
        |value| format!("{}={value:?}", parsed.name).into(),
    )
}

#[derive(Clone)]
enum ExpectedValues {
    Set(BTreeSet<Option<String>>),
    Any,
}

impl ExpectedValues {
    fn merge(&mut self, other: Self) {
        match (self, other) {
            (slot, other @ Self::Any) => *slot = other,
            (Self::Set(existing), Self::Set(values)) => existing.extend(values),
            _ => {}
        }
    }

    fn specification(&self) -> String {
        match self {
            Self::Any => "any()".into(),
            Self::Set(values) => values
                .iter()
                .map(|value| {
                    value
                        .as_ref()
                        .map_or_else(|| "none()".into(), |value| format!("{value:?}"))
                })
                .collect::<Vec<_>>()
                .join(","),
        }
    }
}

fn empty_call(input: ParseStream<'_>) -> syn::Result<()> {
    let arguments;
    parenthesized!(arguments in input);
    if !arguments.is_empty() {
        return Err(arguments.error("expected an empty call"));
    }
    Ok(())
}

fn expected_values(input: ParseStream<'_>) -> syn::Result<ExpectedValues> {
    let arguments;
    parenthesized!(arguments in input);
    let mut values = BTreeSet::new();
    let mut any = false;
    while !arguments.is_empty() {
        if arguments.peek(LitStr) {
            values.insert(Some(arguments.parse::<LitStr>()?.value()));
        } else {
            match identifier(&arguments)?.as_str() {
                "none" => {
                    empty_call(&arguments)?;
                    values.insert(None);
                }
                "any" if !any => {
                    empty_call(&arguments)?;
                    any = true;
                }
                _ => return Err(arguments.error("unknown expected value")),
            }
        }
        if !arguments.is_empty() {
            arguments.parse::<Token![,]>()?;
        }
    }
    if any {
        if !values.is_empty() {
            return Err(arguments.error("any() must not specify concrete values"));
        }
        Ok(ExpectedValues::Any)
    } else {
        Ok(ExpectedValues::Set(values))
    }
}

struct Specification {
    any_name: bool,
    names: Vec<String>,
    values: ExpectedValues,
}

impl Parse for Specification {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        if identifier(input)? != "cfg" {
            return Err(input.error("expected cfg"));
        }
        let arguments;
        parenthesized!(arguments in input);
        let mut any_name = false;
        let mut names = Vec::new();
        let mut values = None;
        while !arguments.is_empty() {
            let name = identifier(&arguments)?;
            if arguments.peek(syn::token::Paren) {
                match name.as_str() {
                    "any" if !any_name => {
                        empty_call(&arguments)?;
                        any_name = true;
                    }
                    "values" if !names.is_empty() && values.is_none() => {
                        values = Some(expected_values(&arguments)?);
                    }
                    _ => return Err(arguments.error("unknown cfg expectation")),
                }
            } else if values.is_none() {
                names.push(name);
            } else {
                return Err(arguments.error("cfg names must precede values"));
            }
            if !arguments.is_empty() {
                arguments.parse::<Token![,]>()?;
            }
        }
        if any_name && (!names.is_empty() || values.is_some()) {
            return Err(arguments.error("any() must be isolated"));
        }
        let values = values.unwrap_or_else(|| ExpectedValues::Set(BTreeSet::from([None])));
        Ok(Self {
            any_name,
            names,
            values,
        })
    }
}

/// The compiler merges repeated specs by name; any-value dominates sets,
/// and any-name disables exhaustive names without disabling value checking.
/// An empty specification still enables checking of the well-known cfgs.
pub(super) fn expectations(specifications: &[OsString]) -> Option<Vec<OsString>> {
    if specifications.is_empty() {
        return Some(Vec::new());
    }
    let mut any_name = false;
    let mut expecteds = BTreeMap::<String, ExpectedValues>::new();
    for spec in specifications {
        let Specification {
            any_name: any,
            names,
            values,
        } = syn::parse_str(spec.to_str()?).ok()?;
        any_name |= any;
        for name in names {
            expecteds
                .entry(name)
                .and_modify(|existing| existing.merge(values.clone()))
                .or_insert_with(|| values.clone());
        }
    }
    let mut normalized = vec![if any_name {
        "cfg(any())".into()
    } else {
        "cfg()".into()
    }];
    normalized.extend(
        expecteds
            .into_iter()
            .map(|(name, values)| format!("cfg({name},values({}))", values.specification()).into()),
    );
    Some(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(specs: &[&str]) -> Option<Vec<OsString>> {
        expectations(&specs.iter().map(OsString::from).collect::<Vec<_>>())
    }

    #[test]
    fn cfg_predicates_decode_rust_literals_and_raw_identifiers() {
        assert_eq!(
            predicate(OsStr::new(" r#feature = r#\"some,value\"# ")),
            "feature=\"some,value\""
        );
        assert_eq!(
            predicate(OsStr::new(r#"feature="\u{61}""#)),
            "feature=\"a\""
        );
        assert_ne!(
            predicate(OsStr::new("foo")),
            predicate(OsStr::new("foo=\"\""))
        );
    }

    #[test]
    fn check_cfg_unions_names_and_values() {
        assert_eq!(
            key(&[
                r#"cfg(b, a, values("two", "one"))"#,
                r#"cfg(a, values("one", none()))"#,
                "cfg(b, values(any()))"
            ]),
            key(&[
                "cfg(b, values(any()))",
                r#"cfg(a, values(none(), "one", "two"))"#
            ])
        );
        assert_eq!(
            key(&["cfg(foo)", "cfg()", "cfg(foo, values(none()))"]),
            key(&["cfg(foo)"])
        );
        assert_eq!(
            key(&["cfg(any())", "cfg(foo, values())"]),
            key(&["cfg(foo, values())", "cfg(any())", "cfg()"])
        );
        assert_eq!(
            key(&[r##"cfg(foo, values(r#"a,b"#, "\u{61}"))"##]),
            key(&[r#"cfg(foo, values("a", "a,b"))"#])
        );
        assert_ne!(key(&[]), key(&["cfg()"]));
        assert_ne!(key(&["cfg(any())"]), key(&["cfg()"]));
        assert_ne!(key(&["cfg(foo, values())"]), key(&["cfg(foo)"]));
        assert_ne!(key(&["cfg(foo, values(any()))"]), key(&["cfg(foo)"]));
        assert!(key(&["cfg(foo, future_extension())"]).is_none());
    }
}
