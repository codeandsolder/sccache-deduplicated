//! Canonical Rust result-key arguments. The compiler's actual argv remains
//! unchanged: discovery validates it, and both diagnostics and compilation
//! still see the original options. These reductions follow rustc's parsed
//! `CodegenOptions` fields, not the surface syntax of its CLI.
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};

pub(super) type ArgumentPair = (OsString, Option<OsString>);

/// rustc's option lookup treats underscores and hyphens identically. Some
/// higher-level rustc consumers still look at literal spellings (notably -O),
/// so callers must not use this to rewrite arbitrary execution arguments.
pub(super) fn option_is(actual: &str, expected: &str) -> bool {
    actual
        .bytes()
        .map(|byte| if byte == b'_' { b'-' } else { byte })
        .eq(expected.bytes())
}

#[derive(Clone, Copy)]
enum Field {
    Last,
    AppendWords,
    AppendArgument,
    AppendFeatures,
    FramePointer,
    Ordered,
}

/// These are the setter semantics in `rustc_session`'s `CodegenOptions` table.
/// Cross-group mitigation flags and unknown options retain their raw position.
fn codegen_field(name: &str) -> Option<Field> {
    Some(match name {
        "metadata" | "llvm-args" | "passes" | "link-args" => Field::AppendWords,
        "link-arg" => Field::AppendArgument,
        "target-feature" => Field::AppendFeatures,
        "force-frame-pointers" => Field::FramePointer,
        "link-self-contained" | "linker-features" | "remark" => Field::Ordered,
        "code-model"
        | "codegen-units"
        | "collapse-macro-debuginfo"
        | "debug-assertions"
        | "debuginfo"
        | "default-linker-libraries"
        | "dlltool"
        | "dwarf-version"
        | "embed-bitcode"
        | "embed-metadata"
        | "extra-filename"
        | "force-unwind-tables"
        | "instrument-coverage"
        | "jump-tables"
        | "link-dead-code"
        | "linker"
        | "linker-flavor"
        | "linker-plugin-lto"
        | "lto"
        | "no-prepopulate-passes"
        | "no-redzone"
        | "no-vectorize-loops"
        | "no-vectorize-slp"
        | "opt-level"
        | "overflow-checks"
        | "panic"
        | "prefer-dynamic"
        | "profile-generate"
        | "profile-sample-use"
        | "profile-use"
        | "relocation-model"
        | "relro-level"
        | "rpath"
        | "save-temps"
        | "split-debuginfo"
        | "strip"
        | "symbol-mangling-version"
        | "target-cpu"
        | "unsafe-allow-abi-mismatch" => Field::Last,
        _ => return None,
    })
}

fn boolean(value: Option<&str>) -> Option<&'static str> {
    match value {
        None | Some("y" | "yes" | "on" | "true") => Some("yes"),
        Some("n" | "no" | "off" | "false") => Some("no"),
        _ => None,
    }
}

fn frame_pointer(value: Option<&str>) -> Option<u8> {
    match value {
        Some("non-leaf") => Some(1),
        Some("always") => Some(2),
        _ => boolean(value).map(|value| if value == "yes" { 2 } else { 0 }),
    }
}

/// Only canonicalize equivalent parsed values. In particular an explicitly
/// set optional boolean is not the same as the compiler's absent default.
fn scalar(name: &str, value: Option<&str>) -> Option<String> {
    let normalized = match name {
        "debuginfo" => match value {
            Some("0" | "none") => Some("none"),
            Some("1" | "limited") => Some("limited"),
            Some("2" | "full") => Some("full"),
            _ => value,
        },
        "debug-assertions"
        | "default-linker-libraries"
        | "embed-bitcode"
        | "embed-metadata"
        | "force-unwind-tables"
        | "jump-tables"
        | "link-dead-code"
        | "no-redzone"
        | "overflow-checks"
        | "prefer-dynamic"
        | "rpath"
        | "save-temps"
        | "linker-plugin-lto" => boolean(value).or(value),
        "instrument-coverage" => match value {
            Some("all") => Some("yes"),
            Some("0") => Some("no"),
            _ => boolean(value).or(value),
        },
        "lto" => value.map(|value| boolean(Some(value)).unwrap_or(value)),
        _ => value,
    };
    if matches!(name, "codegen-units" | "dwarf-version") {
        return normalized.map(|value| {
            value
                .parse::<u64>()
                .map_or_else(|_| value.to_owned(), |value| value.to_string())
        });
    }
    if name == "unsafe-allow-abi-mismatch" {
        return normalized.map(|value| {
            let mut values: Vec<_> = value.split(',').collect();
            values.sort_unstable();
            values.join(",")
        });
    }
    normalized.map(str::to_owned)
}

fn static_default(name: &str) -> Option<&'static str> {
    match name {
        "opt-level" => Some("0"),
        "debuginfo" | "strip" => Some("none"),
        "extra-filename" => Some(""),
        "embed-bitcode" | "jump-tables" => Some("yes"),
        "default-linker-libraries"
        | "instrument-coverage"
        | "linker-plugin-lto"
        | "prefer-dynamic"
        | "rpath"
        | "save-temps" => Some("no"),
        _ => None,
    }
}

#[derive(Default)]
struct CodegenFields(BTreeMap<String, Vec<Option<String>>>);

impl CodegenFields {
    /// A shared destination field for `link-arg` and `link-args` preserves
    /// their exact interleaving, including single arguments containing spaces.
    fn insert(&mut self, name: String, value: Option<&str>, field: Field) {
        match field {
            Field::Last => {
                let value = scalar(&name, value);
                if static_default(&name).is_some_and(|default| value.as_deref() == Some(default)) {
                    self.0.remove(&name);
                } else {
                    self.0.insert(name, vec![value]);
                }
            }
            Field::AppendWords => {
                let name = if name == "link-args" {
                    "link-arg".to_owned()
                } else {
                    name
                };
                if let Some(value) = value {
                    self.0
                        .entry(name)
                        .or_default()
                        .extend(value.split_whitespace().map(|word| Some(word.to_owned())));
                }
            }
            Field::AppendFeatures => {
                if let Some(value) = value {
                    let values = self.0.entry(name).or_default();
                    if let Some(Some(previous)) = values.last_mut() {
                        if !previous.is_empty() {
                            previous.push(',');
                        }
                        previous.push_str(value);
                    } else {
                        values.push(Some(value.to_owned()));
                    }
                }
            }
            Field::FramePointer => {
                // rustc ratchets this field, it does not use last-wins.
                let Some(rank) = frame_pointer(value) else {
                    return;
                };
                if rank == 0 {
                    return;
                }
                let previous = self
                    .0
                    .get(&name)
                    .and_then(|values| values.first())
                    .and_then(|value| frame_pointer(value.as_deref()))
                    .unwrap_or(0);
                if rank > previous {
                    self.0.insert(
                        name,
                        vec![Some(
                            if rank == 2 { "always" } else { "non-leaf" }.to_owned(),
                        )],
                    );
                }
            }
            Field::AppendArgument | Field::Ordered => {
                self.0
                    .entry(name)
                    .or_default()
                    .push(value.map(str::to_owned));
            }
        }
    }

    fn into_pairs(self) -> impl Iterator<Item = ArgumentPair> {
        self.0.into_iter().flat_map(|(name, values)| {
            values.into_iter().filter_map(move |value| {
                // An empty feature list is the initial empty string. Empty
                // *individual linker arguments*, by contrast, are significant.
                if name == "target-feature" && value.as_deref() == Some("") {
                    return None;
                }
                Some((
                    "-C".into(),
                    Some(
                        value
                            .map_or_else(|| name.clone(), |value| format!("{name}={value}"))
                            .into(),
                    ),
                ))
            })
        })
    }
}

/// The early rustc pass validates the original options. The result key keeps
/// ordered options, independently parsed codegen fields, and set-valued
/// emission/cfg requests separate. -O/-g are *not* aliases for -C values:
/// rustc tracks both the raw codegen field and the final top-level setting.
pub(super) fn normalize(arguments: &[ArgumentPair], target: Option<&OsStr>) -> Vec<ArgumentPair> {
    let mut short_opt = false;
    let mut short_debug = false;
    let mut ordered = Vec::new();
    let mut cfg = BTreeSet::new();
    let mut check_cfg = Vec::new();
    let mut emit = BTreeSet::new();
    let mut fields = CodegenFields::default();
    for (flag, value) in arguments {
        match flag.to_str() {
            Some("--extern" | "-L" | "--out-dir" | "--target") => continue,
            Some("-O") => {
                short_opt = true;
                continue;
            }
            Some("-g") => {
                short_debug = true;
                continue;
            }
            Some("--cfg") => {
                cfg.insert(value.as_deref().map(super::rust_key_cfg::predicate));
                continue;
            }
            Some("--check-cfg") => {
                if let Some(value) = value {
                    check_cfg.push(value.clone());
                    continue;
                }
            }
            Some("--emit") => {
                if let Some(value) = value.as_ref().and_then(|value| value.to_str()) {
                    emit.extend(value.split(','));
                    continue;
                }
            }
            Some("-C" | "--codegen") => {
                if let Some(value) = value.as_ref().and_then(|value| value.to_str()) {
                    let (name, value) = value
                        .split_once('=')
                        .map_or((value, None), |(name, value)| (name, Some(value)));
                    let canonical = name.replace('_', "-");
                    if let Some(field) = codegen_field(&canonical) {
                        // The top-level -O selector recognizes only the literal
                        // hyphenated spelling; the raw codegen field accepts both.
                        if name == "opt-level" {
                            short_opt = false;
                        }
                        if name == "debuginfo" {
                            short_debug = false;
                        }
                        fields.insert(canonical, value, field);
                        continue;
                    }
                }
            }
            _ => {}
        }
        ordered.push((flag.clone(), value.clone()));
    }
    if let Some(target) = target {
        ordered.push(("--target".into(), Some(target.to_owned())));
    }
    if !emit.is_empty() {
        ordered.push((
            "--emit".into(),
            Some(emit.into_iter().collect::<Vec<_>>().join(",").into()),
        ));
    }
    let short_changes_field = |name, forced| {
        fields
            .0
            .get(name)
            .and_then(|values| values.last())
            .and_then(|value| value.as_deref())
            != Some(forced)
    };
    if short_opt && short_changes_field("opt-level", "3") {
        ordered.push(("-O".into(), None));
    }
    if short_debug && short_changes_field("debuginfo", "full") {
        ordered.push(("-g".into(), None));
    }
    ordered.extend(fields.into_pairs());
    ordered.extend(cfg.into_iter().map(|value| ("--cfg".into(), value)));
    let check_cfg = super::rust_key_cfg::expectations(&check_cfg).unwrap_or_else(|| {
        log::debug!("Unrecognized rustc check-cfg grammar; retaining original specifications");
        check_cfg
    });
    ordered.extend(
        check_cfg
            .into_iter()
            .map(|value| ("--check-cfg".into(), Some(value))),
    );
    ordered
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(args: &[(&str, Option<&str>)]) -> Vec<ArgumentPair> {
        normalize(
            &args
                .iter()
                .map(|(name, value)| ((*name).into(), value.map(OsString::from)))
                .collect::<Vec<_>>(),
            None,
        )
    }

    #[test]
    fn target_key_uses_resolved_identity() {
        let explicit = vec![("--target".into(), Some("/checkout/alpha.json".into()))];
        assert_eq!(normalize(&explicit, None), normalize(&[], None));
        let alpha = normalize(&explicit, Some(OsStr::new("alpha.json")));
        assert_eq!(alpha, normalize(&[], Some(OsStr::new("alpha.json"))));
        assert_ne!(alpha, normalize(&explicit, Some(OsStr::new("beta.json"))));
        assert_ne!(alpha, normalize(&explicit, Some(OsStr::new("alpha"))));
    }

    #[test]
    fn codegen_values_and_independent_fields_are_canonical() {
        assert_eq!(
            key(&[
                ("-C", Some("opt-level=1")),
                ("--codegen", Some("opt_level=2")),
                ("-C", Some("embed-bitcode=false")),
                ("-C", Some("debuginfo=1"))
            ]),
            key(&[
                ("-C", Some("debuginfo=limited")),
                ("-C", Some("embed-bitcode=no")),
                ("-C", Some("opt-level=2"))
            ])
        );
        assert_eq!(
            key(&[
                ("-C", Some("opt-level=2")),
                ("-C", Some("opt-level=0")),
                ("-C", Some("debuginfo=0")),
                ("-C", Some("embed-bitcode=yes"))
            ]),
            key(&[])
        );
        assert_ne!(key(&[("-C", Some("debug-assertions=yes"))]), key(&[]));
        assert_ne!(key(&[("-C", Some("overflow-checks=yes"))]), key(&[]));
        assert_eq!(
            key(&[("--emit", Some("link,metadata,link"))]),
            key(&[("--emit", Some("metadata")), ("--emit", Some("link"))])
        );
        assert_ne!(
            key(&[("--emit", Some("link,metadata,dep-info"))]),
            key(&[("--emit", Some("link,metadata"))])
        );
    }

    #[test]
    fn accumulated_values_preserve_semantic_order_and_boundaries() {
        assert_eq!(
            key(&[
                ("-C", Some("metadata=one two")),
                ("-C", Some("target-feature=+sse2,-avx"))
            ]),
            key(&[
                ("-C", Some("target_feature=+sse2")),
                ("-C", Some("metadata=one")),
                ("-C", Some("target-feature=-avx")),
                ("-C", Some("metadata=two"))
            ])
        );
        assert_ne!(
            key(&[("-C", Some("metadata=one two"))]),
            key(&[("-C", Some("metadata=two one"))])
        );
        assert_eq!(
            key(&[
                ("-C", Some("link-arg=a")),
                ("-C", Some("link_args=b c")),
                ("-C", Some("link-arg=d e"))
            ]),
            key(&[
                ("-C", Some("link-args=a b c")),
                ("-C", Some("link-arg=d e"))
            ])
        );
        assert_ne!(
            key(&[("-C", Some("link-args=a b"))]),
            key(&[("-C", Some("link-arg=a b"))])
        );
        assert_ne!(
            key(&[("-C", Some("target-feature=+avx,-avx"))]),
            key(&[("-C", Some("target-feature=-avx,+avx"))])
        );
    }

    #[test]
    fn short_flags_keep_both_raw_and_effective_settings() {
        assert_eq!(
            key(&[("-O", None), ("-C", Some("opt-level=2"))]),
            key(&[("-C", Some("opt-level=2"))])
        );
        assert_eq!(
            key(&[("-g", None), ("-C", Some("debuginfo=full"))]),
            key(&[("-C", Some("debuginfo=2"))])
        );
        assert_eq!(
            key(&[("-O", None), ("-C", Some("opt_level=2"))]),
            key(&[("-C", Some("opt-level=2")), ("-O", None)])
        );
        assert_ne!(
            key(&[("-O", None), ("-C", Some("opt_level=2"))]),
            key(&[("-C", Some("opt-level=2"))])
        );
        assert_eq!(
            key(&[
                ("-O", None),
                ("-C", Some("opt-level=1")),
                ("-C", Some("opt_level=2"))
            ]),
            key(&[("-C", Some("opt-level=2"))])
        );
        assert_eq!(
            key(&[
                ("-C", Some("force-frame-pointers=yes")),
                ("-C", Some("force-frame-pointers=no"))
            ]),
            key(&[("-C", Some("force-frame-pointers=yes"))])
        );
        assert_ne!(key(&[("-O", None)]), key(&[("-C", Some("opt-level=3"))]));
        assert_ne!(key(&[("-g", None)]), key(&[("-C", Some("debuginfo=2"))]));
        assert_ne!(
            key(&[("-O", None), ("-C", Some("opt-level=0"))]),
            key(&[("-C", Some("opt-level=0")), ("-O", None)])
        );
        assert_ne!(
            key(&[
                ("-C", Some("control-flow-guard=no")),
                ("-Z", Some("allow-partial-mitigations=control-flow-guard"))
            ]),
            key(&[
                ("-Z", Some("allow-partial-mitigations=control-flow-guard")),
                ("-C", Some("control-flow-guard=no"))
            ])
        );
        assert_ne!(
            key(&[
                ("-C", Some("force-frame-pointers=yes")),
                ("-C", Some("force-frame-pointers=no"))
            ]),
            key(&[("-C", Some("force-frame-pointers=no"))])
        );
    }
}
