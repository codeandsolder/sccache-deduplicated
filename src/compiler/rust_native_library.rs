//! Native library selection follows the compiler's expanded foreign modules,
//! then applies command-line overrides in rustc's order. Archive discovery
//! uses this same list for both result identity and the execution input tree.
use super::native_archive::ArchiveUse;
use crate::errors::{Context, Result};
use proc_macro2::{Delimiter, Group, TokenStream, TokenTree};
use syn::{
    Ident, LitStr, Token,
    ext::IdentExt,
    parenthesized,
    parse::{Parse, ParseStream},
};

#[derive(Clone, Debug, PartialEq, Eq)]
enum Kind {
    Unspecified,
    Static { bundle: bool, whole_archive: bool },
    Other,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Library {
    name: String,
    kind: Kind,
    verbatim: bool,
    conditional: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CommandLibrary {
    library: Library,
    rename: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ArchiveRequest {
    pub name: String,
    pub verbatim: bool,
    pub usage: ArchiveUse,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct NativeLibraries {
    command_line: Vec<CommandLibrary>,
    pub packed: bool,
    pub source_directives: bool,
}

impl Default for NativeLibraries {
    fn default() -> Self {
        Self {
            command_line: Vec::new(),
            packed: false,
            source_directives: true,
        }
    }
}

impl Library {
    fn new(name: String, kind: Option<&str>, modifiers: &str, conditional: bool) -> Self {
        let has = |modifier| modifiers.split(',').any(|value| value == modifier);
        let kind = match kind {
            None => Kind::Unspecified,
            Some("static") => Kind::Static {
                bundle: !has("-bundle"),
                whole_archive: has("+whole-archive"),
            },
            Some(_) => Kind::Other,
        };
        Self {
            name,
            kind,
            verbatim: has("+verbatim"),
            conditional,
        }
    }

    fn archive(&self, usage: ArchiveUse) -> ArchiveRequest {
        ArchiveRequest {
            name: self.name.clone(),
            verbatim: self.verbatim,
            usage,
        }
    }
}

impl NativeLibraries {
    pub fn push(&mut self, kind: Option<&str>, name: &str) {
        let (kind, modifiers) = kind.map_or((None, ""), |kind| {
            let (kind, modifiers) = kind.split_once(':').unwrap_or((kind, ""));
            (Some(kind), modifiers)
        });
        let (name, rename) = name.split_once(':').map_or((name, None), |(name, rename)| {
            (name, Some(rename.to_owned()))
        });
        self.command_line.push(CommandLibrary {
            library: Library::new(name.to_owned(), kind, modifiers, false),
            rename,
        });
    }

    /// rustc moves every previous mention of a library to the end, applying
    /// the specified kind and rename without erasing its source cfg predicate.
    fn resolve(&self, mut source: Vec<Library>) -> Vec<Library> {
        if !self.source_directives {
            source.clear();
        }
        for command in &self.command_line {
            let passed = &command.library;
            let mut matching = source
                .extract_if(.., |library| library.name == passed.name)
                .collect::<Vec<_>>();
            if matching.is_empty() {
                matching.push(passed.clone());
            }
            for library in &mut matching {
                if passed.kind != Kind::Unspecified {
                    library.kind = passed.kind.clone();
                }
                if let Some(rename) = &command.rename {
                    library.name.clone_from(rename);
                }
                library.verbatim = passed.verbatim;
            }
            source.append(&mut matching);
        }
        source
    }

    pub fn archive_requests(
        &self,
        source: Vec<Library>,
        rlib: bool,
        staticlib: bool,
        link: bool,
    ) -> Vec<ArchiveRequest> {
        let mut requests = Vec::new();
        for library in self.resolve(source) {
            let Kind::Static {
                bundle,
                whole_archive,
            } = library.kind
            else {
                if link && library.kind == Kind::Unspecified {
                    requests.push(library.archive(ArchiveUse::Link));
                }
                continue;
            };
            if bundle {
                let packed = rlib && (self.packed || library.conditional || whole_archive);
                if packed {
                    requests.push(library.archive(ArchiveUse::Packed));
                }
                if staticlib || (rlib && !packed) {
                    requests.push(library.archive(ArchiveUse::Members));
                }
            }
            if link {
                requests.push(library.archive(ArchiveUse::Link));
            }
        }
        requests
    }
}

struct LinkAttribute(Library);

impl Parse for LinkAttribute {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let attribute = input.call(Ident::parse_any)?;
        if attribute.unraw() != "link" {
            return Err(input.error("expected link attribute"));
        }
        let arguments;
        parenthesized!(arguments in input);
        let mut name = None;
        let mut kind = None;
        let mut modifiers = String::new();
        let mut conditional = false;
        while !arguments.is_empty() {
            let field = arguments.call(Ident::parse_any)?.unraw().to_string();
            if field == "cfg" {
                let predicate;
                parenthesized!(predicate in arguments);
                let _: TokenStream = predicate.parse()?;
                conditional = true;
            } else {
                arguments.parse::<Token![=]>()?;
                let value = arguments.parse::<LitStr>()?.value();
                match field.as_str() {
                    "name" => name = Some(value),
                    "kind" => kind = Some(value),
                    "modifiers" => modifiers = value,
                    // DLL import naming is not a static archive input.
                    _ => {}
                }
            }
            if !arguments.is_empty() {
                arguments.parse::<Token![,]>()?;
            }
        }
        Ok(Self(Library::new(
            name.ok_or_else(|| input.error("native link attribute has no name"))?,
            kind.as_deref(),
            &modifiers,
            conditional,
        )))
    }
}

fn ident(token: Option<&TokenTree>, value: &str) -> bool {
    matches!(token, Some(TokenTree::Ident(ident)) if ident.unraw() == value)
}

fn punct(token: Option<&TokenTree>, value: char) -> bool {
    matches!(token, Some(TokenTree::Punct(punct)) if punct.as_char() == value)
}

fn group(token: Option<&TokenTree>, delimiter: Delimiter) -> Option<&Group> {
    match token {
        Some(TokenTree::Group(group)) if group.delimiter() == delimiter => Some(group),
        _ => None,
    }
}

fn attribute(tokens: &[TokenTree], start: usize) -> Option<(&Group, bool, usize)> {
    if !punct(tokens.get(start), '#') {
        return None;
    }
    let inner = punct(tokens.get(start + 1), '!');
    let index = start + 1 + usize::from(inner);
    Some((
        group(tokens.get(index), Delimiter::Bracket)?,
        inner,
        index + 1,
    ))
}

fn collect_link_attribute(attribute: &Group, libraries: &mut Vec<Library>) -> Result<()> {
    let tokens = attribute.stream();
    if ident(tokens.clone().into_iter().next().as_ref(), "link") {
        libraries.push(
            syn::parse2::<LinkAttribute>(tokens)
                .context("parse expanded native link attribute")?
                .0,
        );
    }
    Ok(())
}

/// The expanded AST keeps macro definitions, but ordinary invocations have
/// already been expanded. Do not visit definition bodies. Compiler built-ins
/// such as format_args! and asm! are printed using macro syntax even after
/// expansion; their real expression operands must still be visited.
fn macro_definition_end(tokens: &[TokenTree], start: usize) -> Option<usize> {
    if ident(tokens.get(start), "macro_rules")
        && punct(tokens.get(start + 1), '!')
        && matches!(tokens.get(start + 2), Some(TokenTree::Ident(_)))
        && matches!(tokens.get(start + 3), Some(TokenTree::Group(_)))
    {
        return Some(start + 4);
    }
    if ident(tokens.get(start), "macro")
        && matches!(tokens.get(start + 1), Some(TokenTree::Ident(_)))
    {
        let body =
            start + 2 + usize::from(group(tokens.get(start + 2), Delimiter::Parenthesis).is_some());
        if group(tokens.get(body), Delimiter::Brace).is_some() {
            return Some(body + 1);
        }
    }
    None
}

fn foreign_module(tokens: &[TokenTree], start: usize) -> Option<(bool, &Group, usize)> {
    let mut index = start + usize::from(ident(tokens.get(start), "unsafe"));
    if !ident(tokens.get(index), "extern") {
        return None;
    }
    index += 1;
    let mut rust_abi = false;
    if let Some(TokenTree::Literal(literal)) = tokens.get(index) {
        let abi = syn::parse_str::<LitStr>(&literal.to_string()).ok()?;
        rust_abi = abi.value() == "Rust";
        index += 1;
    }
    Some((
        rust_abi,
        group(tokens.get(index), Delimiter::Brace)?,
        index + 1,
    ))
}

fn collect_foreign_libraries(stream: TokenStream, libraries: &mut Vec<Library>) -> Result<()> {
    let tokens = stream.into_iter().collect::<Vec<_>>();
    let mut index = 0;
    while index < tokens.len() {
        let mut attributes = Vec::new();
        while let Some((attribute, inner, end)) = attribute(&tokens, index) {
            if !inner {
                attributes.push(attribute);
            }
            index = end;
        }
        if let Some(end) = macro_definition_end(&tokens, index) {
            index = end;
            continue;
        }
        if let Some((rust_abi, body, end)) = foreign_module(&tokens, index) {
            if !rust_abi {
                for attribute in attributes {
                    collect_link_attribute(attribute, libraries)?;
                }
                let body_tokens = body.stream().into_iter().collect::<Vec<_>>();
                let mut body_index = 0;
                while let Some((attribute, true, end)) = attribute(&body_tokens, body_index) {
                    collect_link_attribute(attribute, libraries)?;
                    body_index = end;
                }
            }
            // Constant/type expressions in foreign declarations can themselves
            // contain foreign blocks. Visit these after the enclosing module.
            collect_foreign_libraries(body.stream(), libraries)?;
            index = end;
            continue;
        }
        if let Some(TokenTree::Group(group)) = tokens.get(index) {
            collect_foreign_libraries(group.stream(), libraries)?;
        }
        index += 1;
    }
    Ok(())
}

/// Rustc has applied cfg, loaded modules and expanded macros. Inspect its
/// token trees, recognizing only attributes on actual foreign blocks. This
/// intentionally does not parse the rest of the Rust AST: new expression or
/// item syntax does not change the native link attribute grammar.
pub(super) fn expanded_libraries(output: &[u8]) -> Result<Vec<Library>> {
    let source = std::str::from_utf8(output).context("rustc expanded source is not UTF-8")?;
    // Rustc emits active link attributes with the canonical `#[link` spelling.
    if !source.contains("#[link")
        && !source.contains("#![link")
        && !source.contains("#[r#link")
        && !source.contains("#![r#link")
    {
        return Ok(Vec::new());
    }
    let stream = source.parse::<TokenStream>().map_err(|error| {
        anyhow::anyhow!("lex rustc expanded source for native library dependencies: {error}")
    })?;
    let mut libraries = Vec::new();
    collect_foreign_libraries(stream, &mut libraries)?;
    Ok(libraries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expanded_foreign_blocks_and_cli_overrides() -> Result<()> {
        let source = br##"
            macro_rules! unused { () => { #[link(name="unused", kind="static")] unsafe extern "C" {} } }
            const TEXT: &str = "#[link(name=\"fake\",kind=\"static\")]";
            macro unused2() { #[link(name="unused2", kind="static")] unsafe extern "C" {} }
            #[link(name="first", kind="static")] unsafe extern "C" {}
            mod nested { #[link(name="second", kind="static", cfg(any()))] unsafe extern "C" {} }
            fn nested() { #[link(name="third", kind="static", modifiers="+whole-archive")] unsafe extern "C" {} }
            #[link(name="rust",kind="static")] unsafe extern "Rust" {}
            #[link(name="dynamic")] unsafe extern "C" {}
            fn format() { let _ = format_args!("{}", { #[link(name="inside", kind="static")] unsafe extern "C" {} 1 }); }
            unsafe extern "C" { #![link(name="inner", kind="static")] }
        "##;
        let mut options = NativeLibraries::default();
        options.push(Some("dylib"), "first");
        options.push(None, "second:renamed");
        options.push(Some("static"), "fourth");
        let actual = options.archive_requests(expanded_libraries(source)?, true, true, false);
        assert_eq!(
            actual
                .iter()
                .map(|request| (request.name.as_str(), request.usage))
                .collect::<Vec<_>>(),
            [
                ("third", ArchiveUse::Packed),
                ("third", ArchiveUse::Members),
                ("inside", ArchiveUse::Members),
                ("inner", ArchiveUse::Members),
                ("renamed", ArchiveUse::Packed),
                ("renamed", ArchiveUse::Members),
                ("fourth", ArchiveUse::Members)
            ]
        );
        Ok(())
    }
}
