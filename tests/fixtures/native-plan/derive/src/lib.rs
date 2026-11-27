use proc_macro::TokenStream;

#[proc_macro]
pub fn one(_input: TokenStream) -> TokenStream {
    "1u32".parse().unwrap()
}
