use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::{format_ident, quote};
use syn::{parse_macro_input, parse_quote, ItemFn};

#[proc_macro_attribute]
pub fn kernel_test_case(attr: TokenStream, item: TokenStream) -> TokenStream {
    if !attr.is_empty() {
        return syn::Error::new(
            Span::call_site(),
            "kernel_test_case does not accept arguments",
        )
        .to_compile_error()
        .into();
    }

    let mut function = parse_macro_input!(item as ItemFn);
    function.attrs.push(parse_quote!(#[test_case]));

    let fn_name = &function.sig.ident;
    let span = fn_name.span();
    let start = span.start();
    let line = start.line as u32;
    let column = start.column as u32;

    let static_ident = format_ident!("__CYRIUS_TEST_META_{}_{}_{}", fn_name, line, column);
    let name_const_ident = format_ident!("__CYRIUS_TEST_NAME_{}_{}_{}", fn_name, line, column);
    let module_ident = format_ident!("__cyrius_test_mod_{}_{}_{}", fn_name, line, column);
    let export_name = format!("__cyrius_test_{}_{}_{}", fn_name, line, column);

    let result = quote! {
        #function

        #[cfg(test)]
        #[allow(non_upper_case_globals)]
        const #name_const_ident: &str = concat!(module_path!(), "::", stringify!(#fn_name));

        #[cfg(test)]
        mod #module_ident {
            #[allow(non_upper_case_globals)]
            #[used]
            #[export_name = #export_name]
            #[link_section = "cyrius_tests"]
            static #static_ident: crate::test::NamedTest = crate::test::NamedTest {
                name: super::#name_const_ident,
            };
        }
    };

    result.into()
}
