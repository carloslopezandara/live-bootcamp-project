use proc_macro::TokenStream;
use quote::quote;
use syn::{parse::Parser, parse_macro_input, ItemFn, Ident};

#[proc_macro_attribute]
pub fn auto_cleanup(args: TokenStream, input: TokenStream) -> TokenStream {
    // Parse optional argument: #[auto_cleanup(variable_name)]
    let parser = syn::punctuated::Punctuated::<Ident, syn::Token![,]>::parse_terminated;
    let parsed_args = parser.parse(args).unwrap_or_default();
    let var_ident = parsed_args
        .first()
        .cloned()
        .unwrap_or_else(|| syn::Ident::new("app", proc_macro2::Span::call_site()));

    // Parse the original test function
    let input_fn = parse_macro_input!(input as ItemFn);
    let attrs = &input_fn.attrs; // Extract attributes like #[tokio::test]
    let vis = &input_fn.vis; // Extract visibility (pub, etc.)
    let sig = &input_fn.sig; // Extract the function signature
    let block = &input_fn.block; // Extract the function body
    // Extract the statements from the block so we can reinsert them into the
    // generated block. If we insert `#block` as is, we would create a
    // nested block `{ ... }` and the variables defined inside would not
    // be visible to the `clean_up()` that comes after.
    let stmts = &block.stmts;

    // ⚙️ Generate the expansion: inject cleanup at the end *inside* the same block
    let expanded = quote! {
        #(#attrs)*
        #vis #sig {
            async {
                #(#stmts)*
                // This will be executed at the end of the block, when the variable still exists
                #var_ident.clean_up().await;
            }.await;
        }
    };

    TokenStream::from(expanded)
}
