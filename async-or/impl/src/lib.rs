// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT
use proc_macro::TokenStream;

#[proc_macro_attribute]
#[cfg(feature = "async")]
pub fn async_or(_args: TokenStream, input: TokenStream) -> TokenStream {
    let mut input: syn::ItemFn = syn::parse_macro_input!(input as syn::ItemFn);

    input.sig.asyncness = Some(syn::Token![async](proc_macro2::Span::call_site()));

    use quote::ToTokens;
    input.to_token_stream().into()
}

#[proc_macro_attribute]
#[cfg(not(feature = "async"))]
pub fn async_or(_args: TokenStream, input: TokenStream) -> TokenStream {
    input
}

fn is_ident_present_in_attr(attr: &syn::Attribute, ident: &str) -> bool {
    match &attr.meta {
        syn::Meta::Path(path) => path.is_ident(ident),
        syn::Meta::List(ml) => ml.path.is_ident(ident),
        syn::Meta::NameValue(nv) => nv.path.is_ident(ident),
    }
}

#[proc_macro_attribute]
#[cfg(feature = "async")]
pub fn async_trait_or(_args: TokenStream, input: TokenStream) -> TokenStream {
    let mut input: syn::ItemTrait = syn::parse_macro_input!(input as syn::ItemTrait);
    for item in input.items.iter_mut() {
        if let syn::TraitItem::Fn(trait_item_fn) = item {
            for (index, attr) in trait_item_fn.attrs.iter().enumerate() {
                if is_ident_present_in_attr(attr, "async_or") {
                    trait_item_fn.sig.asyncness =
                        Some(syn::Token![async](proc_macro2::Span::call_site()));
                    trait_item_fn.attrs.remove(index);
                    break;
                }
            }
        }
    }

    TokenStream::from(quote::quote! {
        #[async_trait::async_trait]
        #input
    })
}

#[proc_macro_attribute]
#[cfg(not(feature = "async"))]
pub fn async_trait_or(_args: TokenStream, input: TokenStream) -> TokenStream {
    let mut input: syn::ItemTrait = syn::parse_macro_input!(input as syn::ItemTrait);
    for item in input.items.iter_mut() {
        if let syn::TraitItem::Fn(trait_item_fn) = item {
            for (index, attr) in trait_item_fn.attrs.iter().enumerate() {
                if is_ident_present_in_attr(attr, "async_or") {
                    trait_item_fn.attrs.remove(index);
                    break;
                }
            }
        }
    }

    TokenStream::from(quote::quote! {
        #input
    })
}

#[proc_macro_attribute]
#[cfg(feature = "async")]
pub fn async_impl_or(_args: TokenStream, input: TokenStream) -> TokenStream {
    let mut input: syn::ItemImpl = syn::parse_macro_input!(input as syn::ItemImpl);
    for item in input.items.iter_mut() {
        if let syn::ImplItem::Fn(impl_item_fn) = item {
            for (index, attr) in impl_item_fn.attrs.iter().enumerate() {
                if is_ident_present_in_attr(attr, "async_or") {
                    impl_item_fn.sig.asyncness =
                        Some(syn::Token![async](proc_macro2::Span::call_site()));
                    impl_item_fn.attrs.remove(index);
                    break;
                }
            }
        }
    }

    TokenStream::from(quote::quote! {
        #[async_trait::async_trait]
        #input
    })
}

#[proc_macro_attribute]
#[cfg(not(feature = "async"))]
pub fn async_impl_or(_args: TokenStream, input: TokenStream) -> TokenStream {
    let mut input: syn::ItemImpl = syn::parse_macro_input!(input as syn::ItemImpl);
    for item in input.items.iter_mut() {
        if let syn::ImplItem::Fn(impl_item_fn) = item {
            for (index, attr) in impl_item_fn.attrs.iter().enumerate() {
                if is_ident_present_in_attr(attr, "async_or") {
                    impl_item_fn.attrs.remove(index);
                    break;
                }
            }
        }
    }

    TokenStream::from(quote::quote! {
        #input
    })
}
