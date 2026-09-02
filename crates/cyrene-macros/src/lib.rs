//! Procedural macros for Cyrene's typed application model.

use proc_macro::TokenStream;
use quote::quote;
use syn::{
    Attribute, Data, DeriveInput, Field, Fields, Ident, LitInt, LitStr, Type, parse_macro_input,
};

/// Derives Cyrene's durable schema metadata for a Serde document.
///
/// The container accepts `#[cyrene(name = "stable.name", version = 1)]`.
/// Fields accept `#[cyrene(id = 42)]`; without it, a deterministic ID is
/// derived from the field's initial source name. Explicit IDs are recommended
/// before a schema is released because they survive Rust field renames.
#[proc_macro_derive(Document, attributes(cyrene))]
pub fn derive_document(input: TokenStream) -> TokenStream {
    expand_document(parse_macro_input!(input as DeriveInput))
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

fn expand_document(input: DeriveInput) -> syn::Result<proc_macro2::TokenStream> {
    let ident = input.ident;
    let (schema_name, version) = parse_container(&ident.to_string(), &input.attrs)?;
    if schema_name.is_empty() {
        return Err(syn::Error::new_spanned(
            &ident,
            "schema name cannot be empty",
        ));
    }

    let fields = match input.data {
        Data::Struct(data) => match data.fields {
            Fields::Named(fields) => fields.named,
            _ => {
                return Err(syn::Error::new_spanned(
                    ident,
                    "Document currently supports structs with named fields",
                ));
            }
        },
        _ => {
            return Err(syn::Error::new_spanned(
                ident,
                "Document currently supports structs",
            ));
        }
    };

    let ParsedFields {
        ids,
        names,
        types,
        merge_fields,
    } = parse_fields(fields.into_iter())?;
    let has_merge_fields = !merge_fields.is_empty();

    let mut fingerprint = fnv1a(schema_name.as_bytes());
    fingerprint = fnv1a_extend(fingerprint, &version.to_be_bytes());
    for ((id, name), ty) in ids.iter().zip(&names).zip(&types) {
        fingerprint = fnv1a_extend(fingerprint, &id.to_be_bytes());
        fingerprint = fnv1a_extend(fingerprint, name.as_bytes());
        fingerprint = fnv1a_extend(fingerprint, quote!(#ty).to_string().as_bytes());
    }

    Ok(quote! {
        impl ::cyrene::Document for #ident {
            const SCHEMA: ::cyrene::Schema = ::cyrene::Schema {
                name: #schema_name,
                version: #version,
                fingerprint: #fingerprint,
                fields: &[
                    #(
                        ::cyrene::FieldSchema {
                            id: #ids,
                            name: #names,
                            rust_type: stringify!(#types),
                        }
                    ),*
                ],
            };

            const HAS_MERGE_FIELDS: bool = #has_merge_fields;

            fn merge_payloads(
                winner: &[u8],
                concurrent: &[&[u8]],
            ) -> ::cyrene::Result<::std::vec::Vec<u8>> {
                if !Self::HAS_MERGE_FIELDS || concurrent.is_empty() {
                    return Ok(winner.to_vec());
                }
                let mut merged: Self = ::cyrene::__private::decode_document(winner)?;
                for payload in concurrent {
                    let other: Self = ::cyrene::__private::decode_document(payload)?;
                    #(
                        ::cyrene::Merge::merge(
                            &mut merged.#merge_fields,
                            &other.#merge_fields,
                        )?;
                    )*
                }
                ::cyrene::__private::encode_document(&merged)
            }
        }
    })
}

fn parse_container(default_name: &str, attributes: &[Attribute]) -> syn::Result<(String, u32)> {
    let mut schema_name = default_name.to_owned();
    let mut version = 1_u32;
    for attribute in attributes {
        if attribute.path().is_ident("cyrene") {
            attribute.parse_nested_meta(|meta| {
                if meta.path.is_ident("name") {
                    schema_name = meta.value()?.parse::<LitStr>()?.value();
                    Ok(())
                } else if meta.path.is_ident("version") {
                    version = meta.value()?.parse::<LitInt>()?.base10_parse()?;
                    Ok(())
                } else {
                    Err(meta.error("expected `name` or `version`"))
                }
            })?;
        }
    }
    Ok((schema_name, version))
}

struct ParsedFields {
    ids: Vec<u32>,
    names: Vec<String>,
    types: Vec<Type>,
    merge_fields: Vec<Ident>,
}

fn parse_fields(fields: impl Iterator<Item = Field>) -> syn::Result<ParsedFields> {
    let mut ids = Vec::new();
    let mut names = Vec::new();
    let mut types = Vec::new();
    let mut merge_fields = Vec::new();
    for field in fields {
        let field_ident = field.ident.expect("named fields have identifiers");
        let field_name = field_ident.to_string();
        let mut field_id = stable_field_id(&field_name);
        let mut merge = false;
        for attribute in &field.attrs {
            if attribute.path().is_ident("cyrene") {
                attribute.parse_nested_meta(|meta| {
                    if meta.path.is_ident("id") {
                        field_id = meta.value()?.parse::<LitInt>()?.base10_parse()?;
                        Ok(())
                    } else if meta.path.is_ident("merge") {
                        merge = true;
                        Ok(())
                    } else {
                        Err(meta.error("expected `id` or `merge`"))
                    }
                })?;
            }
        }
        if field_id == 0 {
            return Err(syn::Error::new_spanned(
                field_ident,
                "field ID must be non-zero",
            ));
        }
        if ids.contains(&field_id) {
            return Err(syn::Error::new_spanned(
                field_ident,
                "duplicate Cyrene field ID",
            ));
        }
        ids.push(field_id);
        names.push(field_name);
        types.push(field.ty);
        if merge {
            merge_fields.push(field_ident);
        }
    }
    Ok(ParsedFields {
        ids,
        names,
        types,
        merge_fields,
    })
}

const fn stable_field_id(name: &str) -> u32 {
    let hash = fnv1a(name.as_bytes());
    let bytes = hash.to_be_bytes();
    let folded = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
        ^ u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    if folded == 0 { 1 } else { folded }
}

const fn fnv1a(bytes: &[u8]) -> u64 {
    fnv1a_extend(0xcbf2_9ce4_8422_2325, bytes)
}

const fn fnv1a_extend(mut hash: u64, bytes: &[u8]) -> u64 {
    let mut index = 0;
    while index < bytes.len() {
        hash ^= bytes[index] as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        index += 1;
    }
    hash
}
