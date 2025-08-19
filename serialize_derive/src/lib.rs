// MIT License
// Copyright (c) Valan Sai 2025
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use proc_macro::TokenStream;
use quote::{quote, ToTokens};
use syn::parse::{Parse, ParseStream};
use syn::{Ident, Token, braced, Expr, ExprPath};
use syn::spanned::Spanned;
use syn::parse_macro_input;

mod kw {
    syn::custom_keyword!(target); 
    syn::custom_keyword!(readwrite); 
    syn::custom_keyword!(this); 
}


struct SerializeMacroInput {
    struct_name: Ident, 
    statements: Vec<Statement>, 
}

enum Statement {
    ReadWrite { field: Expr }, 
    Assign { left: Expr, right: Expr }, 
    If { condition: Expr, then_block: Vec<Statement>, else_block: Option<Vec<Statement>> }, 
}

impl Parse for SerializeMacroInput {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        input.parse::<kw::target>()?;
        let struct_name: Ident = input.parse()?;
        let content;
        braced!(content in input);
        let mut statements = Vec::new();

        while !content.is_empty() {
            statements.push(content.parse::<Statement>()?);
        }
        Ok(SerializeMacroInput { struct_name, statements })
    }
}

impl Parse for Statement {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        if input.peek(kw::readwrite) {
            input.parse::<kw::readwrite>()?;
            let content;

            syn::parenthesized!(content in input);
            let field: Expr = content.parse()?;
            input.parse::<Token![;]>()?;
            Ok(Statement::ReadWrite { field })
        }

        else if input.peek(Token![if]) {
            let if_stmt: syn::ExprIf = input.parse()?;
            let condition = *if_stmt.cond; 

            let then_block = if_stmt.then_branch.stmts.into_iter()
                .map(|stmt| syn::parse2::<Statement>(stmt.to_token_stream()))
                .collect::<syn::Result<Vec<_>>>()?;

            let else_block = if let Some((_, else_branch)) = if_stmt.else_branch {
                let else_block = match *else_branch {
                    syn::Expr::Block(expr_block) => expr_block.block.stmts,
                    _ => return Err(syn::Error::new(else_branch.span(), "Expected block in else branch")),
                };
                Some(else_block.into_iter()
                    .map(|stmt| syn::parse2::<Statement>(stmt.to_token_stream()))
                    .collect::<syn::Result<Vec<_>>>()?)
            } else {
                None
            };
            Ok(Statement::If { condition, then_block, else_block })
        }
        else {
            let left: Expr = input.parse()?;
            input.parse::<Token![=]>()?;
            let right: Expr = input.parse()?;
            input.parse::<Token![;]>()?;
            Ok(Statement::Assign { left, right })
        }
    }
}

fn replace_this_with_self(expr: &Expr) -> Expr {
    match expr {
        Expr::Path(expr_path) => {
            if expr_path.path.segments.len() == 1 && expr_path.path.segments[0].ident == "this" {
                let self_ident = Ident::new("self", expr_path.span());
                Expr::Path(ExprPath {
                    attrs: expr_path.attrs.clone(),
                    qself: None,
                    path: syn::Path {
                        leading_colon: None,
                        segments: vec![syn::PathSegment {
                            ident: self_ident,
                            arguments: syn::PathArguments::None,
                        }]
                        .into_iter()
                        .collect(),
                    },
                })
            }

            else if expr_path.path.segments.len() > 1 && expr_path.path.segments[0].ident == "this" {
                let mut new_segments = expr_path.path.segments.clone();
                new_segments[0].ident = Ident::new("self", new_segments[0].ident.span());
                Expr::Path(ExprPath {
                    attrs: expr_path.attrs.clone(),
                    qself: None,
                    path: syn::Path {
                        leading_colon: None,
                        segments: new_segments,
                    },
                })
            } else {
                expr.clone()
            }
        }
        _ => expr.clone(),
    }
}

#[proc_macro]
pub fn impl_serialize_for_struct(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as SerializeMacroInput);
    let struct_name = input.struct_name;

    let size_code = input.statements.iter().map(|stmt| match stmt {
        Statement::ReadWrite { field } => {
            let field = replace_this_with_self(field);
            quote! {
                #field.get_serialize_size(n_type, n_version)
            }
        }
        Statement::Assign { .. } => quote! { 0 }, 
        Statement::If { condition, then_block, .. } => {
            let condition = replace_this_with_self(&condition);
            let then_size = then_block.iter().map(|stmt| match stmt {
                Statement::ReadWrite { field } => {
                    let field = replace_this_with_self(field);
                    quote! {
                        #field.get_serialize_size(n_type, n_version)
                    }
                }
                _ => quote! { 0 },
            });
            quote! {
                (if #condition {
                    #(#then_size)+*
                } else {
                    0
                })
            }
        }
    });

    let serialize_code = input.statements.iter().map(|stmt| match stmt {
        Statement::ReadWrite { field } => {
            let field = replace_this_with_self(field);
            quote! {
                #field.serialize(writer, n_type, n_version)?;
            }
        }
        Statement::Assign { left, right } => {
            let left = replace_this_with_self(left);
            let right = replace_this_with_self(&right);
            quote! {
                #left = #right;
            }
        }
        Statement::If { condition, then_block, else_block } => {
            let condition = replace_this_with_self(&condition);
            let then_code = then_block.iter().map(|stmt| match stmt {
                Statement::ReadWrite { field } => {
                    let field = replace_this_with_self(field);
                    quote! {
                        #field.serialize(writer, n_type, n_version)?;
                    }
                }
                Statement::Assign { left, right } => {
                    let left = replace_this_with_self(left);
                    let right = replace_this_with_self(&right);
                    quote! {
                        #left = #right;
                    }
                }
                _ => quote! {},
            });
            let else_code = else_block.as_ref().map(|block| {
                let code = block.iter().map(|stmt| match stmt {
                    Statement::ReadWrite { field } => {
                        let field = replace_this_with_self(field);
                        quote! {
                            #field.serialize(writer, n_type, n_version)?;
                        }
                    }
                    Statement::Assign { left, right } => {
                        let left = replace_this_with_self(left);
                        let right = replace_this_with_self(&right);
                        quote! {
                            #left = #right;
                        }
                    }
                    _ => quote! {},
                });
                quote! { #(#code)* }
            });
            quote! {
                if #condition {
                    #(#then_code)*
                } else {
                    #else_code
                }
            }
        }
    });

    let unserialize_code = input.statements.iter().map(|stmt| match stmt {
        Statement::ReadWrite { field } => {
            let field = replace_this_with_self(field);
            quote! {
                #field.unserialize(reader, n_type, n_version)?;
            }
        }
        Statement::Assign { left, right } => {
            let left = replace_this_with_self(left);
            let right = replace_this_with_self(&right);
            quote! {
                #left = #right;
            }
        }
        Statement::If { condition, then_block, else_block } => {
            let condition = replace_this_with_self(&condition);
            let then_code = then_block.iter().map(|stmt| match stmt {
                Statement::ReadWrite { field } => {
                    let field = replace_this_with_self(field);
                    quote! {
                        #field.unserialize(reader, n_type, n_version)?;
                    }
                }
                Statement::Assign { left, right } => {
                    let left = replace_this_with_self(left);
                    let right = replace_this_with_self(&right);
                    quote! {
                        #left = #right;
                    }
                }
                _ => quote! {},
            });
            let else_code = else_block.as_ref().map(|block| {
                let code = block.iter().map(|stmt| match stmt {
                    Statement::ReadWrite { field } => {
                        let field = replace_this_with_self(field);
                        quote! {
                            #field.unserialize(reader, n_type, n_version)?;
                        }
                    }
                    Statement::Assign { left, right } => {
                        let left = replace_this_with_self(left);
                        let right = replace_this_with_self(&right);
                        quote! {
                            #left = #right;
                        }
                    }
                    _ => quote! {},
                });
                quote! { #(#code)* }
            });
            quote! {
                if #condition {
                    #(#then_code)*
                } else {
                    #else_code
                }
            }
        }
    });

    let size_calc = if input.statements.is_empty() {
        quote! { 0 }
    } else {
        quote! { #(#size_code)+* }
    };

    let expanded = quote! {
        impl Serialize for #struct_name {
            fn get_serialize_size(&self, n_type: i32, n_version: i32) -> usize {
                #size_calc
            }

            fn serialize<W: ::std::io::Write>(&self, writer: &mut W, n_type: i32, n_version: i32) -> Result<(), ::std::io::Error> {
                let f_read = false;
                #(#serialize_code)*
                Ok(())
            }

            fn unserialize<R: ::std::io::Read>(&mut self, reader: &mut R, n_type: i32, n_version: i32) -> Result<(), ::std::io::Error> {
                let f_read = true; 
                #(#unserialize_code)*
                Ok(())
            }
        }
    };

    TokenStream::from(expanded)
}