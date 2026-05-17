//! `#[basalt_plugin]` procedural macro.
//!
//! Matches on the decorated function's name and generates the corresponding
//! `extern "C"` export with the packed-u64 output ABI.
//!
//! # Supported function names
//!
//! | Rust fn name           | Generated WASM export          | Signature                                                                        |
//! |------------------------|-------------------------------|----------------------------------------------------------------------------------|
//! | `diagnose`             | `basalt_diagnose`             | `(src_ptr, src_len, path_ptr, path_len: i32) -> u64`                             |
//! | `build_project_model`  | `basalt_build_project_model`  | `(root_ptr, root_len: i32) -> u64`                                               |
//! | `hover`                | `basalt_hover`                | `(src_ptr, src_len, path_ptr, path_len, byte_offset: i32) -> u64`                |
//! | `agent_metadata`       | `basalt_agent_metadata`       | `() -> u64`                                                                      |
//! | `agent_environment`    | `basalt_agent_environment`    | `() -> u64`                                                                      |
//! | `agent_settings_schema` | `basalt_agent_settings_schema` | `() -> u64`                                                                      |
//! | `agent_parse_line`     | `basalt_agent_parse_line`     | `(line_ptr, line_len, state_ptr, state_len: i32) -> u64`                         |
//! | `api_index`            | `basalt_api_index`            | `(root_ptr, root_len: i32) -> u64`                                               |
//! | `review_actions`       | `basalt_review_actions`       | `(root_ptr, root_len, workspace_ptr, workspace_len: i32) -> u64`                 |
//! | `review_action_plan`   | `basalt_review_action_plan`   | `(action_ptr, action_len, root_ptr, root_len, workspace_ptr, workspace_len: i32) -> u64` |
//! | `review_action_parse_line` | `basalt_review_action_parse_line` | `(action_ptr, action_len, line_ptr, line_len, state_ptr, state_len: i32) -> u64` |
//!
//! All generated wrappers call the decorated function with decoded Rust types
//! and pack the return value via `basalt_plugin_sdk::pack_output`.

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, ItemFn};

#[proc_macro_attribute]
pub fn basalt_plugin(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as ItemFn);
    let fn_name_str = input.sig.ident.to_string();

    let expanded = match fn_name_str.as_str() {
        "diagnose" => generate_diagnose_wrapper(&input),
        "build_project_model" => generate_build_project_model_wrapper(&input),
        "hover" => generate_hover_wrapper(&input),
        "agent_metadata" => generate_agent_metadata_wrapper(&input),
        "agent_environment" => generate_agent_environment_wrapper(&input),
        "agent_settings_schema" => generate_agent_settings_schema_wrapper(&input),
        "agent_parse_line" => generate_agent_parse_line_wrapper(&input),
        "api_index" => generate_api_index_wrapper(&input),
        "review_actions" => generate_review_actions_wrapper(&input),
        "review_action_plan" => generate_review_action_plan_wrapper(&input),
        "review_action_parse_line" => generate_review_action_parse_line_wrapper(&input),
        _ => {
            // Unknown name — emit the function unchanged with a compile_error.
            let msg = format!(
                "#[basalt_plugin] does not recognise function name `{fn_name_str}`. \
                 Supported names: diagnose, build_project_model, hover, agent_metadata, agent_environment, agent_parse_line, api_index, review_actions, review_action_plan, review_action_parse_line."
            );
            quote! {
                #input
                compile_error!(#msg);
            }
        }
    };

    TokenStream::from(expanded)
}

/// Generate the `basalt_diagnose` export.
///
/// Expects:  `fn diagnose(src: &[u8], path: &str) -> Vec<Diagnostic>`
/// Generates: `extern "C" fn basalt_diagnose(src_ptr, src_len, path_ptr, path_len: i32) -> u64`
fn generate_diagnose_wrapper(input: &ItemFn) -> proc_macro2::TokenStream {
    let fn_name = &input.sig.ident;
    quote! {
        #input

        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn basalt_diagnose(
            src_ptr:  i32,
            src_len:  i32,
            path_ptr: i32,
            path_len: i32,
        ) -> u64 {
            let src = unsafe {
                core::slice::from_raw_parts(src_ptr as *const u8, src_len as usize)
            };
            let path = unsafe {
                core::str::from_utf8_unchecked(
                    core::slice::from_raw_parts(path_ptr as *const u8, path_len as usize),
                )
            };
            let diags = #fn_name(src, path);
            basalt_plugin_sdk::pack_output(basalt_plugin_sdk::encode_diagnostics(&diags))
        }
    }
}

/// Generate the `basalt_build_project_model` export.
///
/// Expects:  `fn build_project_model(root: &str) -> Vec<u8>`
/// Generates: `extern "C" fn basalt_build_project_model(root_ptr, root_len: i32) -> u64`
fn generate_build_project_model_wrapper(input: &ItemFn) -> proc_macro2::TokenStream {
    let fn_name = &input.sig.ident;
    quote! {
        #input

        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn basalt_build_project_model(
            root_ptr: i32,
            root_len: i32,
        ) -> u64 {
            let root = unsafe {
                core::str::from_utf8_unchecked(
                    core::slice::from_raw_parts(root_ptr as *const u8, root_len as usize),
                )
            };
            let data = #fn_name(root);
            basalt_plugin_sdk::pack_output(data)
        }
    }
}

/// Generate the `basalt_hover` export.
///
/// Expects:  `fn hover(src: &[u8], path: &str, byte_offset: u32) -> String`
/// Generates: `extern "C" fn basalt_hover(src_ptr, src_len, path_ptr, path_len, byte_offset: i32) -> u64`
fn generate_hover_wrapper(input: &ItemFn) -> proc_macro2::TokenStream {
    let fn_name = &input.sig.ident;
    quote! {
        #input

        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn basalt_hover(
            src_ptr:     i32,
            src_len:     i32,
            path_ptr:    i32,
            path_len:    i32,
            byte_offset: i32,
        ) -> u64 {
            let src = unsafe {
                core::slice::from_raw_parts(src_ptr as *const u8, src_len as usize)
            };
            let path = unsafe {
                core::str::from_utf8_unchecked(
                    core::slice::from_raw_parts(path_ptr as *const u8, path_len as usize),
                )
            };
            let result = #fn_name(src, path, byte_offset as u32);
            basalt_plugin_sdk::pack_output(result.into_bytes())
        }
    }
}

/// Generate the `basalt_agent_metadata` export.
///
/// Expects:  `fn agent_metadata() -> AgentMetadata`
/// Generates: `extern "C" fn basalt_agent_metadata() -> u64`
fn generate_agent_metadata_wrapper(input: &ItemFn) -> proc_macro2::TokenStream {
    let fn_name = &input.sig.ident;
    quote! {
        #input

        #[unsafe(no_mangle)]
        pub extern "C" fn basalt_agent_metadata() -> u64 {
            let meta = #fn_name();
            basalt_plugin_sdk::pack_output(basalt_plugin_sdk::encode_agent_metadata(&meta))
        }
    }
}

/// Generate the `basalt_agent_environment` export.
///
/// Expects:  `fn agent_environment() -> Vec<(&'static str, &'static str)>`
/// Generates: `extern "C" fn basalt_agent_environment() -> u64`
///
/// The host treats this export as optional — it is safe to omit it entirely.
/// Return an empty `Vec` if there are no environment hints to inject.
fn generate_agent_environment_wrapper(input: &ItemFn) -> proc_macro2::TokenStream {
    let fn_name = &input.sig.ident;
    quote! {
        #input

        #[unsafe(no_mangle)]
        pub extern "C" fn basalt_agent_environment() -> u64 {
            let pairs = #fn_name();
            basalt_plugin_sdk::pack_output(basalt_plugin_sdk::encode_agent_environment(&pairs))
        }
    }
}

/// Generate the `basalt_agent_settings_schema` export.
///
/// Expects:  `fn agent_settings_schema() -> Vec<AgentSettingsField>`
/// Generates: `extern "C" fn basalt_agent_settings_schema() -> u64`
fn generate_agent_settings_schema_wrapper(input: &ItemFn) -> proc_macro2::TokenStream {
    let fn_name = &input.sig.ident;
    quote! {
        #input

        #[unsafe(no_mangle)]
        pub extern "C" fn basalt_agent_settings_schema() -> u64 {
            let fields = #fn_name();
            basalt_plugin_sdk::pack_output(basalt_plugin_sdk::encode_agent_settings_schema(&fields))
        }
    }
}

/// Generate the `basalt_agent_parse_line` export.
///
/// Expects:  `fn agent_parse_line(line: &[u8], state: &[u8]) -> (Vec<u8>, Vec<AgentEvent>)`
///           where the first element of the tuple is the new opaque state blob.
/// Generates: `extern "C" fn basalt_agent_parse_line(line_ptr, line_len, state_ptr, state_len: i32) -> u64`
fn generate_agent_parse_line_wrapper(input: &ItemFn) -> proc_macro2::TokenStream {
    let fn_name = &input.sig.ident;
    quote! {
        #input

        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn basalt_agent_parse_line(
            line_ptr:  i32,
            line_len:  i32,
            state_ptr: i32,
            state_len: i32,
        ) -> u64 {
            let line = unsafe {
                core::slice::from_raw_parts(line_ptr as *const u8, line_len as usize)
            };
            let state = unsafe {
                core::slice::from_raw_parts(state_ptr as *const u8, state_len as usize)
            };
            let (new_state, events) = #fn_name(line, state);
            basalt_plugin_sdk::pack_output(
                basalt_plugin_sdk::encode_agent_parse_output(&new_state, &events)
            )
        }
    }
}

/// Generate the `basalt_api_index` export.
///
/// Expects: `fn api_index(root: &str) -> Vec<u8>`
fn generate_api_index_wrapper(input: &ItemFn) -> proc_macro2::TokenStream {
    let fn_name = &input.sig.ident;
    quote! {
        #input

        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn basalt_api_index(
            root_ptr: i32,
            root_len: i32,
        ) -> u64 {
            let root = unsafe {
                core::str::from_utf8_unchecked(
                    core::slice::from_raw_parts(root_ptr as *const u8, root_len as usize),
                )
            };
            let data = #fn_name(root);
            basalt_plugin_sdk::pack_output(data)
        }
    }
}

/// Generate the `basalt_review_actions` export.
///
/// Expects: `fn review_actions(workspace_root: &str, session_workspace: &str) -> Vec<ReviewActionDescriptor>`
fn generate_review_actions_wrapper(input: &ItemFn) -> proc_macro2::TokenStream {
    let fn_name = &input.sig.ident;
    quote! {
        #input

        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn basalt_review_actions(
            root_ptr: i32,
            root_len: i32,
            workspace_ptr: i32,
            workspace_len: i32,
        ) -> u64 {
            let root = unsafe {
                core::str::from_utf8_unchecked(
                    core::slice::from_raw_parts(root_ptr as *const u8, root_len as usize),
                )
            };
            let workspace = unsafe {
                core::str::from_utf8_unchecked(
                    core::slice::from_raw_parts(workspace_ptr as *const u8, workspace_len as usize),
                )
            };
            let actions = #fn_name(root, workspace);
            basalt_plugin_sdk::pack_output(basalt_plugin_sdk::encode_review_actions(&actions))
        }
    }
}

/// Generate the `basalt_review_action_plan` export.
///
/// Expects: `fn review_action_plan(action_id: &str, workspace_root: &str, session_workspace: &str) -> Option<ReviewActionExecutionPlan>`
fn generate_review_action_plan_wrapper(input: &ItemFn) -> proc_macro2::TokenStream {
    let fn_name = &input.sig.ident;
    quote! {
        #input

        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn basalt_review_action_plan(
            action_ptr: i32,
            action_len: i32,
            root_ptr: i32,
            root_len: i32,
            workspace_ptr: i32,
            workspace_len: i32,
        ) -> u64 {
            let action_id = unsafe {
                core::str::from_utf8_unchecked(
                    core::slice::from_raw_parts(action_ptr as *const u8, action_len as usize),
                )
            };
            let root = unsafe {
                core::str::from_utf8_unchecked(
                    core::slice::from_raw_parts(root_ptr as *const u8, root_len as usize),
                )
            };
            let workspace = unsafe {
                core::str::from_utf8_unchecked(
                    core::slice::from_raw_parts(workspace_ptr as *const u8, workspace_len as usize),
                )
            };
            match #fn_name(action_id, root, workspace) {
                Some(plan) => basalt_plugin_sdk::pack_output(
                    basalt_plugin_sdk::encode_review_action_plan(&plan)
                ),
                None => 0u64,
            }
        }
    }
}

/// Generate the `basalt_review_action_parse_line` export.
///
/// Expects: `fn review_action_parse_line(action_id: &str, line: &[u8], state: &[u8]) -> (Vec<u8>, Vec<AgentEvent>)`
fn generate_review_action_parse_line_wrapper(input: &ItemFn) -> proc_macro2::TokenStream {
    let fn_name = &input.sig.ident;
    quote! {
        #input

        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn basalt_review_action_parse_line(
            action_ptr: i32,
            action_len: i32,
            line_ptr: i32,
            line_len: i32,
            state_ptr: i32,
            state_len: i32,
        ) -> u64 {
            let action_id = unsafe {
                core::str::from_utf8_unchecked(
                    core::slice::from_raw_parts(action_ptr as *const u8, action_len as usize),
                )
            };
            let line = unsafe {
                core::slice::from_raw_parts(line_ptr as *const u8, line_len as usize)
            };
            let state = unsafe {
                core::slice::from_raw_parts(state_ptr as *const u8, state_len as usize)
            };
            let (new_state, events) = #fn_name(action_id, line, state);
            basalt_plugin_sdk::pack_output(
                basalt_plugin_sdk::encode_agent_parse_output(&new_state, &events)
            )
        }
    }
}
