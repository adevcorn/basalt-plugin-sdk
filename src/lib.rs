//! Basalt plugin SDK — safe Rust abstractions over the Basalt WASM plugin ABI.
//!
//! # Overview
//!
//! Plugin authors use three things from this crate:
//!
//! 1. [`basalt_plugin_meta!`] — declares plugin identity + capability flags and
//!    generates the `basalt_plugin_metadata()` export plus `allocate`/`deallocate`.
//! 2. [`basalt_plugin`] proc-macro — wraps a hook function with the correct FFI
//!    signature and packed-u64 return convention.
//! 3. Helper types: [`Diagnostic`], [`Severity`], [`encode_diagnostics`], [`pack_output`],
//!    [`AgentMetadata`], [`AgentEvent`], [`encode_agent_metadata`], [`encode_agent_parse_output`].
//!
//! # Packed-u64 output ABI
//!
//! New-style hooks return `u64` where `high32 = guest_heap_ptr` and `low32 = byte_len`.
//! The host reads `byte_len` bytes from `guest_heap_ptr` in the plugin's linear memory,
//! then calls `deallocate(ptr, len)` to release the allocation.  A return value of `0`
//! means "no output".
//!
//! # Example
//!
//! ```ignore
//! use basalt_plugin_sdk::prelude::*;
//!
//! basalt_plugin_meta! {
//!     name: "my-plugin",
//!     version: "0.1.0",
//!     hook_flags: CAP_DIAGNOSTICS,
//!     provides: "diagnostics",
//!     requires: "",
//!     file_globs: "**/*.rs",
//!     activates_on: "",
//! }
//!
//! #[basalt_plugin]
//! fn diagnose(src: &[u8], path: &str) -> Vec<Diagnostic> {
//!     vec![Diagnostic::new(0, 4, "example warning", Severity::Warning)]
//! }
//! ```

// ── Capability flag constants ───────────────────────────────────────────────

pub const CAP_DIAGNOSTICS: u64 = 1 << 0;
pub const CAP_CODE_ACTIONS: u64 = 1 << 1;
pub const CAP_CANVAS_DECO: u64 = 1 << 2;
pub const CAP_FILE_TRANSFORM: u64 = 1 << 3;
pub const CAP_LAYOUT: u64 = 1 << 4;
pub const CAP_THEME: u64 = 1 << 5;
pub const CAP_EVENTS: u64 = 1 << 6;
pub const CAP_UI_PANELS: u64 = 1 << 7;
pub const CAP_PROJECT_MODEL: u64 = 1 << 8;
pub const CAP_HOVER: u64 = 1 << 9;

pub const CAP_AGENT_LAUNCHER: u64 = 1 << 10;

pub const BASALT_PLUGIN_API_VERSION: u32 = 1;

// ── Diagnostic types ────────────────────────────────────────────────────────

/// Diagnostic severity level (matches LSP convention).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Error = 0,
    Warning = 1,
    Info = 2,
    Hint = 3,
}

/// A single diagnostic produced by a [`CAP_DIAGNOSTICS`] hook.
#[derive(Debug, Clone)]
pub struct Diagnostic {
    /// File-relative byte offset of the highlighted range.
    pub offset: u32,
    /// Byte length of the highlighted range.
    pub length: u32,
    /// Human-readable message.
    pub message: String,
    /// Severity level.
    pub severity: Severity,
}

impl Diagnostic {
    pub fn new(offset: u32, length: u32, message: impl Into<String>, severity: Severity) -> Self {
        Self {
            offset,
            length,
            message: message.into(),
            severity,
        }
    }
}

// ── Agent launcher types ─────────────────────────────────────────────────────

/// Metadata describing an AI agent launcher provided by a [`CAP_AGENT_LAUNCHER`] plugin.
///
/// # Resume arg templates
///
/// `resume_new_args` are used when starting a brand-new session (no prior session ID).
/// `resume_cont_args` are used when resuming a prior session.
/// Both support two placeholders that the host substitutes before launching:
/// - `{prompt}` — the user's prompt string
/// - `{session_id}` — the agent's remote session/thread ID (only in `resume_cont_args`)
#[derive(Debug, Clone)]
pub struct AgentMetadata {
    /// Human-readable agent name (e.g. "Gemini CLI").
    pub name: String,
    /// Absolute path to the agent executable.
    pub executable: String,
    /// Default args for a fresh invocation (no prompt — prompt is handled by the agent itself).
    pub args: Vec<String>,
    /// Args for launching a new session that includes the user's prompt.
    /// Use `{prompt}` as a placeholder.
    pub resume_new_args: Vec<String>,
    /// Args for resuming a prior session.
    /// Use `{session_id}` and `{prompt}` as placeholders.
    pub resume_cont_args: Vec<String>,
}

/// One parsed event produced by `agent_parse_line`.
///
/// Vendor IDs are agent-internal string identifiers (tool_id, item_id, toolCallId, etc.)
/// that the host maps to its own UUIDs.
#[derive(Debug, Clone)]
pub enum AgentEvent {
    /// A new tool-call / activity entry begins.
    NewEntry {
        /// Agent-internal identifier for this entry (used to match CloseEntry).
        vendor_id: String,
        /// Short display label (e.g. "Read foo.swift", "Git commit").
        tool: String,
        /// Category string: "read" | "write" | "run" | "build" | "git" | "search" | "web" | "tool" | "message" | "error".
        category: String,
        /// Raw command or JSON string for tooltip / detail view.
        raw_cmd: String,
        /// File paths touched by this entry (for highlighting on the canvas).
        file_paths: Vec<String>,
    },
    /// An existing entry (matched by vendor_id) is complete.
    CloseEntry {
        vendor_id: String,
        exit_code: i32,
        output_lines: Vec<String>,
    },
    /// Append additional text to an existing entry's label (used for streaming message chunks).
    AppendToEntry { vendor_id: String, text: String },
    /// The agent session terminated.
    SessionEnded { success: bool },
    /// The agent emitted its remote session / thread ID (for resume).
    SessionIDAvailable(String),
}

// ── Wire-format helpers ──────────────────────────────────────────────────────

/// Encode a slice of [`Diagnostic`] values into the Basalt wire format.
///
/// Wire format per record:
/// ```text
/// [offset:   u32 LE]
/// [length:   u32 LE]
/// [msg_len:  u16 LE]
/// [severity: u8    ]
/// [_pad:     u8    ]   — reserved, always 0
/// [message:  u8 × msg_len]
/// ```
pub fn encode_diagnostics(diags: &[Diagnostic]) -> Vec<u8> {
    let mut out = Vec::new();
    for d in diags {
        let msg = d.message.as_bytes();
        let msg_len = (msg.len().min(0xFFFF)) as u16;
        out.extend_from_slice(&d.offset.to_le_bytes());
        out.extend_from_slice(&d.length.to_le_bytes());
        out.extend_from_slice(&msg_len.to_le_bytes());
        out.push(d.severity as u8);
        out.push(0u8); // pad
        out.extend_from_slice(&msg[..msg_len as usize]);
    }
    out
}

/// Encode [`AgentMetadata`] into the Basalt agent-metadata wire format.
///
/// ```text
/// [name_len:             u16 LE][name bytes]
/// [executable_len:       u16 LE][executable bytes]
/// [arg_count:            u16 LE]
///   per arg: [arg_len: u16 LE][arg bytes]
/// [resume_new_arg_count: u16 LE]
///   per arg: [arg_len: u16 LE][arg bytes]
/// [resume_cont_arg_count: u16 LE]
///   per arg: [arg_len: u16 LE][arg bytes]
/// ```
pub fn encode_agent_metadata(m: &AgentMetadata) -> Vec<u8> {
    let mut out = Vec::new();
    write_str16(&mut out, &m.name);
    write_str16(&mut out, &m.executable);
    write_str_list16(&mut out, &m.args);
    write_str_list16(&mut out, &m.resume_new_args);
    write_str_list16(&mut out, &m.resume_cont_args);
    out
}

/// Encode the combined output of `agent_parse_line`: new parser state + events.
///
/// ```text
/// [state_len:    u32 LE][state: u8 × state_len]
/// [event_count:  u16 LE]
/// per event:
///   [kind: u8]
///   kind=0 (NewEntry):
///     [vendor_id_len: u16 LE][vendor_id]
///     [tool_len:      u16 LE][tool]
///     [category_len:  u16 LE][category]
///     [raw_cmd_len:   u16 LE][raw_cmd]
///     [file_count:    u16 LE]
///       per file: [path_len: u16 LE][path]
///   kind=1 (CloseEntry):
///     [vendor_id_len: u16 LE][vendor_id]
///     [exit_code:     i32 LE]
///     [line_count:    u16 LE]
///       per line: [text_len: u16 LE][text]
///   kind=2 (AppendToEntry):
///     [vendor_id_len: u16 LE][vendor_id]
///     [text_len:      u16 LE][text]
///   kind=3 (SessionEnded):
///     [success: u8]
///   kind=4 (SessionIDAvailable):
///     [id_len: u16 LE][id]
/// ```
pub fn encode_agent_parse_output(new_state: &[u8], events: &[AgentEvent]) -> Vec<u8> {
    let mut out = Vec::new();

    // State prefix.
    let state_len = new_state.len().min(0xFFFF_FFFF) as u32;
    out.extend_from_slice(&state_len.to_le_bytes());
    out.extend_from_slice(&new_state[..state_len as usize]);

    // Events.
    let event_count = events.len().min(0xFFFF) as u16;
    out.extend_from_slice(&event_count.to_le_bytes());
    for ev in &events[..event_count as usize] {
        match ev {
            AgentEvent::NewEntry {
                vendor_id,
                tool,
                category,
                raw_cmd,
                file_paths,
            } => {
                out.push(0u8);
                write_str16(&mut out, vendor_id);
                write_str16(&mut out, tool);
                write_str16(&mut out, category);
                write_str16(&mut out, raw_cmd);
                let fc = file_paths.len().min(0xFFFF) as u16;
                out.extend_from_slice(&fc.to_le_bytes());
                for p in &file_paths[..fc as usize] {
                    write_str16(&mut out, p);
                }
            }
            AgentEvent::CloseEntry {
                vendor_id,
                exit_code,
                output_lines,
            } => {
                out.push(1u8);
                write_str16(&mut out, vendor_id);
                out.extend_from_slice(&exit_code.to_le_bytes());
                let lc = output_lines.len().min(0xFFFF) as u16;
                out.extend_from_slice(&lc.to_le_bytes());
                for l in &output_lines[..lc as usize] {
                    write_str16(&mut out, l);
                }
            }
            AgentEvent::AppendToEntry { vendor_id, text } => {
                out.push(2u8);
                write_str16(&mut out, vendor_id);
                write_str16(&mut out, text);
            }
            AgentEvent::SessionEnded { success } => {
                out.push(3u8);
                out.push(if *success { 1u8 } else { 0u8 });
            }
            AgentEvent::SessionIDAvailable(id) => {
                out.push(4u8);
                write_str16(&mut out, id);
            }
        }
    }
    out
}

// ── Internal wire-format helpers ─────────────────────────────────────────────

fn write_str16(out: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    let len = bytes.len().min(0xFFFF) as u16;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&bytes[..len as usize]);
}

fn write_str_list16(out: &mut Vec<u8>, list: &[String]) {
    let count = list.len().min(0xFFFF) as u16;
    out.extend_from_slice(&count.to_le_bytes());
    for s in &list[..count as usize] {
        write_str16(out, s);
    }
}

// ── Allocator helpers (used by pack_output and the generated allocate/deallocate exports) ─

/// Allocate `len` uninitialized bytes on the heap and return a raw pointer.
///
/// The caller must eventually free the memory via [`free_bytes`] with the same `len`.
/// Returns a null pointer if `len` is 0.
pub fn alloc_bytes(len: usize) -> *mut u8 {
    if len == 0 {
        return core::ptr::null_mut();
    }
    let mut v = Vec::<u8>::with_capacity(len);
    let ptr = v.as_mut_ptr();
    core::mem::forget(v);
    ptr
}

/// Free memory previously allocated by [`alloc_bytes`].
///
/// # Safety
/// `ptr` must have been returned by `alloc_bytes(len)`.
pub unsafe fn free_bytes(ptr: *mut u8, len: usize) {
    if !ptr.is_null() && len > 0 {
        // Reconstruct the Vec and drop it to release the allocation.
        drop(unsafe { Vec::from_raw_parts(ptr, 0, len) });
    }
}

/// Copy `data` into a heap allocation and return a packed `u64` for the host.
///
/// The packed value encodes `(guest_ptr << 32) | byte_len`.  Returns `0` if
/// `data` is empty.  The host will call `deallocate(ptr, len)` after reading.
pub fn pack_output(data: Vec<u8>) -> u64 {
    let len = data.len();
    if len == 0 {
        return 0u64;
    }
    let ptr = alloc_bytes(len);
    // SAFETY: ptr is freshly allocated with capacity `len`.
    unsafe {
        core::ptr::copy_nonoverlapping(data.as_ptr(), ptr, len);
    }
    ((ptr as u64) << 32) | (len as u64)
}

// ── Re-export the proc macro ─────────────────────────────────────────────────

pub use basalt_plugin_sdk_macros::basalt_plugin;

// ── basalt_plugin_meta! declarative macro ────────────────────────────────────

/// Generate plugin metadata boilerplate plus `allocate`/`deallocate` exports.
///
/// # Usage
///
/// ```ignore
/// basalt_plugin_meta! {
///     name:              "my-plugin",
///     version:           "0.1.0",
///     hook_flags:        CAP_DIAGNOSTICS,
///     provides:          "diagnostics",
///     requires:          "",
///     file_globs:        "**/*.rs",
///     activates_on:      "**/Cargo.toml",
///     activation_events: "workspace_opened",
/// }
/// ```
///
/// This expands to:
/// - String statics for all identity fields (NUL-terminated).
/// - A `PluginMetaRecord`-compatible `repr(C)` struct + static.
/// - `#[no_mangle] pub extern "C" fn basalt_plugin_metadata() -> *const _`
/// - `#[no_mangle] pub extern "C" fn allocate(size: usize) -> *mut u8`
/// - `#[no_mangle] pub unsafe extern "C" fn deallocate(ptr: *mut u8, size: usize)`
#[macro_export]
macro_rules! basalt_plugin_meta {
    (
        name:              $name:expr,
        version:           $version:expr,
        hook_flags:        $hook_flags:expr,
        provides:          $provides:expr,
        requires:          $requires:expr,
        file_globs:        $file_globs:expr,
        activates_on:      $activates_on:expr,
        activation_events: $activation_events:expr $(,)?
    ) => {
        static __BASALT_PLUGIN_NAME: &[u8] = concat!($name, "\0").as_bytes();
        static __BASALT_PLUGIN_VERSION: &[u8] = concat!($version, "\0").as_bytes();
        static __BASALT_PROVIDES: &[u8] = concat!($provides, "\0").as_bytes();
        static __BASALT_REQUIRES: &[u8] = concat!($requires, "\0").as_bytes();
        static __BASALT_FILE_GLOBS: &[u8] = concat!($file_globs, "\0").as_bytes();
        static __BASALT_ACTIVATES_ON: &[u8] = concat!($activates_on, "\0").as_bytes();
        static __BASALT_ACTIVATION_EVENTS: &[u8] = concat!($activation_events, "\0").as_bytes();

        #[repr(C)]
        struct __BasaltPluginMetaRecord {
            api_version: u32,
            _pad: u32,
            hook_flags: u64,
            name_ptr: u32,
            version_ptr: u32,
            provides_ptr: u32,
            requires_ptr: u32,
            file_globs_ptr: u32,
            activates_on_ptr: u32,
            activation_events_ptr: u32,
        }

        static mut __BASALT_META: __BasaltPluginMetaRecord = __BasaltPluginMetaRecord {
            api_version: basalt_plugin_sdk::BASALT_PLUGIN_API_VERSION,
            _pad: 0,
            hook_flags: $hook_flags,
            name_ptr: 0,
            version_ptr: 0,
            provides_ptr: 0,
            requires_ptr: 0,
            file_globs_ptr: 0,
            activates_on_ptr: 0,
            activation_events_ptr: 0,
        };

        #[unsafe(no_mangle)]
        pub extern "C" fn basalt_plugin_metadata() -> *const __BasaltPluginMetaRecord {
            unsafe {
                __BASALT_META.name_ptr = __BASALT_PLUGIN_NAME.as_ptr() as u32;
                __BASALT_META.version_ptr = __BASALT_PLUGIN_VERSION.as_ptr() as u32;
                __BASALT_META.provides_ptr = __BASALT_PROVIDES.as_ptr() as u32;
                __BASALT_META.requires_ptr = __BASALT_REQUIRES.as_ptr() as u32;
                __BASALT_META.file_globs_ptr = __BASALT_FILE_GLOBS.as_ptr() as u32;
                __BASALT_META.activates_on_ptr = __BASALT_ACTIVATES_ON.as_ptr() as u32;
                __BASALT_META.activation_events_ptr = __BASALT_ACTIVATION_EVENTS.as_ptr() as u32;
                &raw const __BASALT_META as *const __BasaltPluginMetaRecord
            }
        }

        #[unsafe(no_mangle)]
        pub extern "C" fn allocate(size: usize) -> *mut u8 {
            basalt_plugin_sdk::alloc_bytes(size)
        }

        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn deallocate(ptr: *mut u8, size: usize) {
            unsafe { basalt_plugin_sdk::free_bytes(ptr, size) }
        }
    };
}

// ── Prelude ───────────────────────────────────────────────────────────────────

pub mod prelude {
    pub use crate::basalt_plugin;
    pub use crate::basalt_plugin_meta;
    pub use crate::{
        alloc_bytes, encode_agent_metadata, encode_agent_parse_output, encode_diagnostics,
        free_bytes, pack_output, AgentEvent, AgentMetadata, Diagnostic, Severity,
        BASALT_PLUGIN_API_VERSION, CAP_AGENT_LAUNCHER, CAP_CANVAS_DECO, CAP_CODE_ACTIONS,
        CAP_DIAGNOSTICS, CAP_EVENTS, CAP_FILE_TRANSFORM, CAP_HOVER, CAP_LAYOUT, CAP_PROJECT_MODEL,
        CAP_THEME, CAP_UI_PANELS,
    };
}
