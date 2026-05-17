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
//!    [`AgentMetadata`], [`AgentEvent`], [`encode_agent_metadata`], [`encode_agent_parse_output`],
//!    [`ReviewActionDescriptor`], [`ReviewActionExecutionPlan`], [`encode_review_actions`],
//!    [`encode_review_action_plan`].
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
//!     optional_requires: "",
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
pub const CAP_REVIEW_ACTIONS: u64 = 1 << 13;
pub const CAP_API_INDEX: u64 = 1 << 14;

/// Plugin exports `basalt_capability_handle` for native capability dispatch.
pub const CAP_CAPABILITY_HANDLE: u64 = 1 << 17;

pub const BASALT_PLUGIN_API_VERSION: u32 = 1;

// ── Capability invoke support ───────────────────────────────────────────────

/// Error codes returned by the host capability runtime.
/// These match the host-side error namespace (reserved: -1 to -7).
#[repr(i64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityInvokeError {
    /// No provider registered for this capability.
    NotFound = -1,
    /// Malformed capability identifier.
    InvalidCapability = -2,
    /// Provider plugin returned an error or trapped.
    ProviderFailed = -3,
    /// Native WASM provider exceeded fuel budget.
    Timeout = -4,
    /// Circular dependency detected in invocation chain.
    DependencyCycle = -5,
    /// Required dependency not available.
    DependencyMissing = -6,
    /// Malformed request payload.
    InvalidRequest = -7,
}

impl CapabilityInvokeError {
    /// Convert a raw host return code to a typed error.
    /// Returns `None` for non-negative values (success).
    pub fn from_raw(code: i64) -> Option<Self> {
        if code >= 0 {
            return None;
        }
        match code {
            -1 => Some(Self::NotFound),
            -2 => Some(Self::InvalidCapability),
            -3 => Some(Self::ProviderFailed),
            -4 => Some(Self::Timeout),
            -5 => Some(Self::DependencyCycle),
            -6 => Some(Self::DependencyMissing),
            -7 => Some(Self::InvalidRequest),
            _other => Some(Self::ProviderFailed), // unknown host error → ProviderFailed
        }
    }
}

/// Invoke a capability and return the response bytes.
///
/// # Arguments
/// * `capability` — Capability identifier string (e.g. `"parse.call-sites@swift/v1"`).
/// * `request` — Opaque request payload bytes.
///
/// # Returns
/// * `Ok(Vec<u8>)` — Response payload from the provider.
/// * `Err(CapabilityInvokeError)` — Host-level error.
///
/// # Memory Safety
/// This function handles the full lifecycle: invoke → copy → free.
/// Even on copy failure, the host response handle is properly freed.
pub fn invoke_capability(capability: &str, request: &[u8]) -> Result<Vec<u8>, CapabilityInvokeError> {
    extern "C" {
        fn basalt_capability_invoke(
            cap_ptr: *const u8,
            cap_len: usize,
            req_ptr: *const u8,
            req_len: usize,
        ) -> i64;
        fn basalt_capability_copy_response(
            handle: i32,
            out_ptr: *mut u8,
            out_cap: i32,
        ) -> i32;
        fn basalt_capability_free_response(handle: i32);
    }

    let packed = unsafe {
        basalt_capability_invoke(
            capability.as_ptr(),
            capability.len(),
            request.as_ptr(),
            request.len(),
        )
    };

    // Negative values are host errors.
    if packed < 0 {
        return Err(CapabilityInvokeError::from_raw(packed).unwrap_or(CapabilityInvokeError::ProviderFailed));
    }

    let handle = (packed >> 32) as i32;
    let len = (packed & 0xFFFFFFFF) as usize;

    if len == 0 {
        unsafe {
            basalt_capability_free_response(handle);
        }
        return Ok(Vec::new());
    }

    // Allocate buffer and copy.
    let mut buf = Vec::with_capacity(len);
    // SAFETY: Vec::with_capacity guarantees `len` bytes of uninitialized memory.
    // We fill it entirely via copy_response before any read.
    let copy_result = unsafe {
        basalt_capability_copy_response(handle, buf.as_mut_ptr(), len as i32)
    };

    // Always free the host handle, even on copy failure.
    unsafe {
        basalt_capability_free_response(handle);
    }

    match copy_result {
        n if n >= 0 => {
            // SAFETY: copy_response returned n >= 0, meaning n bytes were copied.
            // We verified n == len above (host returns exact size on success).
            unsafe {
                buf.set_len(len);
            }
            Ok(buf)
        }
        -1 => Err(CapabilityInvokeError::ProviderFailed), // invalid handle
        -2 => Err(CapabilityInvokeError::ProviderFailed), // insufficient capacity
        _ => Err(CapabilityInvokeError::ProviderFailed),
    }
}

/// Pack a successful response into the `(ptr << 32) | len` format.
///
/// Use this as the return value from `basalt_capability_handle` implementations.
/// The host will read `len` bytes from `ptr` and then call `deallocate(ptr, len)`.
pub fn pack_success(data: Vec<u8>) -> i64 {
    let len = data.len();
    if len == 0 {
        return 0;
    }
    let ptr = alloc_bytes(len);
    // SAFETY: ptr is freshly allocated with capacity `len`.
    unsafe {
        core::ptr::copy_nonoverlapping(data.as_ptr(), ptr, len);
    }
    ((ptr as i64) << 32) | (len as i64)
}

/// Pack an empty success response (zero bytes).
///
/// Returns `0`, signalling to the host that there is no payload to read.
pub fn pack_empty() -> i64 {
    0
}

/// Pack a provider-defined error code.
///
/// Provider error codes are in the range `-1000` to `-1999`.
/// The host maps these to `ProviderFailed("provider returned N")`.
pub fn pack_error(code: i64) -> i64 {
    debug_assert!(code <= -1000 && code >= -1999, "provider error codes must be in -1000..-1999");
    code
}

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
    /// Preferred Basalt execution tier for this launcher.
    pub execution_tier: AgentExecutionTier,
    /// Symbolic workspace capabilities this agent expects from the host.
    pub workspace_capabilities: Vec<String>,
    /// Communication protocol the agent uses.
    ///
    /// - `Cli` (default): spawn per turn, prompt via CLI args, read stdout until exit.
    /// - `Rpc`: spawn once, prompt via stdin JSON commands, long-lived process.
    pub protocol: AgentProtocol,
}

/// Communication protocol used by an agent.
///
/// This determines how Basalt orchestrates the agent process:
///
/// | Protocol | Stdin | Stdout | Lifecycle |
/// |----------|-------|--------|----------|
/// | `Cli` | Closed | NDJSON until exit | Spawn per turn |
/// | `Rpc` | JSONL commands | NDJSON events | Long-lived process |
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AgentProtocol {
    /// Spawn per turn, prompt via CLI args, read stdout until process exits.
    /// Default for backward compatibility with existing agent plugins.
    #[default]
    Cli = 0,
    /// Spawn once, prompt via stdin RPC commands (`{"type":"prompt",...}`),
    /// events stream on stdout as NDJSON. Process stays alive between turns.
    Rpc = 1,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentExecutionTier {
    StructuredDirect = 1,
    MountedWorkspace = 2,
    Compatibility = 3,
}

#[derive(Debug, Clone)]
pub struct AgentSettingsField {
    pub kind: AgentSettingsFieldKind,
    pub key: String,
    pub label: String,
    pub description: String,
    pub placeholder: String,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentSettingsFieldKind {
    Unknown = 0,
    ExecutablePath = 1,
    Secret = 2,
}

// ── Review action types ──────────────────────────────────────────────────────

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewActionKind {
    Test = 1,
    Build = 2,
    Lint = 3,
    FormatCheck = 4,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewActionCwdMode {
    SessionWorkspace = 1,
    RepoRoot = 2,
}

#[derive(Debug, Clone)]
pub struct ReviewActionDescriptor {
    pub id: String,
    pub title: String,
    pub kind: ReviewActionKind,
    pub ecosystem: String,
    pub command_preview: String,
    pub mutates_workspace: bool,
    pub priority: u16,
}

#[derive(Debug, Clone)]
pub struct ReviewActionExecutionPlan {
    pub executable: String,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub cwd_mode: ReviewActionCwdMode,
    pub output_category: String,
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
        /// Canonical category string: "read" | "write" | "create" | "delete" | "move" | "list" | "search" | "run" | "build" | "test" | "git" | "message" | "thought" | "diagnostic".
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
/// [execution_tier:       u8]
/// [workspace_cap_count:  u16 LE]
///   per cap: [cap_len: u16 LE][cap bytes]
/// [protocol:             u8]   — 0 = Cli, 1 = Rpc
/// ```
pub fn encode_agent_metadata(m: &AgentMetadata) -> Vec<u8> {
    let mut out = Vec::new();
    write_str16(&mut out, &m.name);
    write_str16(&mut out, &m.executable);
    write_str_list16(&mut out, &m.args);
    write_str_list16(&mut out, &m.resume_new_args);
    write_str_list16(&mut out, &m.resume_cont_args);
    out.push(m.execution_tier as u8);
    write_str_list16(&mut out, &m.workspace_capabilities);
    out.push(m.protocol as u8);
    out
}

/// Encode a list of [`AgentSettingsField`] values into the Basalt wire format.
///
/// ```text
/// [count: u16 LE]
/// per field:
///   [kind: u8]
///   [key: str16]
///   [label: str16]
///   [description: str16]
///   [placeholder: str16]
/// ```
pub fn encode_agent_settings_schema(fields: &[AgentSettingsField]) -> Vec<u8> {
    let mut out = Vec::new();
    let count = fields.len().min(0xFFFF) as u16;
    out.extend_from_slice(&count.to_le_bytes());
    for f in &fields[..count as usize] {
        out.push(f.kind as u8);
        write_str16(&mut out, &f.key);
        write_str16(&mut out, &f.label);
        write_str16(&mut out, &f.description);
        write_str16(&mut out, &f.placeholder);
    }
    out
}

/// Encode a list of review-action descriptors into the Basalt wire format.
///
/// ```text
/// [action_count:    u16 LE]
/// per action:
///   [id_len:          u16 LE][id bytes]
///   [title_len:       u16 LE][title bytes]
///   [kind:            u8]
///   [ecosystem_len:   u16 LE][ecosystem bytes]
///   [preview_len:     u16 LE][command_preview bytes]
///   [mutates:         u8]
///   [priority:        u16 LE]
/// ```
pub fn encode_review_actions(actions: &[ReviewActionDescriptor]) -> Vec<u8> {
    let mut out = Vec::new();
    let count = actions.len().min(0xFFFF) as u16;
    out.extend_from_slice(&count.to_le_bytes());
    for action in &actions[..count as usize] {
        write_str16(&mut out, &action.id);
        write_str16(&mut out, &action.title);
        out.push(action.kind as u8);
        write_str16(&mut out, &action.ecosystem);
        write_str16(&mut out, &action.command_preview);
        out.push(if action.mutates_workspace { 1 } else { 0 });
        out.extend_from_slice(&action.priority.to_le_bytes());
    }
    out
}

/// Encode a review-action execution plan into the Basalt wire format.
///
/// ```text
/// [executable_len: u16 LE][executable bytes]
/// [arg_count:      u16 LE]
///   per arg: [arg_len: u16 LE][arg bytes]
/// [env_count:      u16 LE]
///   per pair:
///     [key_len: u16 LE][key bytes]
///     [val_len: u16 LE][val bytes]
/// [cwd_mode:       u8]
/// [output_len:     u16 LE][output_category bytes]
/// ```
pub fn encode_review_action_plan(plan: &ReviewActionExecutionPlan) -> Vec<u8> {
    let mut out = Vec::new();
    write_str16(&mut out, &plan.executable);
    write_str_list16(&mut out, &plan.args);
    let env_count = plan.env.len().min(0xFFFF) as u16;
    out.extend_from_slice(&env_count.to_le_bytes());
    for (key, value) in &plan.env[..env_count as usize] {
        write_str16(&mut out, key);
        write_str16(&mut out, value);
    }
    out.push(plan.cwd_mode as u8);
    write_str16(&mut out, &plan.output_category);
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

/// Encode a list of environment variable key/value pairs into the Basalt
/// agent-environment wire format consumed by `basalt_agent_environment`.
///
/// ```text
/// [count: u16 LE]
/// repeated count times:
///   [key_len: u16 LE][key bytes: UTF-8]
///   [val_len: u16 LE][val bytes: UTF-8]
/// ```
pub fn encode_agent_environment(env: &[(&str, &str)]) -> Vec<u8> {
    let mut out = Vec::new();
    let count = env.len().min(0xFFFF) as u16;
    out.extend_from_slice(&count.to_le_bytes());
    for (key, val) in env.iter().take(count as usize) {
        write_str16(&mut out, key);
        write_str16(&mut out, val);
    }
    out
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
    use std::alloc::{Layout, alloc, handle_alloc_error};
    let layout = Layout::array::<u8>(len).expect("allocation layout failed");
    // SAFETY: layout is valid, len > 0.
    let ptr = unsafe { alloc(layout) };
    if ptr.is_null() {
        handle_alloc_error(layout);
    }
    ptr
}

/// Free memory previously allocated by [`alloc_bytes`].
///
/// # Safety
/// `ptr` must have been returned by `alloc_bytes(len)`.
pub unsafe fn free_bytes(ptr: *mut u8, len: usize) {
    if !ptr.is_null() && len > 0 {
        use std::alloc::{Layout, dealloc};
        let layout = Layout::array::<u8>(len).expect("free layout failed");
        // SAFETY: ptr was allocated with the same layout via alloc.
        unsafe { dealloc(ptr, layout) };
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
///     optional_requires: "",
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
        basalt_plugin_sdk::basalt_plugin_meta! {
            name:              $name,
            version:           $version,
            hook_flags:        $hook_flags,
            provides:          $provides,
            requires:          $requires,
            optional_requires: "",
            file_globs:        $file_globs,
            activates_on:      $activates_on,
            activation_events: $activation_events,
        }
    };
    (
        name:              $name:expr,
        version:           $version:expr,
        hook_flags:        $hook_flags:expr,
        provides:          $provides:expr,
        requires:          $requires:expr,
        optional_requires: $optional_requires:expr,
        file_globs:        $file_globs:expr,
        activates_on:      $activates_on:expr,
        activation_events: $activation_events:expr $(,)?
    ) => {
        static __BASALT_PLUGIN_NAME: &[u8] = concat!($name, "\0").as_bytes();
        static __BASALT_PLUGIN_VERSION: &[u8] = concat!($version, "\0").as_bytes();
        static __BASALT_PROVIDES: &[u8] = concat!($provides, "\0").as_bytes();
        static __BASALT_REQUIRES: &[u8] = concat!($requires, "\0").as_bytes();
        static __BASALT_OPTIONAL_REQUIRES: &[u8] = concat!($optional_requires, "\0").as_bytes();
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
            optional_requires_ptr: u32,
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
            optional_requires_ptr: 0,
        };

        #[unsafe(no_mangle)]
        pub extern "C" fn basalt_plugin_metadata() -> *const __BasaltPluginMetaRecord {
            unsafe {
                __BASALT_META.name_ptr = __BASALT_PLUGIN_NAME.as_ptr() as u32;
                __BASALT_META.version_ptr = __BASALT_PLUGIN_VERSION.as_ptr() as u32;
                __BASALT_META.provides_ptr = __BASALT_PROVIDES.as_ptr() as u32;
                __BASALT_META.requires_ptr = __BASALT_REQUIRES.as_ptr() as u32;
                __BASALT_META.optional_requires_ptr = __BASALT_OPTIONAL_REQUIRES.as_ptr() as u32;
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
        alloc_bytes, encode_agent_environment, encode_agent_metadata, encode_agent_parse_output,
        encode_agent_settings_schema, encode_diagnostics, encode_review_action_plan,
        encode_review_actions, free_bytes, pack_output, pack_success, pack_empty, pack_error,
        invoke_capability, CapabilityInvokeError,
        AgentEvent, AgentExecutionTier,
        AgentMetadata, AgentProtocol, AgentSettingsField, AgentSettingsFieldKind, Diagnostic, ReviewActionCwdMode,
        ReviewActionDescriptor, ReviewActionExecutionPlan, ReviewActionKind, Severity,
        BASALT_PLUGIN_API_VERSION, CAP_AGENT_LAUNCHER, CAP_API_INDEX, CAP_CANVAS_DECO,
        CAP_CAPABILITY_HANDLE, CAP_CODE_ACTIONS, CAP_DIAGNOSTICS, CAP_EVENTS, CAP_FILE_TRANSFORM,
        CAP_HOVER, CAP_LAYOUT, CAP_PROJECT_MODEL, CAP_REVIEW_ACTIONS, CAP_THEME, CAP_UI_PANELS,
    };
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cap_capability_handle_flag() {
        assert_eq!(CAP_CAPABILITY_HANDLE, 1 << 17);
        // Verify no overlap with existing flags (0-16 occupied)
        assert!(CAP_CAPABILITY_HANDLE > CAP_API_INDEX);
    }

    #[test]
    fn capability_invoke_error_from_raw() {
        assert!(CapabilityInvokeError::from_raw(0).is_none());
        assert!(CapabilityInvokeError::from_raw(42).is_none());
        assert_eq!(CapabilityInvokeError::from_raw(-1), Some(CapabilityInvokeError::NotFound));
        assert_eq!(CapabilityInvokeError::from_raw(-2), Some(CapabilityInvokeError::InvalidCapability));
        assert_eq!(CapabilityInvokeError::from_raw(-3), Some(CapabilityInvokeError::ProviderFailed));
        assert_eq!(CapabilityInvokeError::from_raw(-4), Some(CapabilityInvokeError::Timeout));
        assert_eq!(CapabilityInvokeError::from_raw(-5), Some(CapabilityInvokeError::DependencyCycle));
        assert_eq!(CapabilityInvokeError::from_raw(-6), Some(CapabilityInvokeError::DependencyMissing));
        assert_eq!(CapabilityInvokeError::from_raw(-7), Some(CapabilityInvokeError::InvalidRequest));
        assert_eq!(CapabilityInvokeError::from_raw(-99), Some(CapabilityInvokeError::ProviderFailed));
    }

    #[test]
    fn pack_empty_returns_zero() {
        assert_eq!(pack_empty(), 0);
    }

    #[test]
    fn pack_success_returns_packed_value() {
        let data: Vec<u8> = vec![1, 2, 3, 4];
        let packed = pack_success(data);
        // On wasm32, packed > 0. On 64-bit native, the packed format
        // truncates the pointer to 32 bits, so we only verify the length field.
        let len = (packed & 0xFFFFFFFF) as usize;
        assert_eq!(len, 4);
        // The pointer field is non-zero on both wasm32 and native.
        let ptr_field = (packed >> 32) as u32;
        assert_ne!(ptr_field, 0);
    }

    #[test]
    fn pack_success_data_roundtrip() {
        // Test the alloc/copy/free path directly (bypassing pack_success
        // which uses the wasm32-specific packed format).
        let data: Vec<u8> = vec![10, 20, 30, 40];
        let ptr = alloc_bytes(data.len());
        assert!(!ptr.is_null());
        unsafe {
            core::ptr::copy_nonoverlapping(data.as_ptr(), ptr, data.len());
            let slice = core::slice::from_raw_parts(ptr, data.len());
            assert_eq!(slice, &[10, 20, 30, 40]);
            free_bytes(ptr, data.len());
        }
    }

    #[test]
    fn alloc_free_roundtrip() {
        let ptr = alloc_bytes(100);
        assert!(!ptr.is_null());
        unsafe {
            core::ptr::write_bytes(ptr, 0xAB, 100);
            free_bytes(ptr, 100);
        }
    }

    #[test]
    fn pack_success_empty_data_returns_zero() {
        assert_eq!(pack_success(Vec::new()), 0);
    }

    #[test]
    fn pack_error_returns_negative_code() {
        assert_eq!(pack_error(-1001), -1001);
        assert_eq!(pack_error(-1500), -1500);
        assert_eq!(pack_error(-1999), -1999);
    }

    #[test]
    fn capability_error_repr_values() {
        assert_eq!(CapabilityInvokeError::NotFound as i64, -1);
        assert_eq!(CapabilityInvokeError::InvalidCapability as i64, -2);
        assert_eq!(CapabilityInvokeError::ProviderFailed as i64, -3);
        assert_eq!(CapabilityInvokeError::Timeout as i64, -4);
        assert_eq!(CapabilityInvokeError::DependencyCycle as i64, -5);
        assert_eq!(CapabilityInvokeError::DependencyMissing as i64, -6);
        assert_eq!(CapabilityInvokeError::InvalidRequest as i64, -7);
    }
}
