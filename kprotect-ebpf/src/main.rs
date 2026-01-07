// kprotect-ebpf: Chain of Trust with Per-CPU Scratch Buffers
// Copyright (C) 2026 khoinp1012
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! kprotect - Chain of Trust with Per-CPU Scratch Buffers
//!
//! Key innovation: Use bitwise masks (& 0x1F, & 0xF) to PROVE bounds to verifier
//! - All loops have compile-time provable limits
//! - No conditional breaks that create exponential paths
//! - Limits: 32 bytes for paths, 16 for signatures, 32 red zones max

#![no_std]
#![no_main]

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod vmlinux;

use vmlinux::{file, task_struct, linux_binprm, path as kpath, dentry, mm_struct};

use aya_ebpf::{
    macros::{lsm, map},
    maps::{HashMap, LpmTrie, PerfEventArray, PerCpuArray, lpm_trie::Key},
    programs::LsmContext,
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_d_path, bpf_get_current_task, bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes},
    helpers::gen::{bpf_get_current_comm, bpf_probe_read_user},
    cty::c_void,
    bindings::path,
};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

// Event types
const EVENT_TYPE_VERIFIED: u32 = 1;
const EVENT_TYPE_BLOCK: u32 = 2;
const EVENT_TYPE_BIRTH: u32 = 3;
const EVENT_TYPE_EXIT: u32 = 4;

// Provable bounds
const LPM_KEY_SIZE: usize = 32;
const MAX_PATH_HASH: usize = 64;  // CRITICAL: Hash full path for unique signatures!
const MAX_PATH_COPY: usize = 128;  // Increased from 32 for full path visibility
const ARG_READ_SIZE: usize = 256; // Read 256 bytes of arguments

/// LPM Trie Key
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PathKey {
    pub data: [u8; LPM_KEY_SIZE],
}

/// Scratch buffer for LPM key building (moved from stack to map!)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct LpmScratch {
    pub prefix_key: [u8; LPM_KEY_SIZE],
    pub suffix_key: [u8; LPM_KEY_SIZE],
}

/// Scratch buffer for Argument reading
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ArgScratch {
    pub data: [u8; ARG_READ_SIZE],
}

/// Event sent to userspace
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BridgeEvent {
    pub signature: u64,
    pub start_time: u64,
    pub pid: u32,
    pub ppid: u32,
    pub event_type: u32,
    pub argc: u32,
    pub path: [u8; 256],
    pub arg: [u8; 64],
    pub comm: [u8; 16],
}

// ========== MAPS ==========

#[map]
static PROCESS_SIGNATURES: HashMap<u32, u64> = HashMap::with_max_entries(8192, 0);

#[map]
static AUTHORIZED_SIGNATURES: HashMap<u64, u8> = HashMap::with_max_entries(1024, 0);

#[map]
static INTERPRETER_HASHES: HashMap<u64, u8> = HashMap::with_max_entries(64, 0);

#[map]
static ENRICHMENT_PREFIX_MAP: LpmTrie<PathKey, u8> = LpmTrie::with_max_entries(32, 0);

#[map]
static RED_PREFIX_MAP: LpmTrie<PathKey, u8> = LpmTrie::with_max_entries(64, 0);

#[map]
static RED_SUFFIX_MAP: LpmTrie<PathKey, u8> = LpmTrie::with_max_entries(64, 0);

#[map]
static RED_EXACT_MAP: HashMap<u64, u8> = HashMap::with_max_entries(64, 0);

#[map]
static EVENTS: PerfEventArray<BridgeEvent> = PerfEventArray::new(0);

#[map]
static EVENT_SCRATCH: PerCpuArray<BridgeEvent> = PerCpuArray::with_max_entries(1, 0);

// ========== SCRATCH BUFFER (Per-CPU, zero stack usage!) ==========
#[map]
static LPM_SCRATCH: PerCpuArray<LpmScratch> = PerCpuArray::with_max_entries(1, 0);

#[map]
static ARG_SCRATCH: PerCpuArray<ArgScratch> = PerCpuArray::with_max_entries(1, 0);

// ========== SIGNATURE COMPUTATION ==========

/// Compute next signature: parent_sig ⊕ hash(LAST 64 bytes of path)
/// RIGHT-TO-LEFT hashing captures unique filename!
#[inline(always)]
fn compute_next_signature(parent_sig: u64, path: &[u8]) -> u64 {
    const FNV_PRIME: u64 = 0x100000001b3;
    let mut hash = if parent_sig == 0 { 0xcbf29ce484222325 } else { parent_sig };

    // Use path.len() and bound it for the verifier
    let actual_len = if path.len() < 256 { path.len() } else { 256 };

    // Hash LAST 64 bytes (or full path if shorter)
    let start_offset = if actual_len > MAX_PATH_HASH {
        actual_len - MAX_PATH_HASH
    } else {
        0
    };

    #[allow(clippy::needless_range_loop)]
    for i in 0..MAX_PATH_HASH {
        let idx = (start_offset + i) & 0xFF;
        if idx >= path.len() { break; }
        let byte = path[idx];
        if byte == 0 { break; }
        hash ^= byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

/// Compute path hash for exact matching (LAST 64 bytes)
#[inline(always)]
fn compute_path_hash(path: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    
    // Use path.len() and bound it for the verifier
    let actual_len = if path.len() < 256 { path.len() } else { 256 };

    // Hash LAST 64 bytes
    let start_offset = if actual_len > MAX_PATH_HASH {
        actual_len - MAX_PATH_HASH
    } else {
        0
    };
    
    #[allow(clippy::needless_range_loop)]
    for i in 0..MAX_PATH_HASH {
        let idx = (start_offset + i) & 0xFF;
        if idx >= path.len() { break; }
        if path[idx] == 0 { break; }
        h ^= path[idx] as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// Read user arguments and hash argv[1] using bprm->p
/// NOTE: At bprm_committed_creds time, mm->arg_start is NOT yet populated!
/// We must use bprm->p which points to the user stack where args are placed.
/// Read user arguments and hash argv[1] using single-loop state machine
/// Scans for argv[0] end (NUL), then hashes argv[1] in one pass
#[inline(always)]
fn read_and_hash_arg(bprm: *const linux_binprm, arg_out: *mut u8) -> u64 {
    unsafe {
        let p = bpf_probe_read_kernel(core::ptr::addr_of!((*bprm).p)).unwrap_or(0);
        if p == 0 { return 0; }

        let res = bpf_probe_read_user(
             arg_out as *mut c_void, 
             64,
             p as *const c_void
        );
        if res < 0 { return 0; }

        // Simply hash the whole 64-byte block for a robust signature
        const FNV_PRIME: u64 = 0x100000001b3;
        let mut h: u64 = 0xcbf29ce484222325;
        
        for i in 0..64 {
            let b = *arg_out.add(i & 0x3F);
            h ^= b as u64;
            h = h.wrapping_mul(FNV_PRIME);
        }
        h
    }
}

// ========== RED ZONE MATCHING (ZERO STACK USAGE!) ==========

#[inline(always)]
fn is_red_zone(path: &[u8], path_len: usize) -> bool {
    let scratch = match LPM_SCRATCH.get_ptr_mut(0) {
        Some(s) => s,
        None => return false,
    };

    // 1. Prefix match - using map buffer
    unsafe {
        core::ptr::write_bytes((*scratch).prefix_key.as_mut_ptr(), 0, LPM_KEY_SIZE);
        
        let copy_len = if path_len < LPM_KEY_SIZE { path_len } else { LPM_KEY_SIZE };
        
        #[allow(clippy::needless_range_loop)]
        for i in 0..LPM_KEY_SIZE {
            let idx = i & 0x1F;
            if idx >= path.len() || idx >= path_len { break; }
            let b = path[idx];
            if b == 0 { break; }
            (*scratch).prefix_key[idx] = b;
        }
        
        let key = Key::new((copy_len * 8) as u32, PathKey { data: (*scratch).prefix_key });
        if RED_PREFIX_MAP.get(&key).is_some() {
            return true;
        }
    }
    
    // 2. Suffix match - using map buffer
    unsafe {
        core::ptr::write_bytes((*scratch).suffix_key.as_mut_ptr(), 0, LPM_KEY_SIZE);
        
        // Use path_len to find the actual end of the string (excluding NUL)
        // bpf_d_path returns length INCLUDING null terminator
        let str_len = if path_len > 0 { path_len - 1 } else { 0 };
        let valid_len = if str_len < 256 { str_len } else { 255 };
        
        // Take up to LPM_KEY_SIZE characters from the END
        let rev_len = if valid_len < LPM_KEY_SIZE { valid_len } else { LPM_KEY_SIZE };
        
        #[allow(clippy::needless_range_loop)]
        for i in 0..LPM_KEY_SIZE {
            let idx = i & 0x1F; // mask to 31
            if idx >= rev_len { break; }
            
            let src_idx = valid_len - 1 - idx;
            let safe_src_idx = src_idx & 0xFF;
            
            if safe_src_idx < path.len() {
                (*scratch).suffix_key[idx] = path[safe_src_idx];
            }
        }
        
        let rev_key = Key::new((rev_len * 8) as u32, PathKey { data: (*scratch).suffix_key });
        if RED_SUFFIX_MAP.get(&rev_key).is_some() {
            return true;
        }
    }
    
    // 3. Exact match
    let hash = compute_path_hash(path);
    unsafe { RED_EXACT_MAP.get(&hash).is_some() }
}

/// Check if path needs enrichment (prefix based, using scratch)
#[inline(always)]
fn needs_enrichment(path: &[u8], path_len: usize) -> bool {
    let scratch = match LPM_SCRATCH.get_ptr_mut(0) {
        Some(s) => s,
        None => return false,
    };
    
    let copy_len = if path_len < LPM_KEY_SIZE { path_len } else { LPM_KEY_SIZE };

    unsafe {
        core::ptr::write_bytes((*scratch).prefix_key.as_mut_ptr(), 0, LPM_KEY_SIZE);
        
        #[allow(clippy::needless_range_loop)]
        for i in 0..LPM_KEY_SIZE {
            let idx = i & 0x1F;
            if idx >= path.len() || idx >= path_len { break; }
            let b = path[idx];
            if b == 0 { break; }
            (*scratch).prefix_key[idx] = b;
        }
        
        let key = Key::new((copy_len * 8) as u32, PathKey { data: (*scratch).prefix_key });
        ENRICHMENT_PREFIX_MAP.get(&key).is_some()
    }
}

// ========== LSM HOOKS ==========

#[lsm(hook = "bprm_committed_creds")]
pub fn bprm_committed_creds(ctx: LsmContext) -> i32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    let bprm: *const linux_binprm = unsafe { ctx.arg::<u64>(0) as *const _ };
    if bprm.is_null() { return 0; }

    let task = unsafe { bpf_get_current_task() } as *mut task_struct;
    let parent = unsafe { bpf_probe_read_kernel(core::ptr::addr_of!((*task).real_parent)).unwrap_or(core::ptr::null_mut()) };
    
    let mut parent_sig: u64 = 0;
    let mut ppid: u32 = 0;
    if !parent.is_null() {
        ppid = unsafe { bpf_probe_read_kernel(core::ptr::addr_of!((*parent).tgid)).unwrap_or(0) as u32 };
        if let Some(sig) = unsafe { PROCESS_SIGNATURES.get(&ppid) } {
            parent_sig = *sig;
        }
    }

    let filename_ptr = unsafe {
        bpf_probe_read_kernel(core::ptr::addr_of!((*bprm).filename)).unwrap_or(core::ptr::null())
    };
    let start_time = unsafe { bpf_probe_read_kernel(core::ptr::addr_of!((*task).start_time)).unwrap_or(0) };
    let argc = unsafe { bpf_probe_read_kernel(core::ptr::addr_of!((*bprm).argc)).unwrap_or(0) as u32 };

    if !filename_ptr.is_null() {
        let mut path_buf = [0u8; 64];
        let path_res = unsafe { bpf_probe_read_kernel_str_bytes(filename_ptr as *const u8, &mut path_buf) };
        
        if let Ok(path_bytes) = path_res {
            let mut child_sig = compute_next_signature(parent_sig, path_bytes);
            
            // CHECK ENRICHMENT
            // Calculate enrichment hash locally first (optimization to avoid map lookup if not needed)
            if needs_enrichment(path_bytes, path_bytes.len()) {
                if let Some(event) = unsafe { EVENT_SCRATCH.get_ptr_mut(0) } {
                    // Safe to use event scratch for arg reading temporarily
                   unsafe { core::ptr::write_bytes((*event).arg.as_mut_ptr(), 0, 64); }
                   let arg_hash = read_and_hash_arg(bprm, unsafe { (*event).arg.as_mut_ptr() });
                   if arg_hash != 0 {
                        child_sig ^= arg_hash;
                   }
                }
            }

            let _ = unsafe { PROCESS_SIGNATURES.insert(&pid, &child_sig, 0) };
            
            if let Some(event) = unsafe { EVENT_SCRATCH.get_ptr_mut(0) } {
                unsafe {
                    (*event).pid = pid;
                    (*event).start_time = start_time;
                    (*event).ppid = ppid;
                    (*event).signature = child_sig;
                    (*event).event_type = EVENT_TYPE_BIRTH;
                    (*event).argc = argc;
                    bpf_get_current_comm((*event).comm.as_mut_ptr() as *mut c_void, 16);
                    
                    // CRITICAL: Zero path buffer first to prevent corruption!
                    core::ptr::write_bytes((*event).path.as_mut_ptr(), 0, 256);
                    
                    // Copy path from stack buffer to event map
                    // Limit to 64 bytes (MAX_PATH_HASH) since that's what we read
                    let copy_len = if path_bytes.len() < 64 { path_bytes.len() } else { 64 };
                    #[allow(clippy::needless_range_loop)]
                    for i in 0..64 {
                        if i >= copy_len { break; }
                         (*event).path[i] = path_buf[i];
                    }
                    
                    // Clear arg buffer before emission (it was used for hashing above)
                    core::ptr::write_bytes((*event).arg.as_mut_ptr(), 0, 64);
                    let _ = EVENTS.output(&ctx, &*event, 0);
                }
            }
        }
    }

    0
}

#[lsm(hook = "file_open")]
pub fn file_open(ctx: LsmContext) -> i32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    let file_ptr: *const file = unsafe { ctx.arg::<u64>(0) as *const _ };
    if file_ptr.is_null() { return 0; }

    let event = match EVENT_SCRATCH.get_ptr_mut(0) {
        Some(e) => e,
        None => return 0,
    };

    // CRITICAL: Zero path buffer before use to prevent data leakage!
    unsafe { core::ptr::write_bytes((*event).path.as_mut_ptr(), 0, 256); }

    let f_path_ptr = unsafe { core::ptr::addr_of!((*file_ptr).f_path) as *mut path };
    let path_len = unsafe { bpf_d_path(f_path_ptr, (*event).path.as_mut_ptr() as *mut i8, 256) };
    if path_len <= 0 { return 0; }

    let path_slice = unsafe { &(*event).path };
    let path_len_usize = path_len as usize;

    if !is_red_zone(path_slice, path_len_usize) {
        return 0;
    }

    let mut current_sig: u64 = 0;
    if let Some(sig) = unsafe { PROCESS_SIGNATURES.get(&pid) } {
        current_sig = *sig;
    }

    let is_authorized = unsafe { AUTHORIZED_SIGNATURES.get(&current_sig).is_some() };

    if is_authorized {
        unsafe {
            (*event).pid = pid;
            (*event).start_time = 0; // Not critical for VERIFIED events but good to be consistent if possible
            (*event).ppid = 0;
            (*event).signature = current_sig;
            (*event).event_type = EVENT_TYPE_VERIFIED;
            bpf_get_current_comm((*event).comm.as_mut_ptr() as *mut c_void, 16);
            core::ptr::write_bytes((*event).arg.as_mut_ptr(), 0, 64);
            let _ = EVENTS.output(&ctx, &*event, 0);
        }
        return 0;
    }

    unsafe {
        (*event).pid = pid;
        (*event).start_time = 0;
        (*event).ppid = 0;
        (*event).signature = current_sig;
        (*event).event_type = EVENT_TYPE_BLOCK;
        bpf_get_current_comm((*event).comm.as_mut_ptr() as *mut c_void, 16);
        core::ptr::write_bytes((*event).arg.as_mut_ptr(), 0, 64);
        let _ = EVENTS.output(&ctx, &*event, 0);
    }
    
    -1
}

#[lsm(hook = "task_free")]
pub fn task_free(ctx: LsmContext) -> i32 {
    let task: *const task_struct = unsafe { ctx.arg::<u64>(0) as *const _ };
    if task.is_null() { return 0; }

    let tgid = unsafe { bpf_probe_read_kernel(core::ptr::addr_of!((*task).tgid)).unwrap_or(0) as u32 };
    let pid = unsafe { bpf_probe_read_kernel(core::ptr::addr_of!((*task).pid)).unwrap_or(0) as u32 };

    // ONLY proceed if this is the thread group leader (main process task)
    // This prevents worker threads from clearing the process signature!
    if pid != tgid {
        return 0;
    }
    
    let start_time = unsafe { bpf_probe_read_kernel(core::ptr::addr_of!((*task).start_time)).unwrap_or(0) };

    // Emit EXIT event to userspace BEFORE removing from map
    // Use EVENT_SCRATCH to avoid stack usage
    if let Some(event) = unsafe { EVENT_SCRATCH.get_ptr_mut(0) } {
        unsafe {
            core::ptr::write_bytes(event as *mut _ as *mut u8, 0, core::mem::size_of::<BridgeEvent>());
            (*event).pid = tgid;
            (*event).start_time = start_time;
            (*event).event_type = EVENT_TYPE_EXIT;
            let _ = EVENTS.output(&ctx, &*event, 0);
        }
    }
    
    // Now remove from kernel map
    let _ = PROCESS_SIGNATURES.remove(&tgid);

    0
}

#[cfg(not(test))]
#[no_mangle]
pub extern "C" fn _start() -> ! {
    loop {}
}
