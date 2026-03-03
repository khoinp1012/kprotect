# KProtect Test Plan

## Priority 0: New Features from Current Session (Implement First)

These tests cover the 3-pillar Dashboard refactor and global toggle functionality implemented in this session.

### Backend: Configuration Toggle Logic

**File**: `kprotect-daemon/src/server/api/handlers/config.rs`

- [x] **Test: SET_ENGINE command**
  - Verify toggle persists to disk via `save_config()`
  - Verify non-root users receive permission error
  - Verify invalid syntax returns error

- [x] **Test: SET_FILE_PROTECTION command**
  - Verify toggle persists to disk
  - Verify permission check
  - Verify state changes in `DaemonConfig`

- [x] **Test: SET_SUDO_BYPASS command**
  - Verify toggle persists to disk
  - Verify permission check
  - Verify state changes in `DaemonConfig`

### Backend: Smart Suspend Logic

**File**: `kprotect-daemon/src/ebpf/events.rs`

- [x] **Test: Engine disabled behavior**
  - When `engine_enabled = false`, verify Birth/Exit events still processed
  - When `engine_enabled = false`, verify file access events are skipped
  - Verify lineage cache remains intact when engine disabled

- [x] **Test: File Protection disabled behavior**
  - When `file_protection_enabled = false`, verify logic skips matching
  - Verify pattern matching is bypassed when disabled
  - Verify logic verified via `evaluate_sudo_access_logic` mockable logic

**File**: `kprotect-daemon/src/server/api/handlers/sudo.rs`

- [x] **Test: Sudo bypass disabled**
  - When `sudo_bypass_enabled = false`, verify sudo requests are denied
  - When `engine_enabled = false`, verify sudo requests are denied
  - Verify correct error messages returned from logic

### Backend: System Info API

**File**: `kprotect-daemon/src/server/api/handlers/metrics.rs`

- [x] **Test: handle_system_info includes toggles**
  - Verify response includes `engine_enabled` field
  - Verify response includes `file_protection_enabled` field
  - Verify response includes `sudo_bypass_enabled` field

### Frontend: Toggle API Methods

**File**: `kprotect-ui/src/api/index.ts`

- [x] **Test: setEngineEnabled()**
  - Mock Tauri invoke
  - Verify correct command dispatched
  - Handle success/error states

- [x] **Test: setFileProtection()**
  - Mock Tauri invoke
  - Verify correct command dispatched

- [x] **Test: setSudoBypass()**
  - Mock Tauri invoke
  - Verify correct command dispatched

### Frontend: Dashboard Component

**File**: `kprotect-ui/src/pages/Dashboard.tsx`

- [x] **Test: Dashboard renders 3 pillars correctly**
  - Verify "Daemon Engine" card exists
  - Verify "File Protection" card exists
  - Verify "Quick Sudo" card exists

- [x] **Test: Toggle switches render with correct initial state**
  - Mock system info with different toggle states
  - Verify switches reflect backend state

- [x] **Test: Toggle interaction requires root**
  - Mock `isRootActive = false`
  - Verify toggles are disabled
  - Verify no API calls when clicked

- [x] **Test: Activity feeds display recent events**
  - Mock recent file events (Blocked/Verified)
  - Verify they appear in File Protection card
  - Mock recent sudo events
  - Verify they appear in Quick Sudo card

- [x] **Test: Empty state messaging**
  - Mock empty event arrays
  - Verify "No recent file events" message
  - Verify "No recent elevations" message

### Integration Tests

- [ ] **E2E: Toggle persistence across daemon restart**
  1. Set engine_enabled = false via UI
  2. Restart daemon
  3. Verify toggle state persists

- [ ] **E2E: Smart Suspend prevents event processing**
  1. Disable file protection
  2. Trigger file access to protected path
  3. Verify event is auto-verified (not blocked)
  4. Re-enable file protection
  5. Verify blocking resumes

- [ ] **E2E: Lineage survives engine disable/enable cycle**
  1. Build process lineage (spawn chain of processes)
  2. Disable engine
  3. Re-enable engine
  4. Verify lineage chain is still complete

---

## Priority 1: Critical Security Paths (Next Session)

### Authorization & Pattern Matching

**File**: `kprotect-daemon/src/ebpf/events.rs`

- [x] Test pattern matching against red zones
- [x] Test wildcard pattern matching (prefix/suffix)
- [ ] Test signature-based authorization (verified via `evaluate_security_logic`)
- [x] Test unauthorized access blocking
- [x] Test authorized pattern bypass

### Event Processing Pipeline

- [x] Test Birth event creates lineage node
- [x] Test Exit event triggers cleanup
- [x] Test PID reuse detection and healing
- [x] Test incomplete lineage chain handling
- [ ] Test signature mismatch detection

---

## Priority 2: API & State Management

### Configuration Persistence

**File**: `kprotect-daemon/src/config.rs`

- [x] Test config load from encrypted file
- [x] Test config save with encryption
- [x] Test default config generation
- [ ] Test config migration between versions

### API Handlers

**Files**: `kprotect-daemon/src/server/api/handlers/*.rs`

- [x] Test ADD_ZONE command (rules.rs)
- [x] Test REMOVE_ZONE command
- [x] Test ADD_PATTERN command (verified via `handle_pattern_add`)
- [x] Test SUDO_ADD command (sudo.rs)
- [x] Test SUDO_REMOVE command
- [x] Test notification rule CRUD operations (verified in `notifications::tests`)

---

## Priority 3: UI Component Testing

### Event Compression Logic

**File**: `kprotect-ui/src/context/GlobalContext.tsx`

- [x] Test event deduplication by identity
- [x] Test count aggregation for duplicate events
- [x] Test timestamp preservation (most recent)
- [x] Test compression toggle behavior (verified in `GlobalContext.test.tsx`)

### Real-time Event Streaming

- [ ] Test Tauri event listener registration
- [ ] Test event updates trigger UI refresh
- [ ] Test notification display for blocked events
- [ ] Test notification respects user toggle settings

---

## Priority 4: Performance & Stress Testing

### High Volume Event Processing

- [ ] Benchmark: 1000 events/sec processing
- [ ] Benchmark: Memory usage under load
- [ ] Benchmark: Event compression ratio
- [ ] Test: Lineage cache growth limits

### Concurrency

- [ ] Test: Concurrent API requests
- [ ] Test: Race conditions in lineage updates
- [ ] Test: eBPF map access under contention

---

## Test Infrastructure Setup

### Required Tools

- **Rust**: `cargo test` for unit tests
- **Frontend**: `vitest` for component tests
- **E2E**: Custom scripts or `playwright` for UI automation
- **Mocking**: `mockall` for Rust, `vi.mock()` for TypeScript

### Test Helpers Needed

- Mock eBPF event generator
- Mock process lineage builder
- Test fixture for encrypted config files
- Snapshot testing for UI components
