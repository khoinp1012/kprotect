# 📋 Next Implementation Phase: Performance & Privileges

This plan outlines the dual objective of fixing the "Process Lineage Leak" and implementing the "Privilege Guard" (Sudo Bypass) feature.

---

## ⚡ Strategic Implementation Note
*   **Zero Impact on eBPF Core**: This entire feature set (Privilege Guard) is implemented in **Userspace**. No changes are required to the `.c` hooks or kernel maps, ensuring 100% stable eBPF verifier status.
*   **Separated Policy Tracking**: Sudo Bypass patterns are stored in a **separate array** and a separate encrypted file (`sudo_patterns.enc`). This prevents "Privilege Creep" where a file-access rule accidentally grants root access.

---

## ✅ Part 1: Lineage Cache & GUI Optimization
*Objective: Eliminate "Ghost" process growth (memory leaks) and improve event throughput.*

*   [x] **1.1 Heal on Conflict**: Self-healing PID reuse logic. (Verified)
*   [x] **1.2 High-Performance Concurrency**: `DashMap` & `RwLock` implementation. (Completed)
*   [x] **1.3 Event Batching**: Optimized log and metric throughput. (Implemented)
*   [x] **1.4 GUI Label Stability**: Dashboard labels are now immutable for past events. (Implemented)
*   [x] **1.6 API Structure**: File is 102 lines; split determined unnecessary at this scale.


## ✅ Part 2: Privilege Guard (Sudo Bypass)
*Objective: Implement context-aware sudo authorization based on the Chain of Trust.*

*   [x] **2.1 Common & Protocol Updates**: `SudoRule` struct and `CHECK_SUDO` command. (Implemented)
*   [x] **2.2 Daemon Logic**: Isolated `sudo_rules` engine and audit trail. (Implemented)
*   [x] **2.3 PAM Module**: `pam_kprotect.so` with 100ms timeout logic. (Built & Installed)

---

## 🖼️ Part 3: GUI Modernization (4 Dedicated Hubs)

Following the new Information Architecture, the GUI will be restructured into four logical sections to separate File Security from Identity Management.

### 3.1 📊 Dashboard Hub
*   **Overview**: Global health status (Daemon, eBPF).
*   **Metrics**: High-level telemetry (Blocked vs Authorized, Verified events over time).
*   **Active Alerts**: Summary of the most recent high-priority security incidents.

### 3.2 🛡️ File Protection Hub (Lineage Rules)
*   **Protect Sensitive Files**: Red Zone management (Files/Directories monitored by eBPF).
*   **Lineage Allow List**: Management of `AuthorizedPatterns` for file access.
*   **Security Live Feed**: Real-time event log filtered exclusively for file access attempts.
*   **Enrichment Rules**: Management of patterns that expand process names.

### 3.3 🔑 Privilege Guard Hub (Sudo Bypass)
*   **Elevation Allow List**: Management of `SudoRules` (The strict process chains allowed to bypass sudo).
*   **Elevation Live Feed**: Real-time stream of sudo check requests from the PAM module.
*   **Sudo Audit History**: Dedicated history of all sudo bypass attempts, successes, and denials.

### 3.4 ⚙️ System Config Hub
*   **Notification Engine**: Configure Webhooks and Scripts for remote alerting.
*   **Daemon Settings**: Log retention days, encryption key management, and API connection status.

---

## 🧪 Verification & Stress Testing
*   **Lineage Stability**: Verify the lineage cache doesn't leak memory under 1000 processes/second.
*   **PAM Latency**: Ensure `pam_kprotect` never blocks for >100ms.
*   **GUI Responsiveness**: Verify the new hub layout feels snappy with 10k+ log entries.
*   **UI Data Flow**: Verify that the Dashboard and Settings populate instantly upon login with zero "stalled" connections.
