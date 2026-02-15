#!/bin/bash
set -e

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# --- Dependencies ---
if ! command -v gcc &> /dev/null; then
    echo -e "${RED}[ERROR] gcc not found. This benchmark requires a C compiler.${NC}"
    exit 1
fi

# --- Config ---
ITERATIONS=20000
TEST_DIR="/tmp/kprotect_bench"
BIN_DIR="/tmp/kprotect_bench_bins"
KPROTECT_SERVICE="kprotect.service"
TEMP_OUTPUT="/tmp/kprotect_bench_result.txt"

mkdir -p "$TEST_DIR"
mkdir -p "$BIN_DIR"

cleanup() {
    rm -rf "$TEST_DIR" "$BIN_DIR" "$TEMP_OUTPUT"
}
trap cleanup EXIT

echo -e "${BLUE}==============================================${NC}"
echo -e "${BLUE}   kprotect Industrial Benchmark Suite       ${NC}"
echo -e "${BLUE}==============================================${NC}"
echo -e "Iterations: ${YELLOW}$ITERATIONS${NC}"
echo -e "Precision: ${YELLOW}Nanosecond (CLOCK_MONOTONIC in C)${NC}"

# --- Prepare Micro-Benchmarks (With Internal Timing) ---

# 1. File System Overhead (open/close)
cat << EOF > "$BIN_DIR/bench_fs_open.c"
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define ITERATIONS $ITERATIONS

int main() {
    int fd;
    char filename[64];
    struct timespec start, end;
    double time_taken;

    // Create 1000 files first (Warmup)
    for(int i=0; i<1000; i++) {
        sprintf(filename, "$TEST_DIR/file_%d", i);
        fd = open(filename, O_CREAT|O_WRONLY, 0644);
        if(fd >= 0) close(fd);
    }
    
    // Start Timer
    clock_gettime(CLOCK_MONOTONIC, &start);

    // Benchmark Loop
    for(int i=0; i<ITERATIONS; i++) {
        sprintf(filename, "$TEST_DIR/file_%d", i % 1000);
        fd = open(filename, O_RDONLY);
        if(fd >= 0) close(fd);
    }

    // End Timer
    clock_gettime(CLOCK_MONOTONIC, &end);

    time_taken = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    printf("%.9f", time_taken); // Print raw seconds with nano precision
    return 0;
}
EOF

# 2. Process Overhead (fork/exec/wait)
cat << EOF > "$BIN_DIR/bench_proc_spawn.c"
#include <unistd.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#define ITERATIONS $ITERATIONS

int main() {
    struct timespec start, end;
    double time_taken;

    // Start Timer
    clock_gettime(CLOCK_MONOTONIC, &start);

    for(int i=0; i<ITERATIONS; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            execl("/bin/true", "true", NULL);
            exit(1); 
        } else if (pid > 0) {
            wait(NULL);
        } else {
            perror("fork");
            exit(1);
        }
    }

    // End Timer
    clock_gettime(CLOCK_MONOTONIC, &end);

    time_taken = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    printf("%.9f", time_taken); // Print raw seconds with nano precision
    return 0;
}
EOF

echo -e "${BLUE}Compiling micro-benchmarks...${NC}"
# Include -lrt for clock_gettime on older glibc, though standard now
gcc -O2 "$BIN_DIR/bench_fs_open.c" -o "$BIN_DIR/bench_fs_open"
gcc -O2 "$BIN_DIR/bench_proc_spawn.c" -o "$BIN_DIR/bench_proc_spawn"

# --- Helper Functions ---

# Run compiled binary which prints execution time to stdout
measure_cmd() {
    local BIN="$1"
    "$BIN"
}

ensure_daemon_state() {
    local EXPECT_RUNNING="$1" # true or false
    
    if [ "$EXPECT_RUNNING" = "true" ]; then
        if pgrep -f "kprotect-daemon" > /dev/null; then
             echo -e "${GREEN}[CHECK] kprotect-daemon is RUNNING (PID: $(pgrep -f kprotect-daemon | head -n1))${NC}"
        else
             echo -e "${RED}[ERROR] Expected running but process missing!${NC}"
             exit 1
        fi
    else
        if pgrep -f "kprotect-daemon" > /dev/null; then
             echo -e "${RED}[ERROR] Expected stopped but process running!${NC}"
             exit 1
        else
             echo -e "${GREEN}[CHECK] kprotect-daemon is STOPPED${NC}"
        fi
    fi
}

start_daemon() {
    echo -e "Starting kprotect service..."
    sudo systemctl start "$KPROTECT_SERVICE"
    sleep 2
    ensure_daemon_state "true"
}

stop_daemon() {
    echo -e "Stopping kprotect service..."
    sudo systemctl stop "$KPROTECT_SERVICE"
    sleep 2
    ensure_daemon_state "false"
}


# --- Phase 1: Baseline ---

echo -e "\n${YELLOW}--- Phase 1: Baseline Measurement (kprotect DISABLED) ---${NC}"

if systemctl is-active --quiet "$KPROTECT_SERVICE"; then
    stop_daemon
else
    ensure_daemon_state "false"
fi

echo -e "Measuring Baseline File System..."
BASE_FS=$(measure_cmd "$BIN_DIR/bench_fs_open")
echo -e " > Time: ${CYAN}${BASE_FS}s${NC}"

echo -e "Measuring Baseline Process Spawn..."
BASE_PROC=$(measure_cmd "$BIN_DIR/bench_proc_spawn")
echo -e " > Time: ${CYAN}${BASE_PROC}s${NC}"


# --- Phase 2: Active ---

echo -e "\n${YELLOW}--- Phase 2: Active Measurement (kprotect ENABLED) ---${NC}"

start_daemon

echo -e "Measuring Active File System..."
ACTIVE_FS=$(measure_cmd "$BIN_DIR/bench_fs_open")
echo -e " > Time: ${CYAN}${ACTIVE_FS}s${NC}"

echo -e "Measuring Active Process Spawn..."
ACTIVE_PROC=$(measure_cmd "$BIN_DIR/bench_proc_spawn")
echo -e " > Time: ${CYAN}${ACTIVE_PROC}s${NC}"

ensure_daemon_state "true"


# --- Analysis ---

# Use python just for the final print calculation as floating point shell math is hard
calc_overhead() {
    local base=$1
    local active=$2
    python3 -c "
diff = $active - $base
if diff < 0: diff = 0
pct = (diff / $base) * 100 if $base > 0 else 0
per_op_us = (diff / $ITERATIONS) * 1000000
per_op_ms = (diff / $ITERATIONS) * 1000
print(f'{pct:.4f}%')
print(f'   + {per_op_us:.4f} µs/op')
print(f'   + {per_op_ms:.4f} ms/op')
"
}

echo -e "\n${BLUE}==============================================${NC}"
echo -e "${BLUE}   Final Benchmark Report (Nanosecond Precision)${NC}"
echo -e "${BLUE}==============================================${NC}"

echo -e "File System (open/close):"
echo -e "  Baseline: ${BASE_FS}s | Active: ${ACTIVE_FS}s"
echo -e "  Overhead: ${GREEN}$(calc_overhead $BASE_FS $ACTIVE_FS)${NC}"

echo -e "\nProcess Spawn (fork+exec):"
echo -e "  Baseline: ${BASE_PROC}s | Active: ${ACTIVE_PROC}s"
echo -e "  Overhead: ${GREEN}$(calc_overhead $BASE_PROC $ACTIVE_PROC)${NC}"

echo -e "\n${BLUE}==============================================${NC}"
