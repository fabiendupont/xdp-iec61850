#!/bin/bash
# SPDX-License-Identifier: BSD-2-Clause
#
# helpers.sh — Common functions for VM (netns) E2E tests
#
# Provides network namespace creation/teardown, process management,
# and output verification utilities.

set -euo pipefail

# ---- Constants ----

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUILDDIR="${BUILDDIR:-${PROJECT_DIR}/builddir}"
TEST_TIMEOUT="${TEST_TIMEOUT:-10}"

# ---- Root check ----

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "SKIP: requires root (CAP_NET_ADMIN + CAP_NET_RAW)"
        exit 0
    fi
}

# ---- Binary discovery ----

# find_binary NAME — locate a test binary in the build directory
find_binary() {
    local name="$1"
    local binary="$BUILDDIR/tests/$name"
    if [ ! -x "$binary" ]; then
        binary="$BUILDDIR/$name"
    fi
    if [ ! -x "$binary" ]; then
        echo "ERROR: binary '$name' not found in $BUILDDIR" >&2
        echo "  Build with: meson compile -C $BUILDDIR" >&2
        return 1
    fi
    echo "$binary"
}

# ---- Network namespace management ----

# create_netns_pair NS1 NS2 VETH1 VETH2
#   Creates two network namespaces connected by a veth pair.
#   VETH1 is placed in NS1, VETH2 is placed in NS2.
#   Both interfaces are brought up with IPv6 disabled.
create_netns_pair() {
    local ns1="$1" ns2="$2" veth1="$3" veth2="$4"

    # Clean up any leftovers
    ip netns del "$ns1" 2>/dev/null || true
    ip netns del "$ns2" 2>/dev/null || true

    # Create namespaces
    ip netns add "$ns1"
    ip netns add "$ns2"

    # Create veth pair in default namespace, then move endpoints
    ip link add "$veth1" type veth peer name "$veth2"
    ip link set "$veth1" netns "$ns1"
    ip link set "$veth2" netns "$ns2"

    # Bring interfaces up
    ip netns exec "$ns1" ip link set lo up
    ip netns exec "$ns1" ip link set "$veth1" up
    ip netns exec "$ns2" ip link set lo up
    ip netns exec "$ns2" ip link set "$veth2" up

    # Suppress IPv6 noise
    ip netns exec "$ns1" sysctl -q -w "net.ipv6.conf.${veth1}.disable_ipv6=1" 2>/dev/null || true
    ip netns exec "$ns2" sysctl -q -w "net.ipv6.conf.${veth2}.disable_ipv6=1" 2>/dev/null || true
}

# cleanup_netns NS1 NS2
#   Deletes both network namespaces (and their veth endpoints).
cleanup_netns() {
    local ns1="$1" ns2="$2"
    ip netns del "$ns1" 2>/dev/null || true
    ip netns del "$ns2" 2>/dev/null || true
}

# ---- Process management ----

# Accumulator for background PIDs to kill on cleanup
_BG_PIDS=()

# register_bg_pid PID — track a background process for cleanup
register_bg_pid() {
    _BG_PIDS+=("$1")
}

# kill_bg_pids — terminate all registered background processes
kill_bg_pids() {
    for pid in "${_BG_PIDS[@]+"${_BG_PIDS[@]}"}"; do
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
    _BG_PIDS=()
}

# wait_for_output PID PATTERN TIMEOUT_SEC
#   Waits for a background process's output file to contain PATTERN.
#   Returns 0 if found within timeout, 1 otherwise.
#   Caller must redirect the process output to a file and pass PID.
wait_for_output() {
    local pid="$1" pattern="$2" timeout="${3:-$TEST_TIMEOUT}"
    local output_file="$4"
    local elapsed=0

    while [ "$elapsed" -lt "$timeout" ]; do
        if grep -q "$pattern" "$output_file" 2>/dev/null; then
            return 0
        fi
        # Check process is still alive
        if ! kill -0 "$pid" 2>/dev/null; then
            # Process exited — check output one last time
            if grep -q "$pattern" "$output_file" 2>/dev/null; then
                return 0
            fi
            return 1
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    return 1
}

# wait_for_file FILE TIMEOUT_SEC
#   Waits for a file to exist and be non-empty.
wait_for_file() {
    local file="$1" timeout="${2:-$TEST_TIMEOUT}"
    local elapsed=0

    while [ "$elapsed" -lt "$timeout" ]; do
        if [ -s "$file" ]; then
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    return 1
}

# ---- Test result helpers ----

_TESTS_RUN=0
_TESTS_PASSED=0
_TESTS_FAILED=0

test_start() {
    local name="$1"
    _TESTS_RUN=$((_TESTS_RUN + 1))
    printf "  [TEST] %-50s " "$name"
}

test_pass() {
    _TESTS_PASSED=$((_TESTS_PASSED + 1))
    echo "PASS"
}

test_fail() {
    local msg="${1:-}"
    _TESTS_FAILED=$((_TESTS_FAILED + 1))
    echo "FAIL${msg:+: $msg}"
}

test_summary() {
    echo ""
    echo "$_TESTS_PASSED/$_TESTS_RUN passed, $_TESTS_FAILED failed"
    if [ "$_TESTS_FAILED" -gt 0 ]; then
        return 1
    fi
    return 0
}
