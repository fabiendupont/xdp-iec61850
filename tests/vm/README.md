# VM E2E Tests (Network Namespace Isolation)

End-to-end tests for GOOSE and SV publisher/subscriber workflows using
Linux network namespaces instead of full virtual machines.

## Approach

Network namespaces (`ip netns`) provide the same network isolation
guarantees as separate VMs:

- Each namespace has its own network stack (interfaces, routing, iptables)
- Traffic in one namespace is invisible to other namespaces
- veth pairs bridge namespaces, acting like a virtual cable
- No VM provisioning, no disk images, no hypervisor overhead

This gives sub-second test setup compared to minutes for Vagrant/QEMU,
while providing identical isolation for protocol-level testing.

## Prerequisites

- Root privileges (CAP_NET_ADMIN + CAP_NET_RAW)
- Built test binaries: `meson compile -C builddir`
  - `goose_loopback` and `sv_loopback` must be built explicitly
    (they have `build_by_default: false`):
    ```
    ninja -C builddir tests/goose_loopback tests/sv_loopback
    ```
- iproute2 (`ip` command)

## Test Scripts

| Script | Description |
|--------|-------------|
| `helpers.sh` | Common functions: netns create/teardown, process management, result reporting, scenario compilation (WP-2d deviation pattern) |
| `test_goose_vm_e2e.sh` | GOOSE publisher/subscriber E2E across network namespaces |
| `test_sv_vm_e2e.sh` | SV publisher/subscriber E2E across network namespaces |
| `test_isolation.sh` | APPID filtering and cross-namespace traffic isolation |
| `test_rgoose_vm_e2e.sh` | R-GOOSE (IEC TR 61850-90-5) E2E across network namespaces: plain UDP pub/sub with replay rejection, secure signed pub/sub with tamper + replay rejection (WP-4e) |
| `test_rsv_vm_e2e.sh` | R-SV (IEC TR 61850-90-5) E2E across network namespaces: plain UDP pub/sub with smpCnt continuity + replay rejection, secure signed pub/sub with tamper + replay rejection (WP-4e) |
| `test_r_xdp.sh` | 90-5 XDP datapath: attach the IEC 61850 graph (dispatch → UDP dport filter → R-GOOSE/R-SV parse) to a veth end, verify dport-based AF_XDP redirection, drops of unregistered dports and BPF SPDU-number dedup (WP-4e) |

## Running

```sh
# Build required binaries
ninja -C builddir tests/goose_loopback tests/sv_loopback tests/test_packet_io_raw_veth

# Run individual tests
sudo tests/vm/test_goose_vm_e2e.sh
sudo tests/vm/test_sv_vm_e2e.sh
sudo tests/vm/test_isolation.sh
sudo tests/vm/test_rgoose_vm_e2e.sh    # needs -Denable_security=true for
sudo tests/vm/test_rsv_vm_e2e.sh       #   the secure-mode tests
sudo tests/vm/test_r_xdp.sh            # needs libbpf/xgl at meson setup +
                                       #   CAP_BPF (BPF objects from the
                                       #   build tree)

# Run all VM E2E tests
sudo tests/vm/test_goose_vm_e2e.sh && \
sudo tests/vm/test_sv_vm_e2e.sh && \
sudo tests/vm/test_isolation.sh

# Override build directory
sudo BUILDDIR=builddir-asan tests/vm/test_goose_vm_e2e.sh
# or
sudo tests/vm/test_goose_vm_e2e.sh /path/to/builddir
```

## CI Integration

These tests are not registered in `meson.build` (they require root and
are designed for CI pipelines with privileged runners). Add to CI with:

```yaml
vm-e2e:
  stage: test
  script:
    - meson compile -C builddir
    - ninja -C builddir tests/goose_loopback tests/sv_loopback
    - tests/vm/test_goose_vm_e2e.sh
    - tests/vm/test_sv_vm_e2e.sh
    - tests/vm/test_isolation.sh
  tags:
    - privileged
```

## What Gets Tested

1. **GOOSE loopback** -- Publish a GOOSE frame, receive and decode it,
   verify gocbRef and stNum round-trip, all inside a network namespace
2. **SV loopback** -- Send sequential SV samples, receive and verify
   sample counter continuity and gap detection in a namespace
3. **APPID filtering** -- Subscriber configured for APPID 0x0001
   ignores frames sent with APPID 0x9999
4. **Cross-namespace isolation** -- Traffic in namespace A is not
   visible in unconnected namespace B
5. **Parallel execution** -- Two namespaces using identical interface
   names run tests concurrently without interference
6. **R-GOOSE/R-SV routable profiles** -- Plain-mode pub/sub over the
   veth UDP path with SPDU-number replay rejection (including a raw
   wire-level replay injection), secure-mode signed frames with
   tamper-in-transit and replay rejection, across namespace
   boundaries (WP-4e)
7. **90-5 XDP datapath** -- dport-registered traffic redirected to
   AF_XDP, unregistered dports dropped at XDP, duplicate SPDU
   numbers dropped by the BPF dedup (WP-4e)
