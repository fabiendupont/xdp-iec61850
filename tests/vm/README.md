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
| `helpers.sh` | Common functions: netns create/teardown, process management, result reporting |
| `test_goose_vm_e2e.sh` | GOOSE publisher/subscriber E2E across network namespaces |
| `test_sv_vm_e2e.sh` | SV publisher/subscriber E2E across network namespaces |
| `test_isolation.sh` | APPID filtering and cross-namespace traffic isolation |

## Running

```sh
# Build required binaries
ninja -C builddir tests/goose_loopback tests/sv_loopback tests/test_packet_io_raw_veth

# Run individual tests
sudo tests/vm/test_goose_vm_e2e.sh
sudo tests/vm/test_sv_vm_e2e.sh
sudo tests/vm/test_isolation.sh

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
