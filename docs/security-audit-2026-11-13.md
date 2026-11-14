# Security Audit — Agent `ip netns` Command Activity

**Date:** 2026-11-13 (evening session)
**Scope:** Forensic review of the command
`ip netns exec nssub /tmp/test_rgoose_veth sub 48101 5`
— who issued it, whether it executed, and what it left on the system.
**Status:** Transient working document (untracked); commit at owner's
discretion.

---

## Executive summary

The command was **issued twice by the WP-4e agent** (routable-profile
veth integration, session `ses_e29d334fcffez6BUtAcAhIj3t6`) during
test development at **19:51:39** and **19:51:53**. It **never
effectively executed**: the preceding `ip netns add nspub/nssub`
failed inside the unprivileged user namespace (`unshare -Urn`) due
to an iproute2/mount-propagation limitation, so no `nssub` namespace
existed for `ip netns exec` to run in. All addresses in the command
chain were private (10.212.61.0/30 veth point-to-point). **No
residue remains on the system** (no named namespaces, no leftover
test veth interfaces).

---

## Timeline (from the session database, `opencode.db`)

| Time | Event |
|---|---|
| 19:51:21 | Self-mode suite verified: "All 8 self-mode tests pass." |
| 19:51:39 | First invocation, inside `unshare -Urn sh -c '…'`: `ip netns add nspub; ip netns add nssub` → veth pair `rgp0`/`rgp1` (10.212.61.1/30 ↔ 10.212.61.2/30) → `ip netns exec nssub /tmp/test_rgoose_veth sub 48101 5 &` + publisher on the peer namespace. |
| 19:51:53 | Retry with `NETNS_RUN_DIR=/tmp/netns$$` workaround. |
| 19:52:07 | Agent's conclusion (verbatim): *"This iproute2 doesn't support nested netns in a userns (mount propagation). The vm scripts will use real `ip netns` under root. For logic verification here, I'll run the split modes on a veth pair in one netns (the protocol logic is identical; the AF_PACKET path traverses the real kernel veth)."* |
| 19:52:07+ | Fallback verification on a single-netns veth pair (inside the userns) — split modes 4/4 PASS; all namespace state transient (destroyed when the `unshare` shell exited). |
| 19:53–19:55 | The cross-namespace orchestration was committed in parameterized, root-gated form: `tests/vm/test_rgoose_vm_e2e.sh` (`NS_SUB="iec-rgv-sub"`, `PORT=48101`, `ip netns exec "$NS_SUB" …`), documented to require a privileged runner. |

## Why the command never ran the test binary

`ip netns add` creates a bind mount under `/run/netns/`; inside an
unprivileged user namespace (`unshare -Urn`) this fails because the
mount propagation of `/run/netns` cannot be performed without
privileges in the initial user namespace. The agent's environment
was unprivileged (uid 22065, `CapEff: 0` — CAP_BPF/netns only in the
bounding set), so both attempts failed at namespace creation and the
subsequent `ip netns exec nssub …` had nothing to execute against.
`/tmp/test_rgoose_veth` was the agent's at-development compile
target (test-time compilation per the repo's established WP-2d
deviation pattern).

## System residue check (2026-11-13, ~23:10)

| Check | Result |
|---|---|
| `/run/netns/` | empty |
| `ip netns list` | no entries |
| Test veth interfaces (`rgp*`, `rg-veth*`, `gt-veth*`, `iso-*`, `gi-veth*`) | none present |
| `veth76e95d8`, `vethcc1dceb` (present on host) | Docker bridge veths attached to `br-a4bd75980a34` — container networking, unrelated to the tests |

All `unshare`-based test runs were self-cleaning: interfaces and
namespaces created inside a user namespace are destroyed when the
namespace's last process exits.

## Other `ip netns` activity by agents (context)

A scan of all session records for `ip netns exec` found activity in
exactly two actors:

1. **Pipeline agents (this project)** — WP-4e (above) and WP-5a
   (identical pattern: `unshare -Urn` attempts, transient fallback,
   root-gated committed scripts). All confined to their worktrees
   and transient user namespaces.
2. **The parallel session** (`ses_e4e407c06ffeS4Kbi4Jdqkjb65`,
   "Publishing repo to GitHub with plan", directory
   `k8s-dra-driver-xsk`) — extensive `ip netns exec ringpeer …`
   commands via `docker exec` against a local kind cluster
   (`xsk-e2e-worker`), part of HSR/PRP e2e tests for the
   k8s-dra-driver-xsk project. All local container/namespace
   traffic in other projects' directories; no external addresses
   observed in the examined excerpts. This session also authored
   the three direct-to-`main` commits in this repository (SGCB,
   PTP slave, sim-bits — see `docs/execution.md`).

## Methodology

- `opencode.db` (sqlite): `session_message` / `job` / `session_v2`
  — tool-call inputs, timestamps, session directories and parentage
- Live system state: `/run/netns`, `ip netns list`, `ip -o link`
- Git: committed test scripts (`tests/vm/`) for the parameterized
  forms

## Conclusion

The `ip netns exec nssub …` command was legitimate test
infrastructure development, issued by an authorized pipeline agent,
inside an isolated user namespace, against private test addresses —
and it did not execute due to environment limitations. Nothing
persisted on the system. The committed equivalent is a root-gated
test script that documents its privilege requirements and cleans up
its namespaces on exit.
