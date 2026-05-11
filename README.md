# tibet-continuityd

> **Continuous integrity daemon and sealed handoff tool for continuity-native systems.**

`tibet-continuityd` is the resident trust and continuity guardian of the
TIBET stack.

It watches an inbox, sniffs what arrived, classifies trust and mismatch,
optionally verifies and forks sealed objects, reseals trusted forward
state, emits audit records, and can now also **send** and **ack**
sealed envelopes across hosts.

In short:

- **daemon**
  - watch, sniff, verify, classify, triage, seal, police
- **CLI**
  - pack, send, and acknowledge sealed continuity objects across hosts
- **discipline**
  - name is hint, content is truth, arrival is event

## Why it exists

Modern agentic and stateful systems fail when they silently trust:

- filenames
- resumed state
- imported sessions
- unpacked blobs
- unexpected arrivals
- stale or disguised handoff material

`tibet-continuityd` exists to put a resident gate in front of those
arrivals.

It turns:

- file arrival
- cross-host handoff
- resumed state
- imported continuity material

into something that can be:

- sniffed
- verified
- classified
- quarantined
- triaged
- resealed
- audited

## Core model

```
Arrival → Sniff → Classify → Verify/Fork → Trust → Seal → Police
```

The daemon treats every arrival as a meaningful event.

It does **not** assume:

- extension is truthful
- resumed state is safe
- transport success implies continuity legitimacy

## Design axiom

> **Name is hint. Content is truth. Arrival is event.**

## What it does today

### Daemon behavior

- watches inbox lanes for arrivals
- recognizes TBZ/ICC-style sealed bundles via magic bytes
- detects disguised payloads and extension/content mismatch
- classifies arrivals into trust/triage/quarantine/reject paths
- emits audit JSONL suitable for machine analysis and operator review
- supports:
  - `passive`
  - `active`
  - `strict`
  modes
- supports:
  - coalescing
  - verify-fork
  - trust-kernel handoff
  - reseal/outbox
  - police scan for unpacked drift
  - backpressure monitoring

### CLI behavior

The `tcd` CLI now supports:

- `tcd run`
  - run the daemon
- `tcd send FILE --to HOST:PATH`
  - seal and send over `scp`
- `tcd send FILE --to jis:org:service@host`
  - convention-based identity-bound routing
- `tcd send FILE --transport http --to http://host:port`
  - sealed HTTP inbox delivery to a peer listener
- `tcd send FILE --transport http --to jis:org:service@host`
  - JIS-style destination resolution directly into an HTTP inbox URL
- `tcd send FILE --transport mux --to jis:...`
  - identity-bound delivery via `tibet-mux` channel (v0.6.0+)
- `tcd ack REF --to TARGET`
  - sealed receipt/acknowledgement envelope for a prior object
- `tcd heartbeat --to TARGET --kind-detail liveness|shutdown|reboot|custom`
  - liveness / shutdown / reboot signal via short-circuit lane (v0.6.3+)
- `tcd recv --port 8443`
  - ephemeral HTTP listener for one-shot receive (v0.5.9+)
- `tcd mux-consumer --server URL --agent AGENT --inbox PATH`
  - polling consumer that materializes mux frames into a local inbox (v0.6.1+)

This means `tibet-continuityd` is no longer only a passive inbox daemon.

It is also becoming the first practical **post-email sealed handoff
primitive** in the stack.

## Current feature surface

### Watch

- inbox watcher on Linux
- arrival detection
- lane-local event flow

### Sniff

- TBZ magic-byte detection
- sealed bundle recognition independent of extension
- detection of:
  - executable
  - PDF
  - JSON text
  - empty payloads
  - disguised vendor-style names

### Classify

- `trusted-candidate`
- `triage-disguised`
- `reseal-candidate`
- `quarantine`
- `reject`

### Verify / Fork

- optional cryptographic verify path
- forward-only continuation discipline
- trusted fork semantics for admitted sealed material

### Trust / Seal

- optional trust-kernel integration
- reseal to outbox
- forward continuity discipline instead of silent mutation

### Police

- periodic scan for unpacked or policy-breaking material
- age-based alerting for lingering unsafe state

### Backpressure

- queue pressure observation
- low/high watermark monitoring
- intended as part of larger lane health discipline

### Send

- pack local file or directory as sealed envelope
- preserve semantic surface fields
- deliver through:
  - `scp`
  - `http`
  - `mux` (= `tibet-mux` single-port multiplexer, v0.6.0+)
- optionally resolve JIS-style destinations before delivery
- optionally sign the HTTP request itself
- target peer daemon processes arrival through the same watcher/sniff
  pipeline as local files

### ACK

- create a small sealed receipt object referencing a prior bundle name or
  short ID
- default to a low-priority/background semantic surface
- deliver over the same transport paths as `send`
- make roundtrip proof and receipt flow continuity-native instead of
  out-of-band

### Heartbeat (v0.6.3+)

- liveness, shutdown, reboot, or custom signal envelope
- uses `surface_priority=heartbeat` (= 5e SSM priority value)
- short-circuit lane at receiver: after Sniff + Verify (= identity pin
  matched), daemon emits a log-only audit record with `stage=heartbeat`
  and skips Fork / Seal / Police
- identity pin is the safety check: unsigned bundles never reach the
  short-circuit branch because verify-stage rejects them
- typical use:
  - peer liveness pulses between hosts
  - announcing graceful shutdown (= "I'm going offline")
  - announcing reboot (= "I'm restarting, pause work")
- payload includes `kind_detail`, `ts_iso`, `beat_seq`, optional `note`

### Mux transport (v0.6.0+)

- send and receive sealed envelopes via a `tibet-mux` server
- single-port multiplexed transport with intent-based routing
- sender opens a channel for `target=AGENT, intent=continuityd:inbox`
- daemon-side or standalone consumer polls `/api/mux/by-target` (= tibet-mux
  v1.0.1+), fetches `recent_frames`, base64-decodes the bundle payload,
  and writes to the inbox via atomic `.part`-then-rename
- the daemon's existing inotify watcher then picks the file up via the
  normal Sniff / Verify / Seal pipeline
- channel left OPEN by sender with `--mux-keep-open` so the polling
  consumer can find + close it after materialize

### Recv (v0.5.9+)

- ephemeral HTTP listener for one-shot receive without running the full
  daemon
- writes incoming POST bodies to a local inbox dir
- exits after N arrivals or timeout
- intended for laptop / peer-eval / quick demo scenarios

## Install

```bash
pip install tibet-continuityd
```

Optional stacks:

```bash
pip install "tibet-continuityd[verify]"
pip install "tibet-continuityd[phantom]"
pip install "tibet-continuityd[full]"
```

## Quick start — local daemon

```bash
TIBET_CONTINUITYD_INBOX=/tmp/tibet/inbox \
TIBET_CONTINUITYD_QUARANTINE=/tmp/tibet/quarantine \
TIBET_CONTINUITYD_TRIAGE=/tmp/tibet/triage \
TIBET_CONTINUITYD_AUDIT=/tmp/tibet/continuityd-audit.jsonl \
tcd run
```

Drop a TBZ-prefixed file into the inbox:

```bash
printf 'TBZ\x01\x00\x00\x00' > /tmp/tibet/inbox/sample.claude.tza
```

The daemon will emit an arrival and sniff decision.

## Quick start — send over SCP

```bash
tcd send hello.txt \
  --to root@target-host:/var/lib/tibet/inbox \
  --surface-context first-real-cross-host-push \
  --surface-profile claude \
  --surface-priority normal
```

What happens:

1. local file is packed as a sealed `.tza` envelope
2. Ed25519 signing is applied through the TIBET drop toolchain
3. `scp` delivers the bundle to the peer inbox
4. peer `continuityd` sees the arrival and runs the normal intake flow

## Quick start — send over HTTP

Start the peer daemon with an HTTP inbox listener:

```bash
TIBET_CONTINUITYD_INBOX=/tmp/tibet/inbox \
TIBET_CONTINUITYD_AUDIT=/tmp/tibet/audit.jsonl \
TIBET_CONTINUITYD_HTTP_PORT=8443 \
tcd run
```

Then send:

```bash
tcd send hello.txt \
  --transport http \
  --to http://target-host:8443 \
  --surface-context http-proof \
  --surface-profile claude \
  --surface-priority normal
```

Flow:

1. pack sealed envelope
2. HTTP `POST /inbox/<filename>`
3. peer HTTP inbox writes to the daemon inbox
4. inotify watcher sees the new object
5. sniff/classify path runs normally

Note:

- the HTTP inbox listener is transport-friendly, but in this release the
  HTTP layer itself is not the trust source
- the sealed bundle remains the integrity-bearing object

When enabled, HTTP delivery can also carry:

- a signed transport auth header
- a sender DID claim header
- optional AINS-based public key pin verification on the receiving side

## Quick start — identity-style target

Convention-based target form:

```bash
tcd send hello.txt --to jis:humotica:continuityd@p520
```

Current behavior:

- resolves to default SSH user + default inbox path by convention
- can optionally consult the AINS resolve API
- is a stepping stone toward richer identity-bound routing

HTTP-aware identity target:

```bash
tcd send hello.txt \
  --transport http \
  --to jis:humotica:continuityd@192.168.4.76
```

Current behavior:

- resolves the JIS-style destination into an HTTP inbox URL
- keeps the sealed object format unchanged
- can attach a signed HTTP auth header
- can attach a sender DID claim header
- degrades gracefully if no AINS record exists

## Quick start — ACK / roundtrip receipt

```bash
tcd ack "2026-05-11.v058-roundtrip.claude.normal.tza" \
  --transport http \
  --to http://target-host:8443 \
  --note "delivered from laptop, ack from laptop"
```

What happens:

1. a small ACK payload is created locally
2. it is packed as a sealed `.tza` envelope
3. an `ack-of-<shortid>` semantic surface is produced
4. it is delivered through the same transport layer as `send`
5. peer `continuityd` receives it as a normal arrival event

This makes the receipt itself a continuity-bearing object.

## Modes

### `passive`

- observe
- classify
- audit
- advise

### `active`

- verify/fork/seal behavior enabled where configured
- operational continuity handling

### `strict`

- stronger policy expectations
- suited for sealed-only or higher-trust lanes

## Disposition table

| Intake class | Trigger | Disposition |
|---|---|---|
| `sealed-tbz` | TBZ magic + recognized surface | `trusted-candidate` |
| `sealed-tbz-no-ext` | TBZ magic, no/unknown extension | `trusted-candidate` |
| `disguised` | vendor-like name, no TBZ magic | `triage-disguised` |
| `json-text` | raw JSON state in sealed-oriented lane | `reseal-candidate` |
| `executable` | ELF / PE / executable signature | `quarantine` |
| `pdf` | PDF magic | `reject` |
| `unknown` | everything else | `quarantine` |
| `empty` | zero-byte file | `reject` |

## Proven proofs so far

### Portable evaluation

The external evaluation kit proves:

- preflight passes on fresh hosts
- conformance vectors classify correctly
- mini-pipeline runs end-to-end

### Dual-node host simulation

The dual-node lab proves:

- node A to node B handoff shape
- `sniff → verify-fork → seal` on both sides
- same stage/disposition pattern despite reseal

### Real cross-host SCP handoff

Proven:

- real host A packs and sends
- real host B receives and sniffs
- sealed bundle survives host boundary
- older peer daemon versions still recognize the container by magic bytes

### Real HTTP transport handoff

Proven:

- `tcd send --transport http --to http://host:port`
- peer HTTP inbox listener receives the bytes
- writes them into the inbox
- daemon watcher processes the arrival normally

This is the first practical proof that sealed continuity objects can be
carried through a simple HTTP ingress without changing the continuity
discipline.

### Identity-bound HTTP handoff

Proven:

- `tcd send --transport http --to jis:...`
- JIS-style destination resolution to HTTP inbox URL
- signed transport request
- DID sender claim header
- graceful AINS no-record fallback
- normal daemon arrival discipline after ingress

This shows that identity-bound transport can already happen without
depending on a future mux lane.

### ACK roundtrip primitive

Proven:

- `tcd ack <bundle-name> --to <target>`
- sealed ACK envelope generation
- delivery over the same transport carriers as `send`
- receipt itself becomes a continuity-bearing arrival event

### Mux transport handoff (v0.6.0+)

Proven:

- `tcd send --transport mux --to jis:...` opens a `tibet-mux` channel
  with intent `continuityd:inbox` and sends a base64-wrapped sealed
  envelope as a single frame
- `tcd mux-consumer` (or the daemon-integrated thread) polls
  `/api/mux/by-target` and materializes the frame into the inbox
- inotify picks up the file and the normal pipeline runs
- single-port (= one TCP port for many lanes, channel-segmented by
  identity + intent) without per-lane firewall openings
- live verified host-to-host (Kali laptop → JTel-brain server)

### Heartbeat short-circuit lane (v0.6.3+)

Proven:

- `tcd heartbeat --to jis:... --kind-detail liveness` packs a sealed
  envelope with `surface_priority=heartbeat`
- daemon verifies the identity pin and Ed25519 signature normally
- after successful verify, the heartbeat-lane emits `stage=heartbeat`
  audit record with full causal chain and SKIPS Fork / Seal / Police
- shutdown stats show `heartbeats_received=N` separately from
  `events_sealed`
- live verified: 4 heartbeats short-circuited, 2 normal envelopes
  proceeded to full pipeline, all from the same daemon

## Operational paths

The package now has three practical deployment/use surfaces:

- **package runtime**
  - `tcd run`
- **cross-host push**
  - `tcd send`
- **cross-host receipt**
  - `tcd ack`
- **reference deployment kit**
  - portable eval
  - systemd appliance
  - dual-node lab

Reference deployment kit:

- [`reference-deployment/README.md`](reference-deployment/README.md)

## FHS and first-run note

Production defaults are FHS-oriented:

- `/var/lib/tibet/...`
- `/var/log/tibet/...`

For laptop or peer-eval use, set user-writable env vars explicitly.

That split is intentional:

- production appliance defaults
- local/peer override paths

## Why this is different from plain file transfer

`scp`, HTTP, or future mux transport are not the core innovation by
themselves.

The important thing is that what moves is a:

- sealed
- signed
- continuity-bearing
- sniffable
- classifiable
- triageable

object.

Transport is replaceable.

Continuity discipline is the point.

This now also applies to receipts:

- an ACK is not just a side message
- it is also a sealed continuity object
- which can be sniffed, classified, audited, and handled like any other
  arrival

## Related stack pieces

- `tibet-drop`
  - pack/verify/seal primitives
- `tibet-phantom`
  - resumable state and ICC bridge
- `tibet-mux`
  - single-port multiplexed transport (= now wired, v0.6.0+)
- `tibet-overlay`
  - identity-oriented routing substrate
- `tibet-triage`
  - human-visible escalation surface

## Project direction

Near-term direction includes:

- richer identity-bound routing via AINS/JIS
- shutdown-signal persistence (= heartbeat with `kind_detail=shutdown`
  could write peer-offline state with TTL for liveness queries)
- stronger mirrored surface checking
- safer first-run ergonomics for non-root hosts
- deeper causal record integration
- replay-window + sender-pin policy hardening for the mux consumer lane

## License

MIT — Humotica + Root AI + Codex (2026)
