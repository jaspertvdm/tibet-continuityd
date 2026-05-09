# tibet-continuityd

> **Continuous Integrity System Daemon for the Distributed Continuity OS.**

A residential trust-guardian that runs in the background of every
machine where TIBET cryptographic discipline must be continuously
enforced.

```
  Watch  → Sniff  → Verify  → Fork    → Triage  → Reseal
  inotify  libmagic  Ed25519   forward    quarant   periodic
                     +chain    causal     -ine
```

## Design axiom

> **Name is hint. Content is truth. Arrival is event.**
>
> — Codex, 9 May 2026

## v0.1 scope (this release)

- ✅ `Watch` — inotify on a single inbox lane
- ✅ `Sniff` — magic-byte recognition (TBZ + executables + PDF + JSON)
- ✅ Disposition classification per Codex' intake policy table
- ✅ Audit JSONL log + journald-friendly stderr logging
- ✅ Mode 1 (Passive Guardian): observe + log + advise
- ✅ systemd unit ready for deployment
- ⏭ v0.2 will add: `Verify` (cryptographic) + `Fork` (via phantom.icc)
- ⏭ v0.3 will add: `Seal` (continuous reseal) + `Police` (unpacked detect)

## Install

```bash
pip install tibet-continuityd
```

## Run (development)

```bash
TIBET_CONTINUITYD_INBOX=/tmp/inbox \
TIBET_CONTINUITYD_AUDIT=/tmp/audit.jsonl \
python3 -m tibet_continuityd
```

Drop a TBZ-prefixed file into `/tmp/inbox/`:

```bash
printf 'TBZ\x01\x00\x00\x00' > /tmp/inbox/sample.claude.tza
```

You will see:

```
arrival: 'sample.claude.tza' → sealed-tbz (trusted-candidate, 7B)
```

## Run (production, systemd)

```bash
sudo cp tibet-continuityd.service /etc/systemd/system/
sudo useradd -r -s /usr/sbin/nologin tibet
sudo mkdir -p /var/lib/tibet/{inbox,quarantine,triage,materialized}
sudo mkdir -p /var/log/tibet
sudo chown -R tibet:tibet /var/lib/tibet /var/log/tibet
sudo systemctl daemon-reload
sudo systemctl enable --now tibet-continuityd
journalctl -u tibet-continuityd -f
```

## Disposition table (v0.1)

| Intake class            | Trigger                                  | Disposition          |
|-------------------------|------------------------------------------|----------------------|
| `sealed-tbz`            | TBZ magic + recognized vendor extension  | trusted-candidate    |
| `sealed-tbz-no-ext`     | TBZ magic, no/unknown extension          | trusted-candidate    |
| `disguised`             | Vendor extension, no TBZ magic           | triage-disguised     |
| `executable`            | ELF / PE binary                          | quarantine           |
| `pdf`                   | PDF magic                                | reject               |
| `json-text`             | Plain JSON state in sealed-only zone     | reseal-candidate     |
| `unknown`               | Anything else                            | quarantine           |
| `empty`                 | Zero-byte file                           | reject               |

v0.1 logs the disposition only. v0.2+ will act on it
(Verify + Fork or Quarantine + Triage).

## Architecture & spec

- Spec: [`tibet-continuityd-spec.md`](https://humotica.com/specs/continuityd)
- Companion intake guide (Codex):
  [`tibet-continuity-guardian.md`](https://humotica.com/specs/continuity-guardian)

## License

MIT — Humotica + Root AI + Codex (2026)
