# continuityd External Eval Kit — Handoff

## Pad

```bash
cd /srv/jtel-stack/sandbox/ai/codex/continuityd-reference-deployment
```

## Snelste drie commando's

### 1. Portable basis-evaluatie

```bash
bash run-external-eval.sh portable
```

Verwacht:

- `preflight_status=PASS`
- `vector_status=PASS`
- `pipeline_status=PASS`
- `overall_status=PASS`

## 2. Portable evaluatie met bundle

```bash
bash run-external-eval.sh portable /pad/naar/bundle.tza
```

Verwacht:

- hash + magic + grootte
- juiste verifier-keuze (`tbz` of `tibet_drop`)
- unpack naar tempdir
- eventuele `README` preview
- daarna ook de gewone vector + mini-pipeline checks

## 3. Dual-node handoff demo

```bash
bash run-external-eval.sh dual-node
```

Verwacht:

- `node-a`:
  - `sniff`
  - `verify-fork`
  - `seal`
- `node-b`:
  - `sniff`
  - `verify-fork`
  - `seal`
- `same_stage_pattern=True`
- `same_disposition_pattern=True`
- `dual_node_compare_status=PASS`

## Opruimen na dual-node

```bash
bash dual-node-lab/stop-lab.sh
```

Eventueel volledig resetten:

```bash
rm -rf /tmp/continuityd-dual-node-lab
```

## Wanneer welk spoor?

- `portable`
  - laptop
  - smartphone VM
  - snelle peer-check
- `systemd`
  - echte proef-VM
  - resident daemon
- `dual-node`
  - handoff tussen twee nodes
  - A→B continuity demo

## Belangrijke nuance

In de eerste dual-node lab-vorm hoeft `continuity_id` niet identiek te
blijven tussen A en B.

Deze lab-vorm bewijst nu:

- handoff reproduceerbaarheid
- dezelfde stage-vorm
- dezelfde disposition-vorm

Niet:

- definitieve cross-host lineage resume
