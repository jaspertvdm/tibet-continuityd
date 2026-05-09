# portable-eval Expected Results

Deze note beschrijft wat de eerste portable eval kit hoort te doen.

## Scope van v1

Deze kit bewijst:

- environment preflight
- conformance vector check tegen `sniff_payload()`
- mini continuityd run in `passive` mode
- fixture replay met alle vijf hoofddispositions

Deze kit bewijst nog niet:

- volledige `active` verify/fork/seal flow op willekeurige externe host
- dual-node continuity
- systemd deployment

## `check-env.sh`

Verwacht:

- `python3`
- `sha256sum`
- `xxd`
- `file`
- continuityd source tree
- fixture kit
- conformance vectors

`tbz` CLI en `tibet_drop` tooling mogen ontbreken; dat levert
`PARTIAL` op voor bundle-checks, niet automatisch totale mislukking.

## `run-eval.sh`

Zonder bundle argument:

- draait preflight
- draait conformance vector check
- draait mini pipeline
- eindigt normaal met:
  - `vector_status=PASS`
  - `pipeline_status=PASS`
  - `overall_status=PASS`

Met bundle argument:

- toont:
  - `file`
  - eerste 32 bytes
  - `sha256sum`
  - `wc -c`
- probeert verifier:
  - eerst `tbz`
  - anders `tibet_drop`

## `run-mini-pipeline.sh`

Verwacht:

- tijdelijke inbox + audit + log
- daemon in `passive` mode
- fixture replay via bestaande fixture-kit
- exact 5 auditregels

Verwachte semantic set:

- `2026-05-09.demo.claude`
  - `sealed-tbz / trusted-candidate`
  - `disguised / triage-disguised`
- `2026-05-09.session-resume.json`
  - `json-text / reseal-candidate`
- `2026-05-09.agent-drop.exe`
  - `executable / quarantine`
- `2026-05-09.operator-note.pdf`
  - `pdf / reject`

Success marker:

- `mini_pipeline_status=PASS`

## Interpretatie

### `overall_status=PASS`

De host kan:

- lokale continuityd semantiek reproduceren
- fixture-based intake correct classificeren
- de portable eval kit zonder systemd draaien

### `overall_status=PARTIAL`

De basis werkt, maar een specifieke verifier/toolchain ontbreekt of past
niet op het meegeleverde bundleformaat.

### `overall_status=FAIL`

Er is een echte fout in:

- preflight basis
- sniff semantiek
- mini pipeline
- of bundle handling
