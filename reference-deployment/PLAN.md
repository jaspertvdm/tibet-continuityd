# continuityd Reference Deployment Plan

## Aanleiding

`tibet-continuityd` is nu voorbij de losse demo-fase:

- sniff/classify werkt
- verify/fork werkt
- trust-kernel zone clarity werkt
- seal + atomic transfer + coalescing werken
- strict mode, police en backpressure zijn in de runtime-lijn geland
- dual-host gedrag is al operationeel aangetoond

De volgende stap is daarom niet nog een losse demo, maar een
**reproduceerbare deployment-opzet**.

## Doel

Drie referentievormen aanbieden:

1. een **portable peer-eval kit**
2. een **systemd proef-appliance**
3. een **dual-node continuity lab**

## Kernprincipe

Niet alleen:

- "kijk naar onze output"

Maar:

- "draai dezelfde evaluatie zelf"
- "laat dezelfde daemon op jouw host lopen"
- "zie hetzelfde gedrag tussen twee nodes"

## Track 1 — Portable Eval

Doel:

- Richard / smartphone terminal / losse Debian VM
- één map
- één startcommando
- minimale afhankelijkheden

### Deliverables

- `check-env.sh`
- `run-eval.sh`
- `run-mini-pipeline.sh`
- `expected-results.md`
- `fixtures/`

### Minimale flow

1. preflight:
   - `python3`
   - `tbz` of compatibele verifier
   - `sha256sum`
2. artifact check:
   - magic
   - bytes
   - hash
3. verify + unpack
4. fixture replay
5. samenvatting:
   - `PASS`
   - `PARTIAL`
   - `FORMAT MISMATCH`
   - `NEEDS TOOL X`

### Success criterion

Een externe host kan zonder systemd of root:

- de bundle openen
- de evaluatie draaien
- een begrijpelijk resultaat krijgen

## Track 2 — systemd Appliance

Doel:

- echte proef-VM
- daemon als resident subsystem
- operator-achtig gedrag

### Deliverables

- `tibet-continuityd.service`
- `.env` of configvoorbeeld
- lane layout document
- `drop-demo-fixtures.sh`
- `show-audit-summary.sh`

### Vaste lanes

- `inbox/`
- `quarantine/`
- `triage/`
- `outbox/`
- `audit/`

### Evaluatievragen

- start de service schoon?
- houdt hij SIGTERM goed?
- blijven audit en directories leesbaar?
- werkt strict mode zoals verwacht?
- blijft seal atomic?

### Success criterion

Een VM kan als zelfstandige proefhost draaien met:

- echte service
- echte directories
- echte restart/shutdown discipline

## Track 3 — Dual-Node Lab

Doel:

- de continuity-lijn over twee nodes laten lopen
- niet alleen single-host verify/seal, maar echte handoff

### Vorm

Twee containers of twee VM's:

- `node-a`
- `node-b`

Tussenlaag:

- rsync
- shared volume
- of een simpele mocked mux lane

### Deliverables

- `docker-compose.yml` of VM-runbook
- `node-a/`
- `node-b/`
- `send-a-to-b.sh`
- `compare-audit.sh`

### Evaluatievragen

- blijft `surface_hash` gelijk?
- blijft `continuity_id` coherent?
- klopt de `generation`-stijging?
- blijft de outbox van A geldig als inbox van B?

### Success criterion

Twee onafhankelijke nodes tonen:

- hetzelfde policygedrag
- dezelfde lineagestructuur
- reproduceerbare handoff

## Aanbevolen volgorde

1. `portable-eval`
2. `systemd-appliance`
3. `dual-node-lab`

Reden:

- eerst onafhankelijke evaluatie
- dan resident operationele vorm
- dan host-to-host continuity

## Open architectuurvragen

- welke verifier is canoniek voor de peer-eval kit?
- hoe markeren we format-family schoon genoeg als er meerdere
  TBZ-lineages bestaan?
- welke minimale toolchain mag een externe evaluator verwachten?
- wordt `dual-node` eerst `rsync`-gebaseerd of direct met een
  expliciete mux-simulatie gebouwd?

## Kortste samenvatting

`v0.3` bewees het systeemgedrag.

Deze reference deployment fase moet bewijzen dat dat gedrag:

- draagbaar
- resident
- en host-overstijgend reproduceerbaar is.
