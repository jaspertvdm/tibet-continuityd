# dual-node-lab Runbook

## Doel

Een proefopstelling waarbij `node-a` een bundle verwerkt en die daarna
als nieuwe arrival aan `node-b` doorgeeft.

## Stap 1 — prepare

```bash
bash prepare-lab.sh
```

Default root:

- `/tmp/continuityd-dual-node-lab`

Maakt:

- `node-a/`
- `node-b/`
- per node:
  - `inbox`
  - `quarantine`
  - `triage`
  - `outbox`
  - `outbox.staging`
  - `audit.jsonl`
  - `daemon.log`
  - `env`

## Stap 2 — start beide nodes

```bash
bash start-lab.sh
```

Dit start twee `tibet-continuityd` processen in `active` mode met
`enable_seal=true`.

## Stap 3 — inject demo bundle in node A

```bash
bash inject-demo.sh
```

Dit genereert lokaal een geldige sealed `.tza` voor `node-a/inbox`.

## Stap 4 — wacht kort en bridge A → B

```bash
bash bridge-a-to-b.sh
```

Dat kopieert de nieuwste sealed outbox bundle van A naar `node-b/inbox`.

## Stap 5 — vergelijk audits

```bash
bash compare-audit.sh
```

Verwacht:

- `node-a` heeft minstens:
  - `sniff`
  - `verify-fork`
  - `seal`
- `node-b` heeft na bridge ook minstens:
  - `sniff`
  - `verify-fork`
  - `seal`

## Stap 6 — status

```bash
bash show-status.sh
```

## Stap 7 — stop

```bash
bash stop-lab.sh
```

## Snelle one-shot demo

Voor één host of sandbox-validatie is dit vaak handiger:

```bash
bash run-lab-demo.sh
```

Dat doet:

- prepare
- start beide nodes
- inject demo bundle in A
- bridge A → B
- compare audits
- stop beide nodes

## Succescriteria

- beide nodes blijven draaien tot stop
- `node-a/outbox` bevat een resealed bundle
- `node-b/outbox` bevat na bridge ook een resealed bundle
- auditvergelijking toont stage- en semantic overlap

## Bewuste beperking

In deze eerste lab-vorm opent `node-b` een **nieuwe intake-cyclus**.
Dus:

- `continuity_id` hoeft niet identiek te blijven tussen A en B

Wat je hier vooral toetst:

- handoff reproduceerbaarheid
- stage-consistentie
- dezelfde format family over twee nodes
