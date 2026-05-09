# tibet-continuityd Reference Deployment

Deze map is nu de **external evaluation kit** voor `tibet-continuityd`.

Doel:

- van demo naar reproduceerbare evaluatie
- van losse host-run naar resident subsystem
- van single-host pipeline naar host-to-host continuity proefopstelling

## Snelste start

Gebruik de wrapper:

```bash
bash run-external-eval.sh portable
bash run-external-eval.sh systemd
bash run-external-eval.sh dual-node
```

Of bekijk eerst:

- [QUICKSTART.md](QUICKSTART.md)

## REPO_ROOT — wanneer expliciet zetten

De scripts proberen `REPO_ROOT` automatisch te detecteren via
relatieve paden. Dat werkt alleen voor de oorspronkelijke
sandbox-locatie. Vanuit `/packages/tibet-continuityd/reference-deployment/`
moet `REPO_ROOT` expliciet worden meegegeven:

```bash
REPO_ROOT=/srv/jtel-stack bash run-external-eval.sh portable
```

Reden: scripts hebben dependencies op:

- `$REPO_ROOT/packages/tibet-continuityd/src` (daemon source)
- `$REPO_ROOT/sandbox/airdrop-cli/src` (tibet_drop, shadow tot
  v0.3.x convergence ticket-002)
- `$REPO_ROOT/sandbox/ai/codex/continuityd-test-packages` (fixtures)

Volledige path-flexibilization is gepland voor v0.4
(zie `tibet-continuityd-v04-to-v10-infrastructure-path.md`,
Phase 1 — Appliance Discipline).

## Tracks

- `portable-eval/`
  - peer-eval kit voor laptop / smartphone VM / externe host
- `systemd-appliance/`
  - proef-VM met echte daemon service en vaste lanes
- `dual-node-lab/`
  - twee-node handoff lab voor continuity over hosts heen

## Structuur

- `PLAN.md`
  - hoofdplan en volgorde
- `QUICKSTART.md`
  - keuzehulp per hosttype
- `run-external-eval.sh`
  - eenvoudige dispatcher naar de drie tracks

## Status

Deze kit is geen package-installer; het is een werkende referentie-opzet
voor:

- onafhankelijke peer-evaluatie
- systemd proefdeployment
- dual-node handoff validatie
