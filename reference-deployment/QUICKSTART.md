# continuityd External Eval Quickstart

## Kies je spoor

### 1. Laptop / smartphone VM / losse Debian-host

Gebruik:

```bash
bash run-external-eval.sh portable
```

Dit doet:

- preflight
- conformance vector check
- mini continuityd run
- PASS / PARTIAL / FAIL samenvatting

Met bundle:

```bash
bash run-external-eval.sh portable /pad/naar/bundle.tza
```

### 2. Echte proef-VM met `systemd`

Gebruik:

```bash
bash run-external-eval.sh systemd
```

Dit toont:

- prepare command
- runbook
- lane-layout
- service files

Voor niet-root testmodus kun je ook:

```bash
export TIBET_APPLIANCE_STATE_ROOT=/tmp/tibet-appliance-state
export TIBET_APPLIANCE_LOG_ROOT=/tmp/tibet-appliance-log
bash systemd-appliance/prepare-appliance.sh /tmp/tibet-continuityd-appliance.env
```

### 3. Dual-node handoff demo

Gebruik:

```bash
bash run-external-eval.sh dual-node
```

Dit draait een one-shot:

- node A start
- node B start
- demo bundle in A
- bridge A → B
- compare audits

## Praktische interpretatie

### `portable`

Beste keuze als je wilt weten:

- kan deze host de basis evalueren?
- kan hij bundles openen?
- kan hij continuityd semantiek lokaal reproduceren?

### `systemd`

Beste keuze als je wilt weten:

- hoe ziet een resident proefhost eruit?
- welke lanes en env vars horen erbij?
- hoe zet ik dit als appliance op?

### `dual-node`

Beste keuze als je wilt weten:

- hoe loopt outbox van A naar inbox van B?
- blijft de stage-vorm hetzelfde?
- kan ik handoffgedrag zichtbaar maken?
