# Lab Environments

| Field | Value |
|---|---|
| `domain` | Validation |
| `owner` | `@lab-maintainer` |
| `source` | `0xdea/awesome-hacking`, `meirwah/awesome-incident-response` |
| `estate` | `09-labs/infrastructure/` |
| `classification` | T0 (deliberately vulnerable, lab only) |

## 1. Rules

1. **Never deploy the lab estate on a routable network.** Use a host-only or
   isolated lab segment.
2. **Never store real credentials, real data, or real keys in a lab app.**
3. Lab machines carry no access to production identity providers.
4. Every emulation states the expected telemetry and expected rule ids.
5. Any deviation from the expected telemetry is a finding, recorded in
   `10-crosswalk/attack-coverage/attack-coverage.csv`.

## 2. Contents

| Path | What it is | Source |
|---|---|---|
| `apps/` | deliberately vulnerable applications | `09-labs/apps/docker-compose.dvwa.yml` |
| `infrastructure/` | Terraform/Docker estate | `09-labs/infrastructure/terraform-lab.md` |
| `emulations/` | atomic attack emulations per `EV-*` / `CH-*` | `09-labs/emulations/CH-001.md` |
| `ctf/` | categories and tooling | `09-labs/ctf/` |

## 3. Build

```bash
cd 09-labs/infrastructure
docker compose -f docker-compose.lab.yml up -d
# verify
python 11-automation/scripts/lab_healthcheck.py --root ../..
```

## 4. Teardown

```bash
docker compose -f docker-compose.lab.yml down -v
# verify nothing is left listening
ss -tulpn | grep -E ':(80|443|22|8080)\b' || echo "lab torn down"
```
