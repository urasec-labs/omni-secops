# Threat Intelligence

| Field | Value |
|---|---|
| `domain` | CTI |
| `owner` | `@cti-maintainer` |
| `feeds` | `08-threatintel/feeds/feed-registry.yaml` |
| `iocs` | `08-threatintel/ioc/` (schema `12-schemas/ioc.schema.json`) |
| `actors` | `08-threatintel/actors/` |
| `attack` | `08-threatintel/attack/technique-pages/` |

## 1. Operating model

```
  feeds ──► normalise ──► enrich ──► score ──► distribute ──► measure
  (yaml)   (12-schemas)  (actor   (confid.  (Suricata /   (hit rate,
                      ioc.json)  mapping)  Wazuh /    false pos,
                                            SIEM)     time-to-detect)
```

## 2. TLP handling

| Mark | Storage | Distribution | Example |
|---|---|---|---|
| TLP:CLEAR | repo `08-threatintel/ioc/` | public | open-source feed IOCs |
| TLP:GREEN | repo | internal | internal enrichment |
| TLP:AMBER | repo with `classification: T1` | named recipients only | partner-shared IOCs |
| TLP:AMBER+STRICT | external secret store, **not** in git | case participants | breach-specific IOCs |
| TLP:RED | external secret store, **not** in git | named individuals only | pre-release actor intel |

Red and Amber+Strict material must never be committed. Use the case management
system.

## 3. Quality metrics tracked quarterly

| Metric | Target |
|---|---|
| Feed freshness (p95 `last_seen` lag) | < 6 h for reliability A feeds |
| IOC precision (confirmed true positives / alerts) | > 90 % |
| Median time to detect (MTTD) for new feed IOCs | < 30 min |
| Percentage of IOCs with `expires` set | 100 % |
| Coverage of the active actor list | every tracked actor mapped |

## 4. Relationship to the crosswalk

CTI feeds the archive in both directions:

* **In**: `10-crosswalk/attack-coverage/attack-coverage.csv` maps actor
  techniques to the offensive and defensive artifacts.
* **Out**: `06-defense/blue-team/mitre-coverage.csv` shows which techniques are
  `offensive-only` or `gap`, which is the CTI priority queue for detection
  engineering.
