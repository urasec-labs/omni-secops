# Documentation

| Path | Content |
|---|---|
| `architecture/overview.md` | System context, containers, components, trust boundaries, NFRs |
| `standards/knowledge-format.md` | Front matter, section order, command and evidence conventions |
| `decisions/` | Architecture decision records (ADR) |
| `faq.md` | Common questions and troubleshooting |
| `glossary.md` | Vocabulary shared across the archive |

## Reading order for a new maintainer

1. `../README.md` - what this is and how the domains fit together.
2. `00-governance/charter.md` - the rules of engagement for the project itself.
3. `architecture/overview.md` - how the parts connect.
4. `../10-crosswalk/README.md` - the integration model and identifier namespaces.
5. `standards/knowledge-format.md` - how to write a document that passes review.
6. `../CONTRIBUTING.md` - the submission contract.
7. `../11-automation/README.md` - the generators and gates.

## Documentation principles

1. **No document without an owner.** Front matter names a domain, and
   `CODEOWNERS` names a human.
2. **No procedure without a verification step.** See `standards/knowledge-format.md` §2.
3. **No assertion without a source.** Either cite upstream, cite the lock file
   ref, or state that it is an internal engineering decision (with an ADR).
4. **Prefer tables.** They diff well and they can be validated.
5. **The crosswalk is not documentation.** It is data. If a claim needs to be
   enforced, put it in `10-crosswalk/` and let `ssactl verify` enforce it.
