# ai-docs

Documents written for AI agents to read: the context an agent needs before working in this repo that isn't rules (those are in `CLAUDE.md`) and isn't reader-facing documentation (that is in [../docs](../docs/README.md)).

People are welcome to read these, but they are not polished for it.

| Document | What it is |
|---|---|
| [agent-notes.md](agent-notes.md) | Orientation for an agent picking up this repo: a map of the code, the traps already hit, how to test without breaking the owner's connections |
| [spec/2026-11-08-poc-spec.md](spec/2026-11-08-poc-spec.md) | Jack's original proof-of-concept spec, verbatim. The README and findings cite it by section number |
| [spec/2026-11-08-phase-2-brief.md](spec/2026-11-08-phase-2-brief.md) | Jack's Phase 2 brief, verbatim: experiments A to D and the definition of done |
| [sessions/2026-11-12-phase-2.md](sessions/2026-11-12-phase-2.md) | Session record for the Phase 2 work: what was decided, what failed, and why, in order |

## Conventions

- **Specs are kept verbatim** and dated by when Jack wrote them. Don't edit them; write a new one.
- **Session records** go in `sessions/`, named `yyyy-mm-dd-topic.md`. They record decisions and dead ends, not a transcript.
- **No secrets, ever.** This repo is public. Refer to the sandbox's dummy secrets by label (A to G) and to real ones by name only.
- **If people need it, it belongs in `docs/`.** Move it there and write it for them.
