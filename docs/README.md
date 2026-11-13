# docs

Documentation for people and AI agents alike. Start with the architecture guide.

| Document | What it covers | Read it when |
|---|---|---|
| [architecture.md](architecture.md) | How the broker works, with diagrams: the two sign-ins, the localhost redirect, a tool call with approval, where every secret lives | You want to understand or present the design |
| [findings.md](findings.md) | Phase 2 results for each experiment: works, works with caveats, or blocked, and why. Negatives included | You want to know what was actually proven, and what failed |
| [test-log.md](test-log.md) | Generated evidence: the sandbox end-to-end run, Claude Duet's own calls on both brokers, and the live checks | You want the proof behind a claim |
| [live-setup.md](live-setup.md) | The steps only the owner can do on the live broker: passwords, sign-in, connector | You are setting up or reconnecting the live broker |
| [1password.md](1password.md) | Running the 1Password SDK on Cloudflare Workers (built, not currently in use) | You want to move the live secrets into 1Password |

`test-log.md` is written by scripts (`npm run test:e2e`, `npm run test:duet`, `npm run test:live`). Don't edit it by hand.

Material written mainly for AI agents (the original specs, session records, working notes) is in [../ai-docs](../ai-docs/README.md).
