# Privacy4All — Privacy 4 All

Builder hub for the **Midnight blockchain** — open-source privacy apps, tools
and guides, built and maintained by Kyle Cox (@kshot9000).

**Live hub:** https://kshot3000.github.io/Privacy4All/

> Tagging the Midnight team: @midnightntwrk (GitHub) · @MidnightNtwrk (X) —
> this is an independent community builder hub for the Midnight ecosystem
> (14 catalogued projects, 4 live sites at launch). Team feedback and
> corrections welcome.

## What is Midnight?

Midnight is a privacy-first blockchain and Cardano partner chain built around
**programmable privacy**: a public state for what must be verifiable, a private
state for what must stay yours, and zero-knowledge proofs (generated mostly on
the user's own device) to connect the two. Its pattern is **selective
disclosure** — prove a fact ("over 18", "paid in full") without revealing the
underlying data. Smart contracts are written in **Compact**. NIGHT is the
network token (held on Cardano); holding NIGHT generates **DUST**, the
renewable resource that pays for shielded transactions.

- Official site: https://midnight.network/
- Developer docs: https://docs.midnight.network/
- This builder repo: https://github.com/Kshot3000/Privacy4All

## Flagship projects (live)

| Project | Status | What it is |
|---|---|---|
| [Night Messenger](https://kshot3000.github.io/Night-Messenger-/) | ✅ live | Free private DMs on Midnight with selective disclosure (web + Android). ([source](https://github.com/Kshot3000/Night-Messenger-)) |
| [PlutusShield](https://kshot3000.github.io/PlutusShield/) | ✅ live | Cardano Preview + Midnight Preprod DeFi/smart-contract insurance — Aiken validators, Compact policy registry, SDK, oracle relay. Testnet only, unaudited. ([source](https://github.com/Kshot3000/PlutusShield)) |
| [PRISM — CIP-113 Studio](https://kshot3000.github.io/Grok-CIP-113/) | ✅ live | Programmable-token design/research studio with a Midnight DApp Connector (v4), CIP-30 read-only wallet connect and live Koios explorer. Design/research only — no minting or signing. ([source](https://github.com/Kshot3000/Grok-CIP-113)) |
| [NightDream](https://nightdream.xyz/) | ✅ live | Analytics desk with a Midnight/NIGHT desk and DUST calculator, plus Cardano charts, DEX liquidity and portfolios. Real live data only. ([source](https://github.com/Kshot3000/nightdream.xyz)) |

## Full catalogue

| Repo | What it does |
|---|---|
| [nocturne](https://github.com/Kshot3000/nocturne) | Private messaging & email on Midnight |
| [Midnight-GrokBot-Agent](https://github.com/Kshot3000/Midnight-GrokBot-Agent) | Midnight build lab — Compact starters, Lace kit, agent escrow |
| [Cardano-Midnight-Qwen-Builder](https://github.com/Kshot3000/Cardano-Midnight-Qwen-Builder) | Agent escrow, network monitors, privacy dashboards; fleet showcase hub |
| [midnight-bank](https://github.com/Kshot3000/midnight-bank) | ZK banking example — private transfers, encrypted balances (fork, upstream work) |
| [midnight-contracts](https://github.com/Kshot3000/midnight-contracts) | Midnight example contracts, Compact / MeshJS (fork) |
| [midnight-apps](https://github.com/Kshot3000/midnight-apps) | Starter dApps on Midnight Network (fork) |
| [midnight-awesome-dapps](https://github.com/Kshot3000/midnight-awesome-dapps) | Awesome list of Midnight Network dApps (fork) |
| [midnight-rwa](https://github.com/Kshot3000/midnight-rwa) | Real-world assets on Midnight, Brick Towers example (fork) |
| [midnight-seabattle](https://github.com/Kshot3000/midnight-seabattle) | ZK Sea Battle game on Midnight, Brick Towers example (fork) |
| [Cardano4all](https://github.com/Kshot3000/Cardano4all) | Sister hub: building for the Cardano blockchain ([live](https://kshot3000.github.io/Cardano4all/)) |

## Tools on the hub (local only, no wallet needed)

- **Paste-and-protect redactor** — finds and masks email addresses, Cardano
  addresses and US phone numbers in text you paste. Runs entirely in your
  browser; nothing is sent anywhere.
- **Selective-disclosure planner** — sorts what a service asks for into
  *share it / prove it instead / keep it private*, the Midnight way.
- **NIGHT → DUST capacity estimator** — exact BigInt maths on the
  5 DUST-per-NIGHT capacity model used by the NightDream Midnight desk.
  A ceiling estimate, not a generation promise.
- **What does this dApp see?** — tick the permissions a dApp asks for
  (balance, history, viewing key, blind signing…) and get a plain-language
  exposure rating for each, with the Midnight alternative: prove it
  instead of showing it. Never connects a wallet or signs anything.
- **Prove it, don't show it — ZK claim simulator** — pick a claim (age,
  balance, income, membership length), enter a private value and a
  threshold, and see exactly what a verifier learns from a zero-knowledge
  proof (the claim, and whether it holds) and what stays hidden. Honestly
  labelled a teaching simulation, not a cryptographic proof: the exact
  BigInt comparison runs locally in your browser.
- **Compact snippet library** — five privacy patterns (public counter,
  hash commitment, selective disclosure, threshold proof, private vote),
  each showing what stays private, what goes on the public ledger and
  what is deliberately disclosed with `disclose()`. Honestly labelled
  simplified teaching patterns, not production contracts — Compact is
  still evolving, so check the current docs and compile before real use.
- **How DUST works — lifecycle explainer** — step through hold →
  generate → spend → regenerate with your own numbers, on the same exact
  BigInt 5× ceiling model: how many shielded transactions a capacity
  covers, what is left, and what regenerates while you keep holding.
  Honestly labelled a teaching model of amounts and order only — it
  states no generation rate or time, because the real rate depends on
  Midnight network parameters.
- **Commit now, reveal later — hash commitments** — type a secret and
  get a real SHA-256 commitment computed locally in your browser with
  the Web Crypto API: publish the hash now, reveal the secret later,
  and anyone can recompute and confirm it matches — the pattern behind
  sealed bids, votes and predictions, and tool 6's commit-to-a-secret
  snippet. Nothing leaves the page. Honestly labelled with its limits:
  a short or guessable secret can be brute-forced from its hash (real
  systems add a long random salt), and the digest format is a teaching
  format, not Compact's on-chain persistent hash.

## Guides

- [Getting started building on Midnight](guides/getting-started-midnight.md) —
  official docs, Compact, Lace, testnets and proof basics, in learning order.

## How the hourly builder loop works

1. An hourly loop works this repo: building, fixing and improving for the
   Midnight blockchain — correctness first, then new privacy apps and tools,
   accessibility, performance and docs accuracy.
2. Anything shipped is tested (`node tests/test-site.js`) and verified against
   the live GitHub Pages site before it's claimed done. A run that can't produce
   a genuine improvement ships nothing — quiet runs beat mediocre changes.
3. Finished work is committed and pushed to `main` with a descriptive message —
   the commit history is the run log.
4. Every user-facing surface carries the builder's Cardano (ADA) donation
   address and X account, and tags the Midnight team (@midnightntwrk on GitHub,
   @MidnightNtwrk on X) where the platform supports it.

## Support

Cardano (ADA) donations (click-copy on the hub):
`addr1q8hnl6vl5a6k3rw3n5g3jtte696zcl76kfatzv7gpswa9r0dj7fma6klq55y4ffm7tf0em09udnyhuk4ah92pl5x9jpqjae44v`

Built by Kyle Cox — [@kshot9000 on X](https://x.com/kshot9000) ·
[github.com/Kshot3000](https://github.com/Kshot3000)

*Independent builder project — not affiliated with the Midnight Foundation
or IOG.*
