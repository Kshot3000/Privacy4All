# Privacy4All — Privacy 4 All

Builder hub for the **Midnight blockchain** — open-source privacy apps, tools
and guides, built and maintained by Kyle Cox (@kshot9000).

**Live hub:** https://kshot3000.github.io/Privacy4All/

> Tagging the Midnight team: @midnightntwrk (GitHub) · @MidnightNtwrk (X) —
> this is an independent community builder hub for the Midnight ecosystem
> (16 catalogued projects, 4 live flagship sites). Team feedback and
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
| [midnight-faucet-api](https://github.com/Kshot3000/midnight-faucet-api) | API behind the Midnight testnet faucet, open-sourced from midnight-faucet (fork) |
| [midnight-docs](https://github.com/Kshot3000/midnight-docs) | Source for the official Midnight developer docs site, Docusaurus (fork) |
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
- **What can an observer see? — public vs shielded** — pick an action
  (a public-chain transfer, a shielded Midnight transfer, a proof with
  one disclosed claim, a shielded contract call) and see it from a
  stranger reading the ledger: what they can see, what they cannot, and
  what still leaks anyway. Honestly labelled a simplified teaching
  model of ledger visibility only — it does not model network-level
  metadata (timing, IP addresses) as solved, and every scenario names
  its residual leaks.
- **Share a view, not your wallet — viewing-key scope simulator** —
  pick a disclosure scope (a single transaction, one counterparty, one
  time window, or full history) for when an accountant, auditor or
  counterparty legitimately needs to check shielded activity, and see
  what a viewer at that scope can see, cannot see, and the risks to
  weigh — including the two rules that hold at every scope: viewing is
  read-only (it never grants spending or signing), and a disclosure
  once seen cannot be un-seen. Honestly labelled a simplified teaching
  model of scoped disclosure in principle — exact capabilities depend
  on the wallet and contract, so check the current docs before
  granting a real one. No key is entered or generated on the page.
- **Make it unguessable — secret strength & salt for commitments** —
  tool 8's honest limit made measurable: check a commitment secret's
  strength (character pool, best-case entropy bits, and how long an
  offline guessing attack at a labelled assumed rate of 10 billion
  guesses a second would take on average), then generate the standard
  fix — a 16-byte (128-bit) random salt from Web Crypto
  `getRandomValues`, with the exact combined `secret|salt` format to
  commit in tool 8 and reveal together later. Honestly labelled a
  rough teaching estimate, not a security audit: it assumes uniformly
  random characters, and human-chosen secrets are far more
  predictable — so its numbers are a ceiling on safety, never a
  guarantee. Everything runs locally; nothing is sent anywhere.
- **Prove you're on the list — Merkle inclusion proofs** — paste a
  list (an allowlist, a voter roll, a set of eligible wallets), get
  its Merkle root, and build a real inclusion proof for any one
  entry: the sibling hashes along its path, replayed and re-verified
  against the root on the same page, so a verifier can confirm
  membership without ever seeing the rest of the list. Real SHA-256
  via Web Crypto, leaves domain-separated from internal nodes, odd
  nodes promoted unchanged rather than duplicated, duplicates
  rejected as proof-ambiguous. Honestly labelled: a Merkle proof is
  not zero-knowledge — it reveals the entry, its position and the
  rough size of the list, and guessable entries can be
  dictionary-checked against their leaf hashes (tool 11's lesson).
  The hashed-message format is a teaching format, not a specific
  chain's tree format; nothing connects to a chain or a wallet.
- **Split a secret — XOR secret sharing** — split a throwaway secret
  into 2–8 shares: the secret's bytes are XORed with fresh random
  bytes from Web Crypto, so any share on its own is random bytes that
  reveals nothing about the secret's content, and only the complete
  set rebuilds it, character for character — real secret sharing
  computed locally, the one-time-pad argument, not a simulation.
  Combine validates the set strictly (exactly one of each share, one
  split, one length) rather than guessing at partial sets. Honestly
  labelled all-of-n: losing one share loses the secret — threshold
  (k-of-n) sharing such as Shamir's is named as the real-systems
  answer there and implemented by the next tool — and a share's
  length leaks the secret's length. Never paste a real seed phrase
  into any web page, including this one.
- **Spend it once, stay private — notes & nullifiers** — create a
  shielded note and only its commitment hash is published; spend it
  and a second, domain-separated hash — its nullifier — is published
  instead. A pretend in-page ledger enforces the one mechanical rule
  (a nullifier may appear only once, ever), so a second spend of the
  same note is blocked as a double-spend and a never-created note is
  rejected as unknown — while the two hashes alone cannot be linked
  without the secret. Real SHA-256 via Web Crypto, pure local logic,
  inputs never mutated. Honestly labelled a simplified teaching
  model, not how a real Midnight note is constructed: real notes use
  random secrets nobody can guess plus a zero-knowledge existence /
  ownership proof, a human-chosen secret here can be
  dictionary-checked against both hashes, and a leaked secret links
  its commitment and nullifier after the fact.
- **Split with a safety net — Shamir k-of-n sharing** — the threshold
  scheme the XOR tool names: split a throwaway secret into n shares
  (threshold k from 2, up to 8 shares) where any k rebuild it exactly
  and k−1 reveal nothing about its content. Real Shamir sharing over
  GF(256) — each secret byte is a polynomial's constant term, the
  other coefficients are fresh Web Crypto random bytes, shares are
  points on it, and rebuilding is Lagrange interpolation at zero,
  all computed locally. Combine validates strictly (at least k
  distinct shares, one split, one length). Honestly labelled a
  teaching implementation, not an audited library: there is no
  checksum, so with exactly k shares one wrong or mistyped share
  rebuilds a wrong secret silently, and a share's length leaks the
  secret's length. Never paste a real seed phrase into any web page,
  including this one.
- **Seal it so only they can read it — password-encrypted messages** —
  the reversible counterpart to the hash tools: seal a throwaway
  message with a password and it is encrypted for real, locally,
  with AES-GCM — the password stretched by PBKDF2-HMAC-SHA-256
  (210,000 rounds, fresh random 16-byte salt and 12-byte IV per
  seal) into a 256-bit key, in a versioned `p4a-sealed-v1` format.
  The sealed text is safe to share on its own; only the password
  opens it, and because GCM is authenticated, a wrong password or
  one changed character fails outright instead of returning
  gibberish. Honestly labelled a teaching implementation, not an
  audited encryption product: its safety is exactly the password's
  safety (PBKDF2 slows offline guessing but cannot save a weak
  password), the sealed length reveals the message's approximate
  length, and anyone with both the sealed text and the password
  can read it — so share them by different channels. Never paste a
  real seed phrase into any web page, including this one.
- **Sign it — prove it came from you, without sharing your key** —
  the public counterpart to sealing: the message stays public, but
  anyone can check that whoever holds one private key endorsed
  exactly these words, and that not one character changed since.
  Generates a real ECDSA key pair locally on the P-256 curve (the
  curve behind passkeys/WebAuthn; Bitcoin and Ethereum use its
  sibling secp256k1, which Web Crypto does not offer) and signs
  with ECDSA over SHA-256, in a versioned `p4a-sig-v1` format;
  keys are handled as hex (91-byte SPKI public key, 138-byte
  PKCS#8 private key). Verification is strict about the
  distinction that matters: a matching signature is true, a
  well-formed mismatch is false, malformed input is null.
  Honestly labelled a teaching implementation, not an audited
  wallet: a signature does not hide the message, does not prove
  a legal name or real-world identity, and does not prove when
  the signing happened; the private key IS the identity — anyone
  holding it can sign as you, with no recovery — and keys exist
  only in the page, so reloading loses them. Never paste a real
  wallet's private key into any web page, including this one.
- **Agree on a secret nobody saw — key agreement (ECDH)** — how
  two people who have never met get a secret they both know and
  nobody else does, over a channel everyone can read: each side
  generates an ECDH key pair on P-256 locally, only the public
  keys are exchanged, and each side mixes its own private key
  with the other's public key — both land on exactly the same
  32-byte shared secret, a value that is never exchanged and
  cannot be worked out from the public keys alone. The page
  practises both sides (your agreement, then the other side's,
  which must match exactly) and derives a SHA-256 fingerprint of
  the secret that is safe to compare out loud. Honestly labelled
  a teaching implementation, not an audited messaging app: real
  systems never use the raw secret directly (it goes through a
  key-derivation function first), agreement alone does not prove
  who the other public key belongs to (a man-in-the-middle who
  swaps both public keys reads everything — hence fingerprint
  comparison), and the secret is displayed here for practice
  only — a real app never shows it. Never paste a real wallet's
  private key into any web page, including this one.
- **Stretch one secret into proper keys — key derivation (HKDF)** —
  the step the key-agreement tool's warning points at: the raw
  shared secret is never a key to use directly, so this derives
  separate 32-byte keys from it, locally and for real, with HKDF
  (RFC 5869) over SHA-256. The purpose label is mixed in as
  HKDF's info string (messaging / storage / backup), so each
  purpose gets an unrelated key — leaking one reveals nothing
  about the others or the secret — and an optional 16-byte salt
  separates sessions the same way. The salt is not a secret:
  both sides must simply pick the same purpose and the same
  salt, and may exchange the salt openly. A check form re-derives
  and compares, keeping the site's strict distinction: an exact
  match is true, a well-formed mismatch is false, malformed
  input is null; the test suite cross-checks the derivation
  against Node's independent `hkdfSync`. Honestly labelled a
  teaching implementation, not an audited key-management
  product: derivation does not strengthen a weak input — a
  guessable secret derives guessable keys — because HKDF
  assumes high-entropy input, which is why there is deliberately
  no password stretching here. Never paste a real seed phrase
  or production secret into any web page, including this one.
- **Use the key — lock a message with the key you both derived** —
  where the chain lands: the 32-byte key the HKDF tool derives
  imports directly as a real AES-GCM key and locks a message
  locally, in a versioned `p4a-keysealed-v1` line carrying only
  a fresh random IV and the ciphertext. No password, no
  stretching and no salt — the derived key is already
  high-entropy key material, which is the contrast with the
  password-sealing tool, whose sealed text has to carry a salt
  because it starts from a human password. The GCM tag means a
  wrong key fails outright, exactly like a tampered or
  truncated message; there is no fallback. Honestly labelled a
  teaching implementation, not an audited messaging app: real
  messengers add ratcheting, message numbering and key erasure,
  the key itself is the whole secret (whoever it leaks to reads
  everything locked with it), and locked length leaks the
  message's approximate length. Never paste a real wallet key
  or a production session key into any web page, including
  this one — practise with throwaway keys from the agreement
  and derivation tools.
- **Know it's really from them — sign it, then seal it** —
  closes the gap tool 20 names: a session-key seal proves the
  key, not the person, and anyone holding the key can seal a
  message in anyone's name. Here the sender signs the message
  with the signing tool's ECDSA key first, and the signature
  rides inside the AES-GCM seal next to the message, as a
  small versioned JSON envelope (`p4a-signed-v1`) in a
  `p4a-authsealed-v1` line. The opener opens the seal, then
  verifies the signature against the sender's public key — and
  the two answers stay separate: a message that opens but was
  signed by a different key comes back with its text and
  `verified === false`, never silently trusted and never
  hidden. Honestly labelled a teaching implementation, not an
  audited messaging app: the signature proves the signing key,
  not a legal name, and it only means anything if the public
  key really is the sender's, which has to be established
  outside this page. Never paste a real wallet's private key
  into any web page, including this one.
- **One key per message — the ratchet** — builds the fix
  tool 20 names for its one-key-for-everything warning: a
  symmetric hash-chain ratchet. A chain state
  (`p4a-chain-v1:<position>:<chain key>`) starts from a
  tool-19 session key at position 0; each step runs
  HKDF-SHA-256 twice with separate info strings — one output
  is that message's own key, sealing through tool 20's exact
  `p4a-keysealed-v1` line, the other is the next chain key —
  and HKDF's one-wayness means an earlier message key cannot
  be recomputed from a later state, so overwriting an old
  state erases its messages for good: forward secrecy for the
  past. Honestly labelled a teaching implementation, not an
  audited messaging app: the chain protects the past only —
  a leaked current state opens everything after it until
  both sides agree fresh keys — messages open strictly in
  order, each direction needs its own chain, a chain is
  capped at a labelled 1,000,000 messages rather than
  running unbounded, and a failed open advances nothing.
  Never paste a real wallet key or a production session
  key into any web page, including this one.
- **Heal the chain — a fresh agreement restarts the
  ratchet** — builds the recovery tool 22 names for a
  leaked chain state: a simplified version of the
  asymmetric ratchet real messengers run automatically.
  Both holders of a direction's chain make fresh tool-18
  agreement pairs, swap the public keys openly, and mix
  the fresh ECDH secret with the current chain key
  through HKDF — the secret as the input, the chain key
  as the salt, under its own `privacy4all-heal-v1` label —
  landing on a new `p4a-chain-v1` chain at position 0
  that someone holding only the leaked state cannot
  follow, because following takes a fresh private key
  they never had. Honestly labelled a teaching
  implementation, not an audited messaging app: healing
  protects only what comes after it, it does not unlock
  the past or help while a leak is still live, both
  sides must heal from exactly the same current state
  or their healed chains diverge and seals fail closed,
  and real messengers run this step on every reply.
  Never paste a real wallet key or a production session
  key into any web page, including this one.
- **Hide the length — pad it to one size before
  sealing** — builds the fix tools 13, 15, 16 and 20 all
  name for their shared leak: a sealed text's length
  tracks the message's length. Before sealing, the
  message's UTF-8 bytes are padded to exactly one of
  four labelled bucket sizes (256 / 1,024 / 4,096 /
  16,384 bytes) — an 8-byte header (`P4AP` magic plus
  the true byte length) in front, fresh Web Crypto
  random bytes behind — and the whole block is sealed
  with AES-GCM under a tool-19 session key in the
  `p4a-paddedseal-v1` format, so the tag covers the
  filler too and two messages in one bucket seal to
  exactly the same length. Honestly labelled a teaching
  implementation, not an audited messaging app: padding
  hides length only inside a bucket (which bucket still
  shows), timing and frequency are untouched, and real
  messengers pad inside a ratcheted protocol with cover
  traffic on top. Never paste a real wallet key or a
  production session key into any web page, including
  this one.
- **Out of order, still private — skipped message
  keys** — builds the store tool 22 names as its
  missing piece, the way Signal's protocol answers
  out-of-order delivery. Seals carry their position on
  the outside (`p4a-oooseal-v1` — tool 20's exact
  AES-GCM seal under that position's ratchet key,
  numbered); when a message arrives ahead of the
  chain, the receiver steps the chain forward and
  banks the skipped positions' message keys in a
  small store (`p4a-skipped-v1`), and a late message
  opens from its banked key — which is erased the
  moment it is used, so it opens exactly once and a
  replay gets nothing. The store is capped at 32 keys,
  and one open will not step the chain more positions
  than the store could hold the skipped keys for,
  rather than warehousing keys for messages that may
  never arrive; a mismatched state/store pair
  is refused outright, and a failed open consumes
  nothing. Honestly labelled a teaching implementation,
  not an audited messaging app: a banked key pauses
  forward secrecy for its position until its message
  arrives, the position number is visible metadata,
  and tool 23's heal remains the answer to a leak.
  Never paste a real wallet key or a production session
  key into any web page, including this one.

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
