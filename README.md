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
- **For their key only — a sealed box anyone can close,
  only they can open** — the case every earlier seal
  leaves out: sending something private to someone who
  is not there, where all you have is their published
  public key. The sender makes a fresh, one-message
  ECDH pair (tool 18), agrees it with the recipient's
  public key, stretches the result once with HKDF —
  the one-message public key itself as the salt, so
  the key is bound to this box alone — and seals with
  tool 20's AES-GCM in a versioned `p4a-box-v1` line
  whose ephemeral public key rides on the outside in
  plain view, because it is not a secret. The recipient
  mixes it with their private key, lands on the same
  secret and opens; anyone else lands on a different
  secret and the seal refuses. The one-message private
  key is never stored, shown or sent. Honestly
  labelled a teaching implementation, not an audited
  messaging app: a box proves nothing about who sent
  it (the public key is public — tool 21 is the answer
  when the sender matters), there is no ratchet, so a
  private key copied later opens every box ever closed
  to it, and a swapped public key closes every box to
  the swapper instead. Never paste a real wallet key
  or a production private key into any web page,
  including this one.
- **A box that names its sender — sign it, then close
  it in the box** — tool 26's missing half, built from
  tools 17, 21 and 26: the sender signs the message
  with their tool-17 signing key, the signature rides
  inside the box in tool 21's `p4a-signed-v1` envelope
  (inside, so only the recipient ever sees it), and
  the envelope is closed like a tool-26 box in its own
  `p4a-authbox-v1` format, with its own HKDF label
  (`privacy4all-authbox-v1 key`) so signed and plain
  boxes derive unrelated keys and neither can be
  relabelled into the other. Opening returns the
  message and the verdict separately: a box that opens
  but was signed by a different key comes back with
  its text intact and `verified === false`. Honestly
  labelled a teaching implementation, not an audited
  messaging app: the signature proves the signing key,
  not a legal name; both public keys have to really be
  theirs; there is still no ratchet, so a recipient
  private key copied later opens every signed box; and
  a copied box line opens again — nothing inside
  proves when it was signed. Never paste a real wallet
  key or a production private key into any web page,
  including this one.
- **Is that really their key? — the safety number** —
  the check that runs before trust, closing the
  warning every tool from 17 on ends with: a signature
  or a box proves the key, and a swapped public key
  makes every later check pass against the swapper.
  Both public keys are sorted and hashed together
  under the `privacy4all-safetynumber-v1` label with
  real SHA-256, and the digest's first 60 hex
  characters become twelve five-digit groups — the
  same number on both sides, in either key order,
  built from public keys alone, so it is safe to read
  aloud. A companion checker returns `true`, `false`,
  or `null` for a malformed number, so "no match" and
  "cannot be checked" never blur. Honestly labelled a
  teaching implementation, not an audited identity
  system: the number proves the keys, not a legal
  name; it must be re-compared whenever a key
  changes; the digit format is this page's own
  teaching format, not any messenger's published
  safety-number format; and a 60-digit number is a
  truncated hash. Public keys only — never paste a
  real wallet key or any private key into any web
  page, including this one.
- **A fresh destination for every payment — one-time
  destinations** — the stealth-addressing pattern,
  built from tool 18's agreement: a reused address
  links every payment to its owner for any watcher,
  so the sender makes a fresh one-payment agreement
  pair, mixes its private half with the recipient's
  published public key, and hashes the shared secret
  under the `privacy4all-onetime-v1` label — that
  digest is the destination, a fresh 64-hex
  identifier nobody can connect to the published
  key. The one-payment public key travels with the
  payment in plain view; the recipient scans with
  their private key and lands on the same
  destination, and a checker returns `true`, `false`,
  or `null` for a malformed destination, so "not
  yours" and "cannot be checked" never blur. Two
  payments to the same person produce two unrelated
  destinations. Honestly labelled a teaching
  implementation, not an audited wallet: this models
  the recognition half of stealth addressing — real
  schemes derive a one-time public key on the curve
  with a matching spend key; the destination here is
  an identifier, not an address on any chain, and
  nothing moves funds; the sender necessarily knows
  the destination they made; scanning needs the
  one-payment key, and amounts, timing and metadata
  still leak. Never paste a real wallet key or a
  production private key into any web page,
  including this one.
- **The key that can spend it — one-time spend keys** —
  the spend half of stealth addressing that tool 29
  names as its gap, built with real P-256 curve
  arithmetic computed locally in plain BigInt code:
  the tool-18 shared secret is hashed once under the
  `privacy4all-spendkey-v1` label and read as a tweak
  under the curve order; the sender adds tweak×G to
  the recipient's published point to make the
  one-time public key, and the recipient adds the
  same tweak to their private scalar — (r + t)×G is
  the same point, so the derived one-time private
  key (a 138-byte PKCS#8 key in tool 18's format)
  matches it exactly, and a checker returns `true`,
  `false`, or `null` for malformed keys, so "not a
  pair" and "cannot be checked" never blur. Honestly
  labelled a teaching implementation, not an audited
  wallet: the key is not an address on any chain and
  nothing moves funds — real stealth schemes run on
  their own curves and encodings with different
  tweak hashes; whoever holds the recipient's
  ordinary private key plus the one-payment public
  key can derive the spend key, by design; and the
  affine curve code is written to be read and
  checked line by line, not for speed or
  side-channel resistance — production wallets use
  audited, constant-time libraries. Never paste a
  real wallet key or a production private key into
  any web page, including this one.
- **Eyes without hands — a view key that can watch
  but never spend** — the split tools 29 and 30 both
  name as their shared flaw (the scanning key is the
  spending key), built Monero-style from two tool 18
  pairs published side by side: senders mix with the
  view public key, so the view private key alone
  re-derives each payment's secret, its destination
  under the `privacy4all-viewscan-v1` label, and its
  one-time public key — watching is complete — while
  the spend tweak under the
  `privacy4all-viewspend-v1` label is added to the
  spend private scalar the view holder does not
  have, so claiming a spend key takes both private
  keys and a checker on destinations returns `true`,
  `false`, or `null` for malformed input, so "not
  theirs" and "cannot be checked" never blur.
  Honestly labelled a teaching implementation, not
  an audited wallet: nothing is an address on any
  chain and nothing moves funds; the spend key alone
  cannot even scan in this construction; and the
  view key still sees every payment the published
  pair ever receives, past and future, until the
  keys rotate — eyes without hands, not eyes that
  see nothing. Never paste a real wallet key or a
  production private key into any web page,
  including this one.
- **Prove you know the key — a zero-knowledge proof
  of knowledge** — the real proof tool 5's simulator
  points at: the Schnorr identification protocol on
  the hub's P-256 curve. The prover commits to a
  fresh secret nonce (state format
  `p4a-zkproof-v1`), the verifier draws a fresh
  challenge only after the commitment is fixed, and
  the answer `s = k + c·x mod n` is checked as
  `s×G = R + c×Y` against the published key — the
  equation balances only for whoever holds the
  private key, and the answer reveals neither it nor
  the nonce. A verifier's verdict returns `true`,
  `false`, or `null` for malformed pieces, so "not
  proved" and "cannot be checked" never blur.
  Honestly labelled a teaching implementation, not
  an audited wallet and not one of Midnight's
  Compact circuit proofs: the commitment coming
  first is the proof, not ceremony (a prover who
  sees the challenge first can work backwards and
  fake it); answering two challenges with the same
  commitment leaks the private key itself, so one
  state answers exactly one challenge; a completed
  proof is not a signature — it signs no message,
  authorises nothing, and proves knowledge of a key,
  not a legal name; and this one page plays both
  sides, so it demonstrates the maths, not a live
  exchange. Never paste a real wallet key or a
  production private key into any web page,
  including this one.
- **A proof that signs itself — a Schnorr
  signature** — tool 32's proof with the verifier
  taken out of the room: the Fiat–Shamir transform
  replaces the hand-drawn challenge with a hash —
  SHA-256 under the label `privacy4all-schnorr-v1`
  of the commitment and the message together,
  reduced under the curve order — so the signer
  computes the challenge alone and publishes the
  commitment and the answer as one signature line
  (format `p4a-schnorr-v1`), and anyone can rehash
  and check `s×G = R + e×Y` against the published
  key at any later time. A verifier's verdict
  returns `true`, `false`, or `null` for malformed
  pieces, so "not signed" and "cannot be checked"
  never blur. Honestly labelled a real Schnorr
  signature but not the signature format any chain
  or wallet checks — tool 17's ECDSA remains the
  signature a P-256 wallet would produce, and real
  Schnorr deployments such as BIP-340 use their own
  curves, encodings and hash constructions: a
  signature binds a message and can be shown around
  forever, which trades tool 32's freshness for
  transferability; and one nonce behind two
  signatures leaks the private key itself, so a
  fresh nonce is drawn for every signature. Never
  paste a real wallet key or a production private
  key into any web page, including this one.
- **One of us signed it — a ring signature** —
  tool 33's hashed challenges chained into a closed
  loop over a ring of 2–6 published public keys: the
  Abe–Ohkubo–Suzuki construction, where each link is
  `E_i = z_i×G + c_i×Y_i` and each challenge is
  SHA-256 under the label `privacy4all-ring-v1` of
  the previous link and the message. The signer
  invents the other members' answers forwards,
  walks the chain around, and answers the final
  challenge with the only private key used anywhere
  in the signature; a verifier walks the same chain
  from the seed and learns the loop closed — one of
  the listed keys signed (format `p4a-ring-v1`) —
  and never which one. The verdict returns `true`,
  `false`, or `null` for malformed pieces, so "not
  proved" and "cannot be checked" never blur.
  Honestly labelled: the ring is the whole anonymity
  set (two keys are a coin flip); nobody in the ring
  had to agree to be in it, so a ring signature is
  not a group endorsement; and this teaching version
  carries no key image, so two signatures by the
  same signer cannot be linked by the signatures
  alone — Monero, the best-known ring signature
  system, adds one deliberately. Not the signature
  format any chain or wallet checks. Never paste a
  real wallet key or a production private key into
  any web page, including this one.
- **Signed twice? It shows — a linkable ring
  signature** — the LSAG form of the ring above: the
  same Abe–Ohkubo–Suzuki chain doubled, each link a
  pair `E_i = z_i×G + c_i×Y_i` and
  `F_i = z_i×Hp(Y_i) + c_i×I`, each challenge SHA-256
  under the label `privacy4all-linkable-ring-v1` of
  both points and the message, and every signature
  carrying a key image `I = x×Hp(Y)` (format
  `p4a-lring-v1`). `Hp` hashes a public key to a
  curve point by try-and-increment under the label
  `privacy4all-linkable-hash-v1` — no known discrete
  log, so nobody can compute a member's image from
  their public key alone — yet the same key always
  yields the same image, in any ring, over any
  message, so `linkableRingSignaturesLinked` can say
  whether two lines came from one key: linked,
  without being identified. The verdict returns
  `true`, `false`, or `null` for malformed pieces.
  Honestly labelled: in this teaching version the
  image is tied to the member key itself, so the
  same signer is linkable across every ring and
  message — Monero ties its image to a one-time key
  per note, a narrower exposure. Not the signature
  format any chain or wallet checks. Never paste a
  real wallet key or a production private key into
  any web page, including this one.
- **Signed without seeing — a blind signature** —
  Chaum's construction in its Schnorr form, a
  four-move exchange over the same curve: the signer
  commits to a fresh nonce (state format
  `p4a-blindsigner-v1`); the requester shifts the
  commitment by two secret blinding factors,
  `R′ = R + α×G + β×Y`, hashes the real challenge
  out of `R′` and the message with tool 33's own
  challenge under the label `privacy4all-schnorr-v1`,
  and sends the signer only the blinded challenge
  `e = e′ + β` (request state format
  `p4a-blindreq-v1`); the signer answers with tool
  32's arithmetic, `s = k + e·x mod n`, over a
  challenge they cannot read; the requester lifts
  the answer by `α` and publishes an ordinary
  `p4a-schnorr-v1` line that tool 33's verifier
  checks — the signer signed the message, and never
  saw it, and nothing in the line points back to
  the signing session. Honestly labelled: the
  signer endorses sight unseen, so a blind-signing
  key is for tokens, vouchers and ballots, never
  statements; one nonce behind two blinded answers
  leaks the private scalar, and parallel sessions
  face the ROS attack on blind Schnorr — this
  teaching page does no session coordination. Not
  the signature format any chain or wallet checks.
  Never paste a real wallet key or a production
  private key into any web page, including this
  one.
- **It takes a quorum — a threshold signature** —
  one group key, split at setup by a dealer with
  tool 15's Shamir idea moved into the curve's own
  scalar field: the polynomial
  `f(t) = x + a₁t (+ a₂t²)` mod n deals holder i the
  single number f(i) in a share line
  (`p4a-threshshare-v1`), while the group public
  key stays the ordinary `Y = x×G`. Any quorum —
  2 or 3 of up to 5 holders — signs together: each
  commits to a fresh nonce (state format
  `p4a-threshsigner-v1`), the commitments sum to
  one aggregate, the challenge is tool 33's own
  hash of it under `privacy4all-schnorr-v1`, and
  each holder answers with their share weighted by
  their Lagrange coefficient for the participating
  set, `s_j = k_j + e·λ_j·f(j)`, so the answers sum
  to an ordinary `p4a-schnorr-v1` line — because
  `Σ λ_j·f(j)` is exactly `x`, interpolated at zero
  without ever being reconstructed — that tool
  33's verifier checks against the group key.
  Fewer than the quorum interpolate to a scalar
  that is not x, and the line verifies false.
  Honestly labelled: a trusted-dealer teaching
  construction — real threshold protocols such as
  FROST generate the key jointly, by distributed
  key generation, so the whole key never exists in
  one place, and add coordination against
  concurrent-session attacks this page does not
  attempt; one nonce behind two partial answers
  leaks the holder's share. Not the signature
  format any chain or wallet checks. Never paste
  a real wallet key or a production private key
  into any web page, including this one.
- **No dealer ever saw it — distributed key
  generation** — the fix for tool 37's named flaw,
  Pedersen's distributed key generation with
  Feldman's verifiable sharing as the check: there
  is no group key to split, so every holder deals a
  split of their own fresh random contribution
  instead. Each broadcasts one commitment line
  (`p4a-dkgcommit-v1`) carrying the Feldman
  commitments `C_jk = a_jk×G` and sends each holder
  one private share line (`p4a-dkgshare-v1`)
  carrying `f_j(i)`, computed by tool 37's own
  polynomial arithmetic. A recipient checks a dealt
  share against the broadcast commitments —
  `share × G` must equal `Σ_k i^k·C_jk` — and a
  share that fails is a dealer who dealt a
  different polynomial than the one they committed
  to. Finalizing is addition only: holder i sums
  the shares addressed to them, and the sum is a
  share of the summed polynomial, whose constant
  term — the group scalar — is never computed by
  anyone; only its public key exists, as the sum
  of the dealers' constant commitments. The
  finalized line is an ordinary
  `p4a-threshshare-v1` share, so a dealerless key
  signs in tool 37 unchanged. Honestly labelled: a
  simplified teaching round — this page plays
  every holder on one device, there is no
  complaint/dispute round (verification and
  finalizing simply refuse), and no claim to
  FROST's full security proofs. Not the key format
  any chain or wallet checks. It needs no existing
  key at all — every contribution is drawn fresh
  on the page.
- **A signature that waits for a secret — adaptor
  signatures** — a signature that is complete
  except for one missing number, built on tool
  33's Schnorr scheme. The missing number is an
  adaptor secret `t`; only its point `T = t×G` is
  published. The signer pre-signs by shifting
  their nonce commitment by the point —
  `R̂ = R + T` — and drawing tool 33's challenge
  over the shifted commitment; the answer `s′`
  (`p4a-adaptor-v1`) sits exactly one adaptor
  point short of balancing, so tool 33's verifier
  rejects the line as it stands, while anyone
  holding `T` can check it is a genuine
  pre-signature: `s′×G = (R̂ − T) + e×Y`. Adapting
  is one addition, `s = s′ + t`, and the result
  is an ordinary `p4a-schnorr-v1` signature;
  extraction is the same addition read backwards,
  `t = s − s′`, so publishing an adapted signature
  hands the secret to every holder of the
  pre-signature — the symmetry real systems build
  atomic swaps out of: two signatures on two
  chains, one secret, both complete or neither
  does. Honestly labelled: the pre-signature is
  worthless until adapted, a swapped adaptor
  point locks the signature to a stranger's
  secret, and publication is the reveal. Not the
  signature format any chain or wallet checks.
  Never paste a real wallet key or a production
  private key into any web page, including this
  one.
- **Many keys, one signature — aggregate
  signatures** — the MuSig shape, built on tool
  33's Schnorr scheme: every signer keeps their
  own ordinary key, all of them must sign, and
  the world sees one ordinary-looking key and one
  ordinary `p4a-schnorr-v1` signature. The
  aggregate key is a weighted sum,
  `Ỹ = Σ aᵢ·Yᵢ`, where each coefficient
  `aᵢ = SHA-256` under
  `privacy4all-musig-keyagg-v1` of the whole key
  list and that key — the weighting is what
  blocks the rogue-key attack, in which the last
  joiner crafts their key to cancel everyone
  else's out of a plain sum and ends up holding
  the group key alone. Each signer commits a
  fresh nonce for their position in the list
  (state `p4a-musigsigner-v1`), the challenge is
  tool 33's own over the summed commitment, each
  partial answer is tool 32's arithmetic over
  the weighted scalar `aᵢ·xᵢ`, and the partials
  sum into a signature tool 33's verifier judges
  against the aggregate key. Honestly labelled:
  everyone must sign — one missing signer is no
  signature, where tool 37's quorum would carry
  on; the list's order is part of the agreement;
  production MuSig2 (BIP-327) adds rounds this
  teaching page omits and works over secp256k1,
  not this page's P-256. Not the signature format
  any chain or wallet checks. Never paste a real
  wallet key or a production private key into
  any web page, including this one.
- **Check them all at once — batch
  verification** — many tool 33 signatures, each
  under its own key and message, checked in one
  weighted equation instead of one per line:
  `(Σ aᵢ·sᵢ)×G = Σ aᵢ×Rᵢ + Σ (aᵢ·eᵢ)×Yᵢ`. The
  weights are not plain ones: with every
  `aᵢ = 1` a forger can nudge one response up
  and another down by the same amount and the
  errors cancel in the sum, so each `aᵢ` is
  SHA-256 under `privacy4all-batch-v1` of the
  whole batch transcript and the entry's
  position — a commitment to the final pile
  that differently weights the errors so they
  no longer cancel. A failed batch cannot say
  which entry failed — that is the honest
  price of one equation — so a second form
  falls back to tool 33's per-entry check and
  names the failing positions. Entries are two
  to six, written key line, signature line,
  then the message, blank line between them;
  the same key may sign several entries.
  Honestly labelled: batching saves verifier
  work and strengthens nothing; production
  batch verifiers (BIP-340 among them) draw
  weights from verifier-side randomness and
  work over secp256k1. Not the signature format
  any chain or wallet checks. This tool takes
  public keys and published signatures only.
- **Hide the amount, keep the maths — Pedersen
  commitments** — a commitment that hides a value
  completely yet still does arithmetic: `C(v, r) =
  r×G + v×H`, where `H` is a second generator
  hashed into the curve under
  `privacy4all-pedersen-h-v1` by try-and-increment,
  so nobody knows the discrete logarithm between
  `G` and `H` — the unknown that makes the
  commitment binding. The blinding `r` is a fresh
  random scalar per commitment (zero refused, for
  the same reason tool 32 refuses a zero nonce),
  so the same value committed twice lands on two
  unrelated points. Commitments are homomorphic:
  `C(v₁, r₁) + C(v₂, r₂) = C(v₁ + v₂, (r₁ + r₂) mod n)`,
  checked by a third form that adds two commitments
  as points and verifies the sum opens to the total
  value under the total blinding — the balance
  check a shielded ledger runs without any amount
  in the clear. Values are whole numbers from 0 to
  1,000,000,000,000, so a sum of two can never wrap
  the curve order. Honestly labelled: a commitment
  hides a value but proves no range — real
  confidential systems pair commitments with range
  proofs; the opening is a secret of private-key
  rank. Not a Compact circuit proof, and not a
  format any chain or wallet checks. This tool
  needs no keys at all.
- **In range, and I can prove it — range proofs**
  — the answer to tool 42's named limit: prove the
  value inside a Pedersen commitment is a whole
  number from 0 to 255, revealing neither the value
  nor its blinding. The value is decomposed into
  eight bits, each with its own Pedersen commitment
  under the same `privacy4all-pedersen-h-v1`
  generator; the bit blindings are solved so the
  weighted sum of the bit commitments is the
  commitment itself, and each bit is proved to be
  0 or 1 with a Cramer–Damgård–Schoenmakers OR
  proof — the true branch answered like tool 32,
  the other simulated backwards — all bound by one
  Fiat–Shamir challenge hashed under
  `privacy4all-rangeproof-v1`, each bit's two branch
  challenges summing to it. The proof line is
  `p4a-rangeproof-v1`. Honestly labelled: eight
  bits is a teaching range — production proofs
  (Bulletproofs, Compact circuits) cover 64-bit
  amounts in logarithmic space; not a Compact
  circuit proof, and not a format any chain or
  wallet checks. The opening it is made from stays
  a secret of private-key rank. Tool 44 turns from
  one commitment to two: whether they hide the
  same value.
- **Same value, twice hidden — equality proofs**
  — prove two Pedersen commitments hide the same
  value, opening neither. Two commitments to one
  value under different blindings differ only in
  their blinding terms, so `C₁ − C₂ = (r₁ − r₂)×G`:
  the difference point is a plain multiple of the
  base point that any verifier computes from the
  pair alone, and the proof is tool 32's Schnorr
  proof of knowledge aimed at it — fresh nonce
  commitment, one Fiat–Shamir challenge hashed
  under `privacy4all-eqproof-v1` over the pair in
  order and the nonce commitment, response checked
  as `s×G = R + c×D`. Had the values differed, the
  difference would carry an `H` term whose
  logarithm under `G` nobody knows — that unknown
  is the soundness. The witness is the blinding
  difference alone: the value never enters the
  response, and anyone holding both blindings can
  make the proof. The proof line is
  `p4a-eqproof-v1`. Honestly labelled: identical
  commitments are refused — visibly equal already,
  and their difference is the identity this page
  does not spell; one nonce behind two responses
  hands back the blinding difference. Not a
  Compact circuit proof, and not a format any
  chain or wallet checks. The openings it is made
  from stay secrets of private-key rank. Tool 45
  returns to one commitment and asks whether its
  value sits on a public list.
- **One of these, I won't say which —
  set-membership proofs** — prove the value inside
  a Pedersen commitment is one entry on a small
  public list — two to six candidates — opening
  nothing and naming no entry. For each candidate
  `vᵢ` anyone can compute the shifted point
  `Dᵢ = C − vᵢ×H`; for the candidate that equals
  the hidden value the `H` term vanishes and
  `Dᵢ = r×G`, a statement whose logarithm the
  prover knows because the witness is their own
  blinding, and for every other candidate the
  logarithm runs through `H`, which nobody knows.
  Membership is a Cramer–Damgård–Schoenmakers OR
  proof run once per candidate — the true branch
  answered like tool 32, the rest simulated
  backwards — bound by one Fiat–Shamir challenge
  hashed under `privacy4all-setmember-v1` over the
  commitment, the canonical list and every
  branch's nonce commitment, with the branch
  challenges summing to it. The list is a set:
  duplicates are refused and the order it is typed
  in changes nothing. The proof line is
  `p4a-setmember-v1`. Honestly labelled: the set is
  public and membership is all it proves — a set
  of two is a coin flip about which entry; the
  witness is the blinding alone. Not a Compact
  circuit proof, and not a format any chain or
  wallet checks. The opening it is made from
  stays a secret of private-key rank. Tool 46
  changes the question from proving to asking.
- **Pick one, learn one — oblivious
  transfer** — a receiver takes exactly one of a
  sender's two messages while the sender learns
  nothing about which message was taken, and the
  receiver learns nothing about the one left
  behind: the Bellare–Micali construction, the
  primitive under private database lookups and
  private set intersection. One fixed public
  point whose logarithm nobody knows — tool 42's
  hashed generator — is the stage. The receiver
  picks a fresh scalar `r` and builds two keys
  that sum to that point: the chosen slot's key
  is `r×G`, the other is the point minus `r×G`,
  whose logarithm would need the public point's
  own. The request line is `p4a-otreq-v1`, the
  receiver's kept secret a `p4a-otstate-v1` line.
  The sender checks the two keys sum to the
  public point before sealing anything — the sum
  is what ties the receiver to knowing at most
  one key's logarithm, and a pair built from two
  chosen scalars fails it — then seals each
  message under a fresh ephemeral key, the pad
  hashed out of `kᵢ×keyᵢ` under
  `privacy4all-ot-v1`, answering with a
  `p4a-otresp-v1` line that favours neither slot.
  The receiver rebuilds one shared point,
  `r×E_b = k_b×key_b`, and opens exactly one
  message; the other is not locked but
  unreachable. Honestly labelled: the semi-honest
  teaching core — the sum check is what stands
  between it and a cheating receiver, metadata
  about the transfer itself is out of scope, and
  the state line is a secret of private-key rank.
  Not a Compact circuit proof, and not a format
  any chain or wallet checks. Tool 47 builds the
  private set intersection this primitive is
  famous for.
- **Common ground, nothing else — private set
  intersection** — two lists meet and only the
  entries they already share are named: the
  classic Diffie–Hellman private set
  intersection, the contact-discovery shape tool
  46 pointed at. Each entry is hashed into the
  curve under `privacy4all-psi-item-v1` by
  try-and-increment, so an entry becomes a point
  whose logarithm nobody knows and both sides
  land on the same point for the same entry. The
  initiator blinds every entry point with one
  fresh secret scalar `a` and sends a
  `p4a-psib-v1` line; the responder blinds their
  own entries with their own scalar `b`, blinds
  the initiator's points a second time, and
  answers with a `p4a-psid-v1` line in the
  request's own order plus their blinded list,
  shuffled. The initiator finishes on
  commutativity, `a×(b×H(entry)) = b×(a×H(entry))`:
  an entry is shared exactly when its
  double-blinded point stands among the
  responder's points raised by `a`. The
  initiator's kept secret is a `p4a-psistate-v1`
  line. Honestly labelled: the initiator learns
  the overlap and the other list's size and
  nothing else — unmatched points cannot be
  unblinded or dictionary-tested without `b` —
  and the responder learns the initiator's list
  size and nothing else at all. Semi-honest
  core: the double-blinded order is taken on
  trust, set sizes and the exchange itself leak,
  and entries are normalised (trimmed,
  lower-cased, whitespace collapsed) before any
  maths. Not a Compact circuit proof, and not a
  format any chain or wallet checks. Tool 48
  runs this same exchange for a count only.
- **Just the number, not the names — private set
  intersection, cardinality only** — tool 47's
  exchange, deliberately learning less: sometimes
  only "how many entries are on both lists?" is
  the question — a room size, a quorum check —
  and every name beyond that number is disclosure
  nobody asked for. The initiator starts exactly
  as in tool 47 (a `p4a-psib-v1` request, a kept
  `p4a-psistate-v1` line); the responder here
  shuffles BOTH halves of the reply — their own
  blinded points and the double-blinded
  `p4a-psid-v1` points too — so the reply carries
  no position information at all, and the finish
  never receives the initiator's list: it raises
  the responder's points by `a`, counts how many
  double-blinded points stand among them, and
  returns a number and only a number. A count is
  order-free by construction, so the reordering
  tool 47 takes on trust cannot change it.
  Honestly labelled: a count can itself leak —
  a count equal to your whole list, or a count
  of one on a list of one, is a name worn as a
  number — set sizes and the exchange itself
  still leak, the core is still semi-honest, and
  the privacy lives in this answer form's
  shuffle, not in the counting: a tool-47 reply
  counted here still carried its positions. Not
  a Compact circuit proof, and not a format any
  chain or wallet checks. Tool 49 starts from
  tool 47's exchange again and adds the
  responder's notes for shared entries instead.
- **Common ground, with the note attached —
  private set intersection with payloads** —
  tool 47's exchange, delivering more on
  purpose: the responder holds a short note for
  each of their entries — a room number, a
  handle, "ask for the blue folder" — and the
  initiator receives the notes for the shared
  entries and no others. The key is a point the
  earlier tools never needed, `b×H(entry)`: the
  responder computes it for every one of their
  entries directly, and the initiator obtains
  it for exactly the entries they sent by
  unblinding the reply's double-blinded points
  with `a`'s inverse under the curve order —
  for an entry they did not send, no unblindable
  form of that point ever reaches them. Each
  note is sealed under its entry's point:
  labelled SHA-256 pad blocks under
  `privacy4all-psi-payload-v1`, a truncated
  SHA-256 tag under
  `privacy4all-psi-payload-mac-v1`, the sealed
  notes shuffled on a `p4a-psip-v1` line. The
  reply pointedly carries NO blinded list: in
  tool 47 those points are harmless cargo, here
  they are the note keys, and a reply carrying
  them would open every note, shared or not.
  Honestly labelled: the initiator learns the
  shared entries with their notes, the
  responder's list size and roughly each note's
  length; the responder learns the initiator's
  list size and nothing else; the tag proves a
  note was sealed under its entry's true point,
  never that the note is true; the core is
  still semi-honest. Not a Compact circuit
  proof, and not a format any chain or wallet
  checks. Tool 50 leaves sets behind entirely
  and hides a single lookup instead.
- **Fetch one, tell neither — private
  information retrieval** — a different thing
  hidden: not data, not a set, but a lookup. A
  small catalogue sits on two servers and the
  reader wants exactly one row; asking in plain
  words gives the row away to whoever is asked.
  The reader draws a fresh random bit per row
  (a `p4a-pirq-v1` query: the XOR of the rows
  where the mask has a 1) and sends the second
  server the same query with exactly the wanted
  row's bit flipped, keeping a
  `p4a-pirstate-v1` line. Each server XORs the
  selected rows — every row padded into one
  common block with a two-byte length header
  inside the XOR, so no row's true length
  shows — and returns one `p4a-pirans-v1`
  block. XORing the answers cancels every row
  folded in twice and leaves the wanted row
  alone; its header is read and its padding
  must be exactly zero or the finish fails
  closed. Per server the privacy is
  information-theoretic: one query is a
  coin-flip pattern that fits any wanted row.
  Honestly labelled: the two servers must not
  compare queries — the XOR of their masks is
  a single 1 standing on the wanted row, so
  colluding servers (or one operator running
  both) learn it instantly; answers are not
  authenticated, so a carefully wrong answer
  could decode as a plausible row; the
  catalogue itself is public by design, and
  its size and longest row leak. Not a Compact
  circuit proof, and not a format any chain
  or wallet checks.

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
