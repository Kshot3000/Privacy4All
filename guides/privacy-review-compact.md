# Reviewing a Compact contract for privacy leaks — a reviewer's checklist

How I read someone else's Compact contract — or my own, a week later —
when the question is not "does it work?" but "does it keep private what
it promises to keep private?" This is a review checklist built on
Midnight's official smart-contract security guidance, not an audit and
not a guarantee: a contract can pass every line here and still leak
through its TypeScript frontend, its deployment setup, or a design that
was never private to begin with. I'm an independent builder,
not affiliated with the Midnight Foundation or IOG, and this guide
complements the official docs rather than replacing them — the source I
work from is the security page at
https://docs.midnight.network/compact/smart-contract-security and it is
worth reading whole before reviewing anything that matters.

Compact's starting point is the friendly one: witness values and
circuit inputs are private by default, and the compiler tracks where
witness-derived data flows. A leak therefore rarely looks like an
accident the compiler waved through. It looks like a deliberate-looking
line a tired developer wrote at 1 a.m. The reviewer's job is to read
every deliberate-looking line as if it were the leak.

## 1. Start at every `disclose()` — each one is a publication decision

Nothing witness-derived reaches public ledger state, or comes back out
of an exported circuit, unless the code wraps it in `disclose()` and
the compiler accepts it. That makes the disclose calls the complete
list of places a contract can publish private-derived data — grep for
them and the review has a table of contents. For each one, ask:

- Is this exact value safe for everyone to know, forever? Ledger state
  is public and permanent; there is no unpublish.
- Is what it reveals acceptable on its own — and in combination with
  every other disclosure in the contract (section 8)?
- Is the `disclose()` placed at the point of use, as late as possible?
  `disclose()` is an annotation, not a transformation: it does not
  encrypt, hash or weaken the value, it only tells the compiler the
  developer accepts publication. Wrapping a value early — disclosing a
  secret first and deriving from the disclosed copy — marks everything
  downstream as publishable and quietly widens every later code path.

A disclose I cannot justify in one sentence, in the review notes, is a
finding. "The compiler made me add it" is not a justification; it is
the compiler asking the question this section exists to answer.

## 2. A hash is not a hiding place

Hashing a witness value before storing it feels private and often is
not. The official guidance is blunt about the primitives: the plain
hash functions (`persistentHash`, `transientHash`) carry no disclosure
protection — they are fingerprints, not envelopes. A stored hash of a
low-entropy value — a yes/no, a small number, a short code, a value
from a short list — can be brute-forced from its hash by anyone who
guesses the candidates and hashes them, which is everyone, forever,
from the public ledger. My hub's tool 11 makes the same point with
numbers: guessability is a property of the value, not of the hash.

The review questions:

- For every stored hash of a witness-derived value: how many candidate
  values could an attacker enumerate? If the answer is "all of them,
  this afternoon", the hash is a disclosure.
- Where a value must stay hidden on the ledger, is a commitment used
  instead — `persistentCommit` for anything stored long-term — with
  real randomness doing the hiding?
- Are the transient primitives kept to temporary, in-circuit checks?
  They are not guaranteed to stay consistent across protocol upgrades,
  so anything stored, or used for authentication, should be built on
  the persistent ones.

## 3. Commitment randomness is single-use

A commitment hides because its randomness is unknown. The official
guidance pairs that with the rule reviewers most often find broken:
never reuse commitment randomness across commitments. Reused
randomness links the commitments it touches — two values committed
under the same randomness can be compared and correlated — and if that
randomness ever leaks, everything committed under it is exposed at
once instead of one value. In review: trace where each commitment's
randomness comes from, confirm it is freshly generated per commitment
(never a constant, never derived from the value itself, never shared
across users), and confirm the randomness is treated as a secret —
stored with the private state, never logged, never put on the ledger.

## 4. Witnesses are claims, not proof

Witness functions run locally, on the caller's machine, outside the
zero-knowledge circuit — which means their return values are not
verified by the proof. A witness is the user *claiming* a value; the
circuit's asserts and recomputations are what turn a claim into
something the contract may act on. Review every witness call for the
check that backs it: a balance witness should be tied to state the
circuit verifies, an identity witness to a key derivation the circuit
recomputes, an amount witness to the bounds the circuit asserts.

The sharpest special case has its own warning in the official docs:
`ownPublicKey()` is itself a witness function, so its result is a
claim too. Never accept it on its own as caller verification — a
circuit that treats it as proof of who is calling has an
authentication check that any caller can satisfy. The caller must be
verified by another mechanism first; only then is the value it
returns meaningful.

## 5. Separate your domains

The same secret, hashed for two different purposes, should produce two
unrelated-looking values — otherwise a value made for one purpose can
be replayed as the other. Compact contracts do this with domain
separation: a distinct padded tag per purpose inside each hash, one
for nullifiers, another for commitments, another for derived keys.
In review, list every hash construction in the contract and check
that no two purposes share a tag, that the tags are specific to this
contract (not copied from a tutorial, where the same tag in another
deployed contract invites cross-contract confusion), and that adding
a new purpose later means adding a new tag, never reusing an old one.

## 6. Anything usable once needs a nullifier

A private coin, ticket, vote or claim that can be spent or redeemed
needs a defence against being spent twice that does not reveal which
item was spent. That defence is a nullifier: a domain-separated,
one-way derivation from the item's secret, disclosed on its own and
recorded in a ledger set the circuit checks before inserting. Review
for the full pattern, not half of it: the nullifier is derived inside
the circuit (not supplied by the caller, who would simply supply a
fresh one), membership in the spent set is asserted before the spend
proceeds, and the insert happens in the same transaction as the
spend. My hub's tool 14 walks the pattern end to end.

## 7. Seal what must never change

Ledger fields marked `sealed` can only be set during contract
initialisation; no exported circuit can modify them afterwards.
Configuration — an owner key, a fee recipient, a supply cap, the
parameters the contract's promises rest on — belongs in sealed fields
wherever it is meant to be constant. The review is a diff: for each
unsealed field, name every exported circuit that can write it and who
can call that circuit. A field that is configuration in the design
but unsealed in the code is a promise the deployed contract does not
actually keep.

## 8. Access control is the developer's job — check every door

Compact gives the developer `assert` and expects the developer to use
it: input validation and authorisation are the contract author's
responsibility, and a circuit's access control is only as good as the
developer makes it. So for every exported circuit, the review asks
the same three questions: who may call this, what in the circuit
stops anyone else, and which inputs are asserted in range before they
touch state? An exported circuit with no authorisation assert is a
public function in the strongest sense — anyone can call it, with any
inputs the types allow, as often as they like.

## 9. Review the disclosures together, not one by one

Each disclosure can pass section 1 alone and fail together. Public
values correlate: a disclosed total plus a disclosed count is an
average; disclosures repeated over time are a time series; a value
that is safe in a crowd of thousands identifies someone in a crowd of
three. The last pass of the review reads the contract's complete set
of ledger fields and disclosed returns as one publication and asks
what an observer who watches all of it, indefinitely, can work out.
My hub's anonymity tools (94–101) exist to put numbers on exactly
that question — crowd size, repetition, correlation — and they are a
fair second opinion on any contract whose privacy claim rests on
hiding in a crowd.

## The pass, in order

1. Grep `disclose(` — justify each call in one sentence, placed at
   the point of use, safe alone and combined.
2. Grep the hash calls — no stored hash of an enumerable value;
   commitments with fresh randomness where hiding is the point.
3. Trace every commitment's randomness — fresh, per commitment,
   secret, never reused.
4. List the witnesses — each value backed by an in-circuit check;
   `ownPublicKey()` never standing alone as caller verification.
5. List the hash tags — one domain separator per purpose, specific
   to this contract.
6. Find the spendable things — each guarded by a checked-and-inserted
   nullifier, derived in-circuit.
7. Diff sealed against unsealed — configuration sealed; every
   unsealed writer named, with its caller check.
8. Walk every exported circuit — who may call it, what stops anyone
   else, what is asserted before state changes.
9. Read all public state as one publication — correlations,
   repetition and crowd size included.

A review that finds nothing still writes down that it ran, what it
covered, and what it did not — the frontend, the deployment, the
design itself. An untested suspicion is a note for the next review,
never a public claim; a confirmed leak is disclosed to the contract's
own maintainers first, through the channel their repository names.

## Related

- [Your first Compact contract](compact-starter.md) — the ledger /
  witness / circuit split this checklist reviews.
- [Getting started building on Midnight](getting-started-midnight.md) —
  docs, Lace and testnets in the order I'd learn them.
- Official security guidance: https://docs.midnight.network/compact/smart-contract-security
- Official docs: https://docs.midnight.network/

---

By Kyle Cox (@kshot9000) · Privacy4All: https://github.com/Kshot3000/Privacy4All
Tagging the Midnight team: @midnightntwrk (GitHub) · @MidnightNtwrk (X)
ADA donations: addr1q8hnl6vl5a6k3rw3n5g3jtte696zcl76kfatzv7gpswa9r0dj7fma6klq55y4ffm7tf0em09udnyhuk4ah92pl5x9jpqjae44v
