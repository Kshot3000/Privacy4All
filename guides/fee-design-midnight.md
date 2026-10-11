# Charging honestly on Midnight — designing a disclosed service fee

How I design the one part of a Midnight app that can actually pay for its
own upkeep: a small service fee, designed in from the start, labelled
plainly before anyone commits, and routed to a published address. This is
a design guide, not a contract and not financial advice. Midnight is a
young network — build on a testnet first, and get a real review before
any version of this touches mainnet or real funds.

Everything on Privacy4All itself stays free: no tool on the hub charges a
fee, and this guide charges nothing. It exists because the apps built
*from* this hub — a swap interface, an escrow flow, a marketplace, a
payment tool — need a sustainable way to earn, and "earn" done badly is
how users get burned. Done well it is one line in the quote, visible
before anyone signs anything.

## 1. The rule: quoted before committed, exact, and in the open

A service fee is honest only when all four of these are true at once:

- **Quoted before committed.** The user sees the fee — the rate, the
  exact amount, and who receives it — *before* the step that makes the
  transaction final, not in a receipt afterwards.
- **Exact, not approximate.** Quote the fee in the asset's smallest unit,
  computed with the same arithmetic the settlement will use. "About
  0.25%" is marketing; "fee: 2,500 units of 1,000,000" is a quote.
- **Named recipient.** The fee goes to one published address, stated in
  the interface next to the amount — never to "the platform", and never
  to an address the user can only discover by inspecting the transaction.
- **One fee, once.** The quoted fee is the whole platform charge. No
  second spread, withdrawal charge or "network surcharge" appears later
  wearing a different name.

If any one of the four cannot be true in your design, the design is not
ready — that is the test, and it fails closed.

## 2. The arithmetic: basis points, integers, floor rounding

Quote the rate in **basis points** (bps): 1 bp is 0.01%, so 25 bps is
0.25% and 100 bps is 1%. Do the maths in integers, in the asset's
smallest unit, exactly like the hub's own DUST estimator does:

```text
fee = floor(amount × bps ÷ 10,000)
net = amount − fee
```

Worked examples at 25 bps — check them by hand, they are the test cases:

| Amount (smallest units) | Fee | Net to recipient |
| ---: | ---: | ---: |
| 1,000,000 | 2,500 | 997,500 |
| 50,000 | 125 | 49,875 |
| 10,000 | 25 | 9,975 |
| 399 | 0 | 399 |

Three properties of this shape matter, and a fee design should state all
three out loud:

- **The invariant `fee + net = amount` always holds.** No unit is created
  or lost to rounding; the remainder always lands somewhere named. Test
  it as a property, on random amounts, not on examples alone.
- **Floor rounding favours the user, and small amounts pay zero.** At
  25 bps, anything under 400 units rounds to a fee of 0. Either disclose
  that ("amounts under 400 units pay no fee") or set a minimum fee —
  knowing a flat minimum is a far larger percentage on a small payment,
  and must be quoted as plainly as the rate. Never let rounding silently
  favour the house, and never "fix" the zero with rounding up in the
  app's favour.
- **The fee can never exceed the amount.** With bps at or under 10,000
  the fee is at most the whole amount; a sane app caps its rate far
  below that, states the cap, and refuses a rate above it in code, not
  just in prose.

## 3. DUST is not your fee

Midnight has two different things that both get called "fees", and
conflating them is the most common dishonesty in this space — usually by
accident:

- **DUST pays the network.** Holding NIGHT generates DUST, and DUST is
  the renewable resource shielded transactions spend. It is a network
  cost of transacting at all, it does not go to the app builder, and an
  interface must never present it as one.
- **A service fee pays the app.** It is denominated in the asset that is
  actually moving (the payment, the swap leg, the escrow release),
  computed by the rule in §2, and routed to the builder's published
  address.

Quote them as two separate lines, always. A quote that folds the network
cost into the service fee — or pads the service fee and blames the
network — fails the §1 test.

## 4. Where the fee sits in the flow

The pattern is the same across the app shapes this hub builds toward:

- **Payment tool:** one movement, split at settlement — `net` to the
  recipient, `fee` to the published fee address, both legs in the quote
  the sender approved.
- **Swap / DEX interface:** the fee is taken from one named leg (state
  which one), quoted against the amounts that leg will actually settle
  at — never against a mid-price the user was never going to get.
- **Escrow / marketplace:** the fee is charged on *release*, not on
  deposit — money that comes back on a dispute or a timeout was never
  sold, and charging for its return is a fee the user never agreed to.
  State the moment of charge in the quote.

On Midnight specifically, remember the Compact starter guide's lesson:
anything written to the public ledger is public, forever. A fee amount
and a fee recipient placed in public state are auditable by anyone —
that visibility is a feature for a fee. The parts of the transaction
that stay private (the user's wider balances, history and identity)
stay private exactly as they would without a fee; taking a disclosed
cut does not require, and must never become an excuse for, wider
disclosure.

## 5. The pre-launch checklist

- Rate in bps, amount and recipient shown before the committing step.
- Integer maths in the smallest unit; `fee + net = amount` property-tested.
- Rounding direction and the zero-fee threshold stated in the interface.
- DUST network cost quoted as its own line, never merged or blamed.
- Fee address published on the app's own page, matching the address the
  settlement actually pays — check them against each other after every
  change.
- Testnet first, with the fee flowing to a testnet address, end to end.
- The paid step is a decision, not a surprise: deploying a fee-charging
  contract to mainnet costs real money and moves real funds, so it is
  never an automated step.

My own fee address for Midnight work, when an app of mine reaches that
step, is my published Cardano (ADA) address below — NIGHT is held on
Cardano, so that is where a Midnight builder's address lives today. Any
app that routes a fee anywhere else while carrying my name is not mine.

## Where next

- [Your first Compact contract](compact-starter.md) — the ledger /
  witness / circuit split a fee leg is built inside.
- [Getting started building on Midnight](getting-started-midnight.md) —
  docs, Lace and testnets in the order I'd learn them.
- Official docs: https://docs.midnight.network/

---

By Kyle Cox (@kshot9000) · Privacy4All: https://github.com/Kshot3000/Privacy4All
Tagging the Midnight team: @midnightntwrk (GitHub) · @MidnightNtwrk (X)
ADA donations: addr1q8hnl6vl5a6k3rw3n5g3jtte696zcl76kfatzv7gpswa9r0dj7fma6klq55y4ffm7tf0em09udnyhuk4ah92pl5x9jpqjae44v
