# Your first Compact contract — a starter walkthrough

The walkthrough I wish I'd had open next to the official docs: install the
toolchain, read a real contract line by line, compile it, and know what has
to happen before your first deploy. It complements the official Midnight
documentation — it doesn't replace it. Midnight is a young network: build on
a local network or a testnet, pin your toolchain version, and check the
docs' support matrix before trusting any version number quoted anywhere,
including here.

## 1. Install the toolchain

You need Node.js v22 or later, plus Docker later for the local proof server.

```sh
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/midnightntwrk/compact/releases/latest/download/compact-installer.sh | sh
compact update
compact --version
```

- The installer gives you the `compact` CLI, which manages the compiler
  toolchain. `compact update` installs the latest compiler (or
  `compact update 0.29.0`-style, a specific version); `compact self update`
  updates the CLI itself.
- There's a Compact extension for VS Code in the `compact` repo — syntax
  highlighting and errors in the editor beat finding them at compile time.

## 2. The mental model: three kinds of code

Every Compact contract is built from three declarations, and the privacy of
your app lives in how you split things between them:

- **`export ledger …`** — public on-chain state. Anyone can read it, forever.
  If a raw secret lands here, it's published, not stored.
- **`witness …`** — a function the contract *declares* and your TypeScript
  code *implements* off-chain. It supplies private data (a secret key, a
  score, an amount) at proving time. Witness values stay with the user;
  they are inputs to the proof, not entries in the ledger.
- **`export circuit …`** — a circuit is a contract entry point: the logic a
  transaction runs. Circuit parameters are **private by default**. A private
  value can only reach the public ledger through **`disclose(...)`** — that
  call is your deliberate "yes, publish this" — and the compiler rejects
  code that tries to write a private value to the ledger without it.

## 3. The smallest real contract

This is the Hello World contract from the official tutorial, in full:

```compact
pragma language_version 0.23;

export ledger message: Opaque<"string">;

export circuit storeMessage(newMessage: Opaque<"string">): [] {
  message = disclose(newMessage);
}
```

- `pragma language_version 0.23;` pins the Compact language version the
  contract is written against (0.23 is what the current tutorial uses —
  re-check it, versions move).
- `export ledger message` is one public string slot on-chain.
- `storeMessage` takes a private string and stores it — the `disclose()` is
  the whole privacy lesson in one line: the caller chose to publish this
  value, and the code has to say so out loud. Delete `disclose(...)` and
  the compiler stops you: private data doesn't leak into public state by
  accident or by default.

## 4. Compile it

```sh
compact compile hello-world.compact managed/
```

Compilation produces two things: TypeScript bindings your app calls, and
the zero-knowledge circuit artifacts (proving/verifying material) for each
circuit. While you're iterating on logic, skip the ZK key generation — it
is the slow part:

```sh
compact compile --skip-zk hello-world.compact managed/
```

Recompile *without* `--skip-zk` before you deploy anything: a contract
compiled with it proves nothing.

## 5. One step up: state from the standard library

With `import CompactStandardLibrary;` you get ledger types with their own
circuits. The canonical counter:

```compact
import CompactStandardLibrary;

export ledger round: Counter;

export circuit increment(): [] {
  round.increment(1);
}
```

`Counter` gives you `increment`, `decrement` and `read` instead of
hand-rolled arithmetic on a public integer. From here, the official
**Bulletin board** tutorial is the right next read: it adds an enum for
board state, a `Maybe<…>` message slot, an owner field — and a witness
secret key checked against a hash, so posting rights are *proved*, not
shown. That pattern — store the commitment on-chain, keep the secret in a
witness — is the one most real Midnight apps are built from.

## 6. Before your first deploy

- **Proof server**: proofs are generated on your machine, not on-chain.
  Run the official proof server locally in Docker, or use a wallet's
  delegated proving — either way, no proof server, no transactions.
- **Testnet tokens**: get tNIGHT from the faucet for your test network,
  then **register it for DUST generation**. Holding tNIGHT alone generates
  nothing until it's registered, and DUST is what pays for transactions —
  this is the most common first-deploy blocker.
- **Testnet means testnet**: tNIGHT has no value. Never pay for testnet
  tokens, and never point test software at real funds.

## 7. Mistakes I see (and made)

- Writing to the ledger without `disclose(...)` and reading the compiler
  error as a bug. It's the seatbelt working.
- Assuming anything stored via a contract is "in the contract, so
  private". Ledger state is public; privacy comes from witnesses,
  commitments and hashes — see step 2.
- Deploying a `--skip-zk` build and wondering why nothing verifies.
- Treating any single tutorial's versions as current. The language,
  compiler, runtime and ledger versions move together; the docs' support
  matrix is the source of truth.

## Where next

- Official docs and tutorials: https://docs.midnight.network/
- The Compact language repo (installer, examples, language reference):
  https://github.com/midnightntwrk/compact
- The order I'd learn in: [Getting started building on Midnight](getting-started-midnight.md)
- Working Compact patterns, honestly labelled: the project catalogue in the
  [Privacy4All README](https://github.com/Kshot3000/Privacy4All/blob/main/README.md)

---

By Kyle Cox (@kshot9000) · Privacy4All: https://github.com/Kshot3000/Privacy4All
Tagging the Midnight team: @midnightntwrk (GitHub) · @MidnightNtwrk (X)
ADA donations: addr1q8hnl6vl5a6k3rw3n5g3jtte696zcl76kfatzv7gpswa9r0dj7fma6klq55y4ffm7tf0em09udnyhuk4ah92pl5x9jpqjae44v
