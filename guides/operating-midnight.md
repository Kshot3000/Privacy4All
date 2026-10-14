# Operating a Midnight dApp after launch — a maintainer's checklist

My earlier guides end where most guides end: at the launch. This one is
about the stage after — keeping a shipped Midnight dApp private, and
working, while everything underneath it keeps moving: compiler
releases, runtime releases, wallet releases, your own releases. It is
a maintainer's checklist built on two official docs pages — the
proof server guide and the version-mismatch troubleshooting guide,
both linked below — plus my own operating practice where I say so.
It is a checklist, not a runbook and not a guarantee. I'm an
independent builder, not affiliated with the Midnight Foundation or
IOG, and this guide complements the official docs rather than
replacing them.

The operating fact that drives everything below: a Midnight dApp is
not one program at one version. It is a set of components that only
work in matched combinations, and the private half of the system —
witness values, private state, the proving path — lives on your
users' machines, where your release process can protect it or strand
it, but never patch it by force.

## 1. Keep a version inventory — the stack is one matched set

The components that must agree: the Compact toolchain, the runtime
libraries, the JavaScript libraries (Midnight.js, the wallet SDK,
the dApp connector), the proof server, and the indexer if you use
one. Midnight publishes a compatibility matrix saying which versions
work together; when a user reports breakage, a mismatch between two
of these is the first suspect, ahead of your own code.

My practice, following the official troubleshooting guide:

- Write the versions down in the project — a `VERSIONS.md` at the
  repo root, with the date they were last verified against the
  matrix. Memory is not an inventory, and neither is a lockfile
  nobody reads.
- Pin exact versions everywhere: exact versions in `package.json`,
  with no `^` or `~` ranges, and install with `npm ci` so the build
  is the lockfile, not whatever resolved today.
- Pin the proof server's Docker image to the tag the matrix lists.
  The official guide warns against relying on `latest` for it: that
  tag is republished less often than the versioned tags and can lag
  the matrix, so "up to date" and "compatible" quietly diverge.
- Record the deployed contract's compiler version too. Which
  compiler built the contract on-chain is an operating fact you
  will need the first time an upgrade question arrives.

## 2. Upgrade like a migration, not an update

- Update all related components together, against the matrix. The
  official guide's list of common mistakes is, in my experience,
  just a description of normal upgrades done casually: one component
  bumped alone, the matrix never consulted, contracts never
  recompiled afterwards.
- Back up before you upgrade: the project files, `package.json`, and
  the compiled contract artifacts — committed to git, so the working
  pre-upgrade state is one checkout away, not a memory.
- After a compiler change, clean the old artifacts and recompile.
  A new compiler can mean fresh proving and verifying keys for your
  circuits; Midnight's own switch to BLS proving worked exactly
  that way — recompilation was required and redeploying with the
  existing keys was not enough. Treat "it still compiles" as the
  start of verification, not the end.
- Verify after updates, in this order: the contract compiles, the
  test suite passes, the proof server starts clean and its logs are
  read, and the whole path is exercised on a test network before
  users meet it. An upgrade that reaches users untested is a
  migration performed on other people's data.

## 3. Guard the proving path — it is where private data flows

Everything before this section is hygiene. This one is privacy.

What a dApp sends to a proof server includes private data — details
of token ownership, the dApp's private state — because proving is
where witness values are consumed. So the question "which proof
server does this dApp use?" is a privacy question, and the official
guidance is direct about the answer: a local proof server, or a
remote one on a machine you control, reached over an encrypted
channel. A proof server run by someone else sees your witness
values; there is no encryption trick in the protocol that changes
that, because the server needs the values to prove with them.

Operating rules I hold my own work to:

- Default users to a local proof server. If you offer hosted
  proving, say plainly, in the UI and not a footnote, whose machine
  sees the witness values — that disclosure is as much a part of
  the product as the fee disclosure in my fee guide.
- The server listens on port 6300 by default; if you change the
  port, every wallet and dApp configuration pointing at it changes
  too, or your "upgrade" is an outage.
- Its one outbound request happens at startup, fetching the public
  proving parameters. That data is public and identical for every
  user — your witness data is never part of it. On an air-gapped
  machine, start with `--no-fetch-params` or point
  `MIDNIGHT_PARAM_SOURCE` at your own mirror.
- The proof server must be running for transactions to process at
  all. For a shielded dApp, "the proof server is down" is not a
  degraded mode; it is the outage, and your status checks should
  treat it that way.

## 4. Do not strand your users' private state

On Midnight, private state is stored locally, on the user's device;
the chain holds the public state. That split is the privacy model —
and it means a careless frontend release can destroy data no backup
of yours can restore, because you never had it.

- Version the local private-state format, and migrate it forward on
  upgrade; never silently discard state an old build wrote.
- Test the upgrade path the way users will meet it: install the old
  build, create real state with it, then upgrade and prove the
  state still reads. Testing only fresh installs tests the users
  you do not have yet.
- Announce breaking changes before they ship, and keep the previous
  build reachable, so a user who missed the announcement has a way
  back to their state.
- Support rule, without exceptions: never ask a user to send you
  their private state, seed phrase or keys to help you debug. There
  is no debugging step that needs them, and asking trains users to
  hand the crown jewels to whoever asks next.

## 5. Watch the public side the way an observer would

Ledger state is public and permanent, and your contract publishes a
little more of it with every transaction. A disclosure that was safe
at a hundred users can identify someone once a hundred thousand
transactions of history surround it — combinations accumulate,
repetition accumulates, and crowds thin out. My review guide's last
pass (read all disclosures together) is not a launch-day exercise;
it is a recurring one, and the anonymity tools on this hub (94–101)
price exactly the effects that grow with use.

And know the limit of monitoring before you need it: watching
cannot unpublish. If you find a leak in production, the honest
sequence is: fix it in a new deployment so the bleeding stops, tell
users plainly what became public and from when, and do not quietly
patch and hope nobody archived the old state — public ledgers are
archived by design, by people who are not you.

## 6. Triage support in the order things actually break

When a user says "it stopped working", my order is:

1. Versions first — ask for the version set (compiler, runtime,
   proof server, wallet) before asking what they clicked. After any
   component release, most breakage is a mismatch, and this question
   settles it in one message.
2. The proof server — running? reachable at the configured port?
   Its logs read, not guessed at?
3. DUST — does the wallet hold NIGHT registered for DUST
   generation, and enough DUST capacity for the transaction? A user
   with no DUST has a wallet problem that looks exactly like a dApp
   problem.
4. The network — indexer and node status, on the network the user
   is actually connected to, which is worth confirming out loud;
   testnet and preview are not the same place.

## The operating checklist, on one page

1. Read the version inventory — every component, the proof server
   image tag included, checked against the compatibility matrix.
2. Confirm the pins — exact versions, `npm ci` installs, no ranges
   crept back in.
3. Before any upgrade: back up files, manifest and artifacts, in
   git; after it: recompile clean, run the tests, read the proof
   server logs, exercise the whole path on a test network.
4. Check the proving path — local by default, any hosted proving
   disclosed in the UI, port and parameters source as configured.
5. Run the upgrade-path test — old build's private state, read by
   the new build, before users get it.
6. Re-read the contract's public state as one publication —
   combinations, repetition, crowd size — on a schedule, not only
   at launch.

An operating pass that changes nothing still writes down that it
ran, what it covered, and what it did not. The next incident will
ask what state the system was in before it started, and this list —
kept honestly — is most of the answer.

## Related

- [Reviewing a Compact contract for privacy leaks](privacy-review-compact.md) —
  the pre-launch review this guide keeps running after launch.
- [Your first Compact contract](compact-starter.md) — the ledger /
  witness / circuit split, and the tNIGHT-for-DUST registration
  step section 6 leans on.
- Official proof server guide: https://docs.midnight.network/guides/run-proof-server
- Official version-mismatch guide: https://docs.midnight.network/how-to/fix-version-mismatches
- Official docs: https://docs.midnight.network/

---

By Kyle Cox (@kshot9000) · Privacy4All: https://github.com/Kshot3000/Privacy4All
Tagging the Midnight team: @midnightntwrk (GitHub) · @MidnightNtwrk (X)
ADA donations: addr1q8hnl6vl5a6k3rw3n5g3jtte696zcl76kfatzv7gpswa9r0dj7fma6klq55y4ffm7tf0em09udnyhuk4ah92pl5x9jpqjae44v
