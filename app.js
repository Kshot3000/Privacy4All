"use strict";
/* Privacy4All hub logic: project filtering, a local text redactor,
   a selective-disclosure planner, a NIGHT -> DUST capacity estimator,
   a "what does this dApp see?" permission explainer, a ZK claim
   simulator, a Compact snippet library, a DUST lifecycle explainer,
   a SHA-256 hash commitment maker/checker, a public-vs-shielded
   ledger observer explainer, a viewing-key scope simulator, a
   commitment secret-strength checker with a random salt generator,
   and a password-sealed (AES-GCM) message tool.
   Everything runs locally. Pure functions are exported for tests. */

/* ---------- 1. Redactor ---------- */
/* Order matters: addresses first (longest, most specific), then email, then phone. */
var REDACTORS = [
  {
    kind: "Cardano address",
    pattern: /\b(?:addr1|stake1)[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{20,}\b/g,
    mask: "[CARDANO ADDRESS REDACTED]"
  },
  {
    kind: "email address",
    pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
    mask: "[EMAIL REDACTED]"
  },
  {
    kind: "phone number",
    pattern: /(?:\+?1[\s.-]?)?\(?\b\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}\b/g,
    mask: "[PHONE REDACTED]"
  }
];

function redactText(raw) {
  var text = typeof raw === "string" ? raw : "";
  var counts = {};
  var total = 0;
  REDACTORS.forEach(function (r) {
    var found = text.match(r.pattern);
    var n = found ? found.length : 0;
    counts[r.kind] = n;
    total += n;
    text = text.replace(r.pattern, r.mask);
  });
  return { text: text, counts: counts, total: total };
}

/* ---------- 2. Selective-disclosure planner ---------- */
/* mode: "share" = raw value is normally needed, "proof" = prove a fact about
   it instead of revealing it, "keep" = do not hand it over for a routine check. */
var FIELD_CATALOG = {
  fullName:    { label: "Full name", mode: "share",
                 note: "A name is usually the point of the interaction — share it, but nothing extra attached to it." },
  email:       { label: "Email address", mode: "share",
                 note: "Needed if they must contact you. Prefer an alias address you can retire later." },
  dob:         { label: "Date of birth", mode: "proof",
                 note: "Almost nobody needs your birth date — they need a fact about it. On Midnight: prove “18 or older” and keep the date private." },
  homeAddress: { label: "Home address", mode: "proof",
                 note: "Prove the claim being checked — residency in a country or region — instead of your exact street address." },
  idNumber:    { label: "Government ID number", mode: "keep",
                 note: "Never the raw number for a routine check. A verifier can check a credential’s proof; the number itself stays with you." },
  income:      { label: "Income", mode: "proof",
                 note: "Prove a threshold (“income above X”) rather than payslips or an exact figure." },
  walletBalance: { label: "Wallet balance", mode: "proof",
                    note: "Prove “balance at least X” with a ZK proof instead of exposing the wallet and its full position." },
  txHistory:   { label: "Full transaction history", mode: "keep",
                 note: "Your history is a biography. Disclose the single transaction being verified, with a proof — never the whole ledger of your life." }
};

function planDisclosure(keys) {
  var list = Array.isArray(keys) ? keys : [];
  var items = [];
  var tally = { share: 0, proof: 0, keep: 0, unknown: 0 };
  list.forEach(function (key) {
    var field = FIELD_CATALOG[key];
    if (!field) { tally.unknown++; return; }
    items.push({ key: key, label: field.label, mode: field.mode, note: field.note });
    tally[field.mode]++;
  });
  return { items: items, tally: tally };
}

/* ---------- 3. NIGHT -> DUST capacity ---------- */
/* Model used by the NightDream Midnight desk: each NIGHT can sustain up to
   5 DUST capacity. A ceiling estimate, not a generation promise. */
var DUST_PER_NIGHT_MAX = 5;

function dustCapacity(nightStr) {
  var s = (nightStr == null ? "" : String(nightStr)).trim();
  if (!/^\d+(\.\d{1,6})?$/.test(s)) return null;
  var parts = s.split(".");
  var micro = BigInt(parts[0]) * 1000000n + BigInt(((parts[1] || "") + "000000").slice(0, 6));
  var capMicro = micro * BigInt(DUST_PER_NIGHT_MAX);
  var whole = capMicro / 1000000n;
  var frac = (capMicro % 1000000n).toString().padStart(6, "0").replace(/0+$/, "");
  return frac ? whole.toString() + "." + frac : whole.toString();
}

/* ---------- 4. What does this dApp see? ---------- */
/* level: "low" = usually needed to connect, "caution" = ask why and limit
   it before granting, "high" = do not grant blindly for a routine visit. */
var PERMISSION_CATALOG = {
  viewAddress:   { label: "See your receiving / shielded address", level: "low",
                   note: "Normal for connecting and receiving. An address is still an identifier — reuse links your activity, so prefer a fresh address where your wallet offers one." },
  viewBalance:   { label: "See your wallet balance", level: "caution",
                   note: "A balance is financial data. A well-built Midnight dApp should ask for a proof — “balance at least X” — instead of the exact figure. Ask why it needs the number itself." },
  viewTxHistory: { label: "See your full transaction history", level: "high",
                   note: "History reveals counterparties, amounts and habits — a biography, not a login. Disclose the single relevant transaction with a proof, never the whole history." },
  viewContacts:  { label: "See your contacts / saved addresses", level: "caution",
                   note: "Contacts link your wallet to real people and other wallets you use. Grant per purpose, if at all — a dApp rarely needs your whole address book to do one job." },
  signTransaction: { label: "Sign a specific transaction shown to you", level: "caution",
                     note: "Only sign when the amount, recipient and contract on the confirmation screen match exactly what you reviewed. Signing is authorisation, and a signed transaction cannot be unsent." },
  signArbitrary: { label: "Sign arbitrary messages or data (blind signing)", level: "high",
                   note: "A blind signature can authorise actions you never saw. Refuse it for routine logins — a dApp should present the exact statement being signed, in plain language." },
  viewingKey:    { label: "Share a viewing / disclosure key", level: "high",
                   note: "A viewing key grants ongoing visibility, not a one-off check: anyone holding it can keep watching. Share only scoped disclosure where Midnight supports it, never a master key." },
  offchainData:  { label: "Read data stored off-chain on your device", level: "caution",
                   note: "Midnight keeps the private half of state with you, often on your own device. Grant access per item and per purpose — off-chain does not mean unimportant, it is where the private data lives." }
};

function assessDappPermissions(keys) {
  var list = Array.isArray(keys) ? keys : [];
  var items = [];
  var tally = { low: 0, caution: 0, high: 0, unknown: 0 };
  list.forEach(function (key) {
    var perm = PERMISSION_CATALOG[key];
    if (!perm) { tally.unknown++; return; }
    items.push({ key: key, label: perm.label, level: perm.level, note: perm.note });
    tally[perm.level]++;
  });
  var overall = items.length === 0 ? "none" : tally.high > 0 ? "high" : tally.caution > 0 ? "caution" : "low";
  return { items: items, tally: tally, overall: overall };
}

/* ---------- 5. Prove it, don't show it — ZK claim simulator ---------- */
/* A teaching simulation, NOT a cryptographic proof: the comparison happens
   locally in this page, exactly so the visitor can see what a real Midnight
   ZK proof reveals (the claim and whether it holds) and what it hides (the
   underlying value). Amounts are compared as exact BigInt micro-units. */
var CLAIM_CATALOG = {
  age:        { label: "I am old enough",
                statement: function (t) { return "Age is at least " + t; },
                hidden: "Your exact age and your date of birth stay private — the verifier learns only whether the age threshold is met, never the date itself." },
  balance:    { label: "My balance covers it",
                statement: function (t) { return "Wallet balance is at least " + t; },
                hidden: "Your exact balance, wallet address and transaction history stay private — the verifier learns only whether the amount is covered." },
  income:     { label: "My income qualifies",
                statement: function (t) { return "Income is at least " + t; },
                hidden: "Your exact income, employer and payslips stay private — the verifier learns only whether the income threshold is met." },
  membership: { label: "I have been a member long enough",
                statement: function (t) { return "Membership length is at least " + t + " months"; },
                hidden: "Your join date and account history stay private — the verifier learns only whether you have been a member for the required period." }
};

function parseMicro(str) {
  var s = (str == null ? "" : String(str)).trim();
  if (!/^\d+(\.\d{1,6})?$/.test(s)) return null;
  var parts = s.split(".");
  return BigInt(parts[0]) * 1000000n + BigInt(((parts[1] || "") + "000000").slice(0, 6));
}

function formatMicro(micro) {
  var whole = micro / 1000000n;
  var frac = (micro % 1000000n).toString().padStart(6, "0").replace(/0+$/, "");
  return frac ? whole.toString() + "." + frac : whole.toString();
}

function evaluateProof(claimKey, secretStr, thresholdStr) {
  var claim = CLAIM_CATALOG[claimKey];
  if (!claim) return null;
  var secret = parseMicro(secretStr);
  var threshold = parseMicro(thresholdStr);
  if (secret === null || threshold === null) return null;
  var statement = claim.statement(formatMicro(threshold));
  var proved = secret >= threshold;
  return {
    claim: claimKey,
    proved: proved,
    statement: statement,
    revealed: [statement, proved ? "The claim is true" : "The claim is not true"],
    hidden: claim.hidden
  };
}

/* ---------- 6. Compact snippet library ---------- */
/* Simplified TEACHING patterns, not production contracts: each one exists
   to show the Midnight split — what a witness keeps private on the user's
   device, what the ledger publishes, and what disclose() reveals on purpose.
   Compact evolves; verify syntax against the current docs before real use. */
var SNIPPET_CATALOG = {
  "public-counter": {
    title: "Public counter — the fully public baseline",
    category: "basics",
    note: "The starting point every Midnight developer should contrast against: a ledger counter is world-readable forever. Fine for visit counts and totals that harm nobody — and the reason the other patterns exist for anything personal.",
    priv: ["Nothing — this pattern is fully public by design, which is exactly its lesson"],
    pub: ["The visits counter, on the public ledger, readable by anyone"],
    disclosed: ["That a visit happened — each increment is a public event"],
    code: [
      "pragma language_version >= 0.22;",
      "import CompactStandardLibrary;",
      "",
      "export ledger visits: Counter;",
      "",
      "export circuit recordVisit(): [] {",
      "  visits.increment(1);",
      "}"
    ].join("\n")
  },
  "commit-secret": {
    title: "Commit to a secret — publish the hash, not the value",
    category: "commitments",
    note: "The witness supplies the secret from the user's own device and only its hash reaches the ledger. Later the user can reveal the secret and anyone can check it against the commitment — the value was provably fixed earlier, without ever being public in between.",
    priv: ["The secret value itself — it is supplied by a witness and stays on the user's device"],
    pub: ["The hash commitment, on the public ledger"],
    disclosed: ["Only the hash, deliberately, via disclose() — revealing the secret later is a separate, chosen step"],
    code: [
      "pragma language_version >= 0.22;",
      "import CompactStandardLibrary;",
      "",
      "witness secret(): Bytes<32>;",
      "",
      "export ledger commitment: Bytes<32>;",
      "",
      "export circuit commit(): [] {",
      "  commitment = disclose(hash<Bytes<32>>(secret()));",
      "}"
    ].join("\n")
  },
  "selective-disclose": {
    title: "Selective disclosure — disclose one field, deliberately",
    category: "selective-disclosure",
    note: "Compact makes disclosure an explicit act: a witness value cannot silently flow onto the ledger, it must pass through disclose(). Here exactly one fact — that the holder is an adult — is disclosed, while the birth date behind it never leaves the device.",
    priv: ["The exact date of birth — supplied by a witness, kept in private state on the user's device"],
    pub: ["Nothing about the person — the ledger only records that the circuit ran"],
    disclosed: ["The single boolean fact “is an adult”, and nothing else, via disclose()"],
    code: [
      "pragma language_version >= 0.22;",
      "import CompactStandardLibrary;",
      "",
      "witness isAdult(): Boolean;",
      "",
      "export circuit proveAdult(): Boolean {",
      "  const adult = isAdult();",
      "  assert adult;",
      "  return disclose(adult);",
      "}"
    ].join("\n")
  },
  "threshold-proof": {
    title: "Threshold proof — prove “at least X”, hide the amount",
    category: "proofs",
    note: "The balance never becomes public: the circuit checks it against the required amount inside the proof and discloses only the comparison result. A verifier learns that the threshold is met — not the balance, the address, or the history behind it.",
    priv: ["The exact balance — supplied by a witness and compared inside the proof, never published"],
    pub: ["Nothing about the wallet — no balance, address or history reaches the ledger"],
    disclosed: ["Only whether balance >= required, via disclose() — a yes/no answer to a specific question"],
    code: [
      "pragma language_version >= 0.22;",
      "import CompactStandardLibrary;",
      "",
      "witness balance(): Uint<64>;",
      "",
      "export circuit proveCovers(required: Uint<64>): Boolean {",
      "  const covers = balance() >= required;",
      "  assert covers;",
      "  return disclose(covers);",
      "}"
    ].join("\n")
  },
  "private-vote": {
    title: "Private vote — choice stays local, only the tally is public",
    category: "voting",
    note: "Each choice arrives by witness and stays on the voter's device; only the aggregate counters move. Honest limit: an aggregate only protects you inside a crowd — a tally of one voter reveals that voter, so real elections need many voters and careful timing.",
    priv: ["Each voter's individual choice — supplied by a witness, never written to the ledger"],
    pub: ["The running yes/no tallies, on the public ledger"],
    disclosed: ["That this voter voted for the counted side, as an aggregate increment via disclose() — meaningful only among many voters"],
    code: [
      "pragma language_version >= 0.22;",
      "import CompactStandardLibrary;",
      "",
      "witness myVoteIsYes(): Boolean;",
      "",
      "export ledger yesVotes: Counter;",
      "export ledger noVotes: Counter;",
      "",
      "export circuit vote(): [] {",
      "  if (disclose(myVoteIsYes())) {",
      "    yesVotes.increment(1);",
      "  } else {",
      "    noVotes.increment(1);",
      "  }",
      "}"
    ].join("\n")
  }
};

function getSnippet(id) {
  var s = SNIPPET_CATALOG[id];
  if (!s) return null;
  return { id: id, title: s.title, category: s.category, note: s.note,
           priv: s.priv.slice(), pub: s.pub.slice(), disclosed: s.disclosed.slice(), code: s.code };
}

function searchSnippets(query) {
  var needle = (query == null ? "" : String(query)).trim().toLowerCase();
  return Object.keys(SNIPPET_CATALOG).filter(function (id) {
    if (!needle) return true;
    var s = SNIPPET_CATALOG[id];
    var hay = [s.title, s.category, s.note, s.code,
               s.priv.join(" "), s.pub.join(" "), s.disclosed.join(" ")].join(" ").toLowerCase();
    return hay.indexOf(needle) !== -1;
  });
}

/* ---------- 7. How DUST works — lifecycle explainer ---------- */
/* A teaching model built on the same 5x ceiling as tool 3: holding NIGHT
   generates DUST up to a capacity ceiling, shielded transactions spend
   DUST, and holding the same NIGHT afterwards generates DUST back toward
   the same ceiling — DUST is a renewable resource, not a balance you buy
   once. This models amounts and order only: it states NO generation rate
   or time, because the real rate depends on Midnight network parameters.
   All amounts are exact BigInt micro-units. */
function simulateDustLifecycle(nightStr, spendStr, txCountStr) {
  var night = parseMicro(nightStr);
  var spend = parseMicro(spendStr);
  var txRaw = (txCountStr == null ? "" : String(txCountStr)).trim();
  if (night === null || spend === null || !/^\d+$/.test(txRaw)) return null;
  var txCount = BigInt(txRaw);
  if (txCount < 1n || txCount > 1000000n) return null;
  var capacity = night * BigInt(DUST_PER_NIGHT_MAX);
  var affordable = spend === 0n ? txCount : capacity / spend;
  if (affordable > txCount) affordable = txCount;
  var totalSpent = spend * affordable;
  var remaining = capacity - totalSpent;
  return {
    capacity: formatMicro(capacity),
    spendPerTx: formatMicro(spend),
    txCount: Number(txCount),
    affordableTxs: Number(affordable),
    uncoveredTxs: Number(txCount - affordable),
    totalSpent: formatMicro(totalSpent),
    remaining: formatMicro(remaining),
    toRegenerate: formatMicro(totalSpent)
  };
}

/* ---------- 8. Commit now, reveal later ---------- */
/* A hash commitment lets you prove later that you knew or chose something
   earlier, without revealing it in between — the pattern behind the
   "commit-secret" snippet and sealed bids, votes and predictions. The
   commitment here is a REAL SHA-256 hash of a versioned message built
   from your secret, computed locally with the Web Crypto API: the secret
   itself never leaves this device, and only the 64-character hex digest
   is meant to be shared. Anyone you later reveal the secret to can
   recompute the commitment and check it matches — the secret must be
   typed exactly, character for character, spaces included. Honest
   limits: a short or guessable secret can be brute-forced from its
   commitment, so real systems add a long random salt; and this page's
   digest format is its own teaching format, not Compact's on-chain
   persistent hash. */
var COMMIT_PREFIX = "privacy4all-commitment-v1:";

function commitmentMessage(secret) {
  if (typeof secret !== "string" || secret.trim() === "") return null;
  return COMMIT_PREFIX + "\n" + secret;
}

function sha256Hex(text) {
  if (typeof text !== "string") return Promise.resolve(null);
  var subtle = (typeof globalThis !== "undefined" && globalThis.crypto && globalThis.crypto.subtle) || null;
  if (!subtle) return Promise.resolve(null);
  var data = new TextEncoder().encode(text);
  return subtle.digest("SHA-256", data).then(function (buf) {
    return Array.prototype.map.call(new Uint8Array(buf), function (b) {
      return b.toString(16).padStart(2, "0");
    }).join("");
  }, function () { return null; });
}

function makeCommitment(secret) {
  var msg = commitmentMessage(secret);
  if (msg === null) return Promise.resolve(null);
  return sha256Hex(msg);
}

function verifyCommitment(commitmentHex, secret) {
  var given = typeof commitmentHex === "string" ? commitmentHex.trim().toLowerCase() : "";
  if (!/^[0-9a-f]{64}$/.test(given)) return Promise.resolve(null);
  return makeCommitment(secret).then(function (actual) {
    if (actual === null) return null;
    return actual === given;
  });
}

/* ---------- 9. What can an observer see? ---------- */
/* A simplified TEACHING model of ledger visibility only: pick an action
   and see what an observer reading the ledger can see, what stays
   private, and what still leaks anyway. It deliberately does NOT model
   network-level metadata (timing, IP addresses) as solved — every
   scenario names its residual leaks, because a private ledger is one
   layer of privacy, not the whole of it. */
var OBSERVER_CATALOG = {
  "public-transfer": {
    title: "A transfer on a fully public chain",
    note: "The baseline most people picture when they hear “blockchain”: every fact about the transfer is world-readable, forever. Fine for open markets — a biography when it is your rent, wages and donations.",
    sees: ["The sending and receiving addresses", "The exact amount moved", "When it happened — and the full history of both addresses, before and after"],
    cannot: ["Why the payment was made — a purpose or note is not part of a plain transfer record", "The legal names behind the addresses — until an exchange, merchant or leak links one address to a person, and then that whole history is exposed at once"],
    leaks: ["Store-now, identify-later: the record is public forever, so a leak years from now can re-identify transactions made today"]
  },
  "shielded-transfer": {
    title: "A shielded Midnight transfer",
    note: "The amounts and parties move into private state and a zero-knowledge proof convinces the ledger the transfer is valid without publishing them. Shielded means the facts are hidden — it does not mean no event happened.",
    sees: ["That a shielded transaction was submitted and its zero-knowledge proof verified", "Any public state change the transaction deliberately makes — shielded does not mean invisible as an event"],
    cannot: ["The exact amount moved", "Which shielded party sent it and which received it — those stay in private state"],
    leaks: ["Timing and frequency of your transactions, and network-level metadata such as your IP address if you broadcast without separate protection", "Anything you disclose yourself afterwards — a receipt, a screenshot, or telling the counterparty who you are"]
  },
  "disclosed-claim": {
    title: "A Midnight proof with one disclosed claim",
    note: "Selective disclosure in action: the verifier gets exactly one fact, proved — and the credential behind it stays private. This is the pattern tools 2 and 5 build toward.",
    sees: ["The one claim being proved, stated plainly — for example “over 18”", "Whether the proof verified — true or not true, for that claim"],
    cannot: ["The date of birth behind the claim", "Any other field from the credential — name, document number, address — unless it is separately disclosed"],
    leaks: ["The disclosed claim itself is revealed on purpose — keep claims narrow (“over 18”, never the exact age)", "When and where you proved it, if the verifier logs the interaction — a ledger cannot control a verifier's own records"]
  },
  "shielded-contract": {
    title: "A shielded Midnight contract call",
    note: "A Compact contract splits its state: witness inputs and private state stay with the user, the public ledger state is what the contract chooses to publish. The split is a design decision in every contract — this is tool 6's split, seen from the observer's side.",
    sees: ["That the contract was called and its proof verified", "The contract's public ledger state after the call — counters, tallies, and anything the contract deliberately discloses"],
    cannot: ["Your private inputs (witness values) — they stay on your device", "Your private state — the balances, choices or records the contract keeps private"],
    leaks: ["Aggregates need a crowd: a public tally of one reveals that one person's contribution", "Patterns over many calls: repeated timing, or public outputs that track private inputs too closely, can hint at what was hidden"]
  }
};

function getObserverView(id) {
  var s = OBSERVER_CATALOG[id];
  if (!s) return null;
  return { id: id, title: s.title, note: s.note,
           sees: s.sees.slice(), cannot: s.cannot.slice(), leaks: s.leaks.slice() };
}

/* ---------- 10. Share a view, not your wallet ---------- */
/* A simplified TEACHING model of scoped disclosure in principle: when
   someone legitimately needs to check your shielded activity — an
   accountant, an auditor, a counterparty — the Midnight pattern is to
   disclose the narrowest scope that answers their question, never the
   whole wallet by default. Exact viewing-key and disclosure
   capabilities depend on the wallet and the contract involved, so this
   models what a viewer SHOULD and should NOT get at each scope, not a
   specific implementation's guarantees. Two rules hold at every scope:
   viewing is read-only (it never grants spending or signing), and a
   disclosure once seen cannot be un-seen — the viewer can keep copies. */
var VIEWING_CATALOG = {
  "single-transaction": {
    title: "A single transaction — one payment, one claim",
    note: "The narrowest useful scope, and the right default for most checks: the other side needs to confirm one specific payment or claim, not your finances in general.",
    sees: ["That one transaction: its amount, asset and time", "Whether that transaction's proof or claim verified"],
    cannot: ["Your other transactions — nothing before, after, or in between", "Your balances, other counterparties, or any private state that transaction does not touch", "Your funds themselves — a view is read-only and cannot spend or sign anything"],
    risks: ["A disclosure cannot be un-seen: the viewer can keep copies or screenshots of that one transaction forever", "That one transaction may still identify you to its counterparty — scope limits breadth, not what the disclosed item itself says"]
  },
  "single-counterparty": {
    title: "One counterparty — one employer, client or merchant",
    note: "For an ongoing relationship — proving a year of payments to one employer, or a purchase history with one merchant — without opening your dealings with everyone else.",
    sees: ["Your transaction history with that one counterparty, inside the scope", "Totals and timing for that relationship — enough to reconcile an account"],
    cannot: ["Your transactions with any other counterparty", "Your balances or private state outside that relationship", "Your funds themselves — a view is read-only and cannot spend or sign anything"],
    risks: ["One relationship's full history is still a biography of that relationship — amounts, timing and gaps included", "The viewer can keep what they saw after the relationship ends — grant for a question, not forever, where the tooling allows"]
  },
  "time-window": {
    title: "One time window — a tax year, a quarter, a statement period",
    note: "The accountant's scope: everything inside a defined period, nothing outside it. Useful for tax, audit and reporting, where the period — not the person — is what is being checked.",
    sees: ["Transactions that fall inside the window, with their amounts and times", "Period totals a report can be built from — income in, spending out, for that window only"],
    cannot: ["Transactions before or after the window", "Private state or notes that no transaction in the window touches", "Your funds themselves — a view is read-only and cannot spend or sign anything"],
    risks: ["A full period still reveals patterns — income rhythm, spending habits, quiet months — not just the totals a form asks for", "Window edges leak context: a balance carried into the period can hint at what came before it", "The viewer can keep copies of the period's records after the engagement ends — a disclosure cannot be un-seen, so agree retention limits up front"]
  },
  "full-history": {
    title: "Full history — the master view",
    note: "Everything, ongoing: the scope a master viewing key implies. Almost no routine check needs this. Treat it the way you would treat handing someone your complete bank archive — because that is the closest everyday equivalent.",
    sees: ["Your full shielded transaction history in scope — amounts, times and counterparties", "Your balances and how they changed over time — the complete financial picture"],
    cannot: ["Your private keys — viewing never includes the ability to spend or sign", "Data that was never in the wallet's records — off-device notes and other wallets stay outside it"],
    risks: ["Anyone holding this view can keep watching and keep copies — a breach or a forwarded key exposes everything at once", "This is the one scope that cannot be meaningfully narrowed later: once a full history has been seen, it has been seen"]
  }
};

function getViewingView(id) {
  var s = VIEWING_CATALOG[id];
  if (!s) return null;
  return { id: id, title: s.title, note: s.note,
           sees: s.sees.slice(), cannot: s.cannot.slice(), risks: s.risks.slice() };
}

/* ---------- 11. Make it unguessable — strength + salt ---------- */
/* Tool 8's honest limit, made measurable: a commitment is only as safe
   as the secret behind it, because anyone holding the hash can guess
   offline, at machine speed, with nobody watching. This checker gives
   a ROUGH TEACHING ESTIMATE, not a security audit: it assumes every
   character was picked uniformly at random from the character types
   present (lowercase, capitals, digits, symbols), which is the best
   case. Human-chosen secrets are far more predictable than this model
   — names, dates, words and patterns fall to dictionary and rule-based
   guessing long before raw brute force reaches them — so treat the
   numbers here as a ceiling on safety, never a guarantee. The assumed
   guessing rate is labelled, not measured: a well-equipped offline
   attacker testing fast hashes like SHA-256.
   The second half is the standard fix: a long random salt. The salt is
   generated locally with crypto.getRandomValues (the same Web Crypto
   source tool 8 hashes with). Keep the salt private alongside the
   secret and reveal both together: while the salt is secret, a guesser
   must find the secret AND the salt; if the salt is published with
   the commitment it still defeats precomputed rainbow tables, but a
   weak secret alone can still be dictionary-guessed — salt is not a
   substitute for a strong secret, it is a multiplier on one. */
var GUESSES_PER_SECOND = 10000000000; /* 10 billion — labelled assumption */

function analyzeSecret(secret) {
  if (typeof secret !== "string" || secret.length === 0) return null;
  var classes = {
    lower: /[a-z]/.test(secret),
    upper: /[A-Z]/.test(secret),
    digit: /[0-9]/.test(secret),
    symbol: /[^A-Za-z0-9]/.test(secret)
  };
  var pool = (classes.lower ? 26 : 0) + (classes.upper ? 26 : 0) +
             (classes.digit ? 10 : 0) + (classes.symbol ? 33 : 0);
  var entropyBits = Math.round(secret.length * Math.log2(pool) * 10) / 10;
  var verdict = entropyBits < 28 ? "very weak"
    : entropyBits < 36 ? "weak"
    : entropyBits < 60 ? "fair"
    : entropyBits < 80 ? "strong"
    : entropyBits < 128 ? "very strong" : "excellent";
  return { length: secret.length, pool: pool, classes: classes,
           entropyBits: entropyBits, verdict: verdict };
}

function estimateCrackSeconds(secret) {
  var a = analyzeSecret(secret);
  if (!a) return null;
  /* On average an attacker finds it halfway through the search space. */
  return Math.pow(2, a.entropyBits - 1) / GUESSES_PER_SECOND;
}

function formatApproxDuration(seconds) {
  if (typeof seconds !== "number" || isNaN(seconds) || seconds < 0) return null;
  if (!isFinite(seconds)) return "longer than the age of the universe, many times over";
  if (seconds < 1) return "less than a second";
  if (seconds < 60) return "about " + Math.round(seconds) + " seconds";
  var minutes = seconds / 60;
  if (minutes < 60) return "about " + Math.round(minutes) + (Math.round(minutes) === 1 ? " minute" : " minutes");
  var hours = minutes / 60;
  if (hours < 24) return "about " + Math.round(hours) + (Math.round(hours) === 1 ? " hour" : " hours");
  var days = hours / 24;
  if (days < 365.25) return "about " + Math.round(days) + (Math.round(days) === 1 ? " day" : " days");
  var years = days / 365.25;
  if (years < 1000000) return "about " + Math.round(years).toLocaleString("en-US") + (Math.round(years) === 1 ? " year" : " years");
  var exp = years.toExponential(1).replace("e+", "×10^");
  return "about " + exp + " years";
}

function generateSaltHex(byteCount) {
  var n = byteCount === undefined ? 16 : byteCount;
  if (typeof n !== "number" || !Number.isInteger(n) || n < 8 || n > 64) return null;
  var cryptoObj = (typeof globalThis !== "undefined" && globalThis.crypto) || null;
  if (!cryptoObj || typeof cryptoObj.getRandomValues !== "function") return null;
  var bytes = new Uint8Array(n);
  cryptoObj.getRandomValues(bytes);
  return Array.prototype.map.call(bytes, function (b) {
    return b.toString(16).padStart(2, "0");
  }).join("");
}

/* The combined string to commit in tool 8: the secret, a separator,
   and the salt — revealed together later so anyone can recompute. */
function saltedSecret(secret, saltHex) {
  if (typeof secret !== "string" || secret.trim() === "") return null;
  var salt = typeof saltHex === "string" ? saltHex.trim().toLowerCase() : "";
  if (!/^[0-9a-f]{16,128}$/.test(salt) || salt.length % 2 !== 0) return null;
  return secret + "|" + salt;
}

/* ---------- 12. Prove you're on the list (Merkle inclusion proofs) ---------- */
/* A real SHA-256 Merkle tree, built locally. Every entry is hashed into
   a leaf (domain-separated from internal nodes by its prefix, so a leaf
   can never be mistaken for a node), pairs of hashes are hashed into
   parents level by level, and the single remaining hash — the root —
   commits to the whole list. Publish just the root. Later, one entry
   can be proved a member with only the sibling hashes along its path:
   a verifier replays those hashes up to the root and checks it matches,
   without ever seeing the other entries themselves.
   An odd node at the end of a level is promoted to the next level
   unchanged, never duplicated — duplicating the last leaf is a classic
   Merkle pitfall (it lets one entry prove as if it were two slots).
   Honest limits: a Merkle proof is NOT zero-knowledge. It reveals the
   entry itself, its position, the sibling hashes, and (from the proof
   length) the rough size of the list. The other entries stay behind
   their hashes — but a guessable entry can be dictionary-checked by
   hashing guesses, the tool-11 lesson, so real lists salt low-entropy
   entries. This page's hashed-message format is its own teaching
   format, not any specific chain's tree format. */
var MERKLE_LEAF_PREFIX = "privacy4all-merkle-leaf-v1:";
var MERKLE_NODE_PREFIX = "privacy4all-merkle-node-v1:";
var MERKLE_MAX_ENTRIES = 128;

function parseMerkleEntries(text) {
  if (typeof text !== "string") return null;
  return normalizeMerkleEntries(text.split(/\r?\n/));
}

function normalizeMerkleEntries(entries) {
  if (!Array.isArray(entries)) return null;
  var out = [];
  var seen = {};
  for (var i = 0; i < entries.length; i++) {
    if (typeof entries[i] !== "string") return null;
    var e = entries[i].trim();
    if (e === "") continue;
    if (seen[e]) return null; /* duplicates make a proof ambiguous */
    seen[e] = true;
    out.push(e);
  }
  if (out.length === 0 || out.length > MERKLE_MAX_ENTRIES) return null;
  return out;
}

function merkleLeafHash(entry) {
  if (typeof entry !== "string" || entry.trim() === "") return Promise.resolve(null);
  return sha256Hex(MERKLE_LEAF_PREFIX + "\n" + entry.trim());
}

function merkleNodeHash(leftHex, rightHex) {
  if (!/^[0-9a-f]{64}$/.test(leftHex || "") || !/^[0-9a-f]{64}$/.test(rightHex || "")) {
    return Promise.resolve(null);
  }
  return sha256Hex(MERKLE_NODE_PREFIX + "\n" + leftHex + rightHex);
}

function buildMerkleTree(entries) {
  var cleaned = normalizeMerkleEntries(entries);
  if (!cleaned) return Promise.resolve(null);
  return Promise.all(cleaned.map(function (e) { return merkleLeafHash(e); })).then(function (leafHashes) {
    if (leafHashes.indexOf(null) >= 0) return null;
    var levels = [leafHashes];
    function step() {
      var current = levels[levels.length - 1];
      if (current.length <= 1) {
        return { entries: cleaned.slice(), leafHashes: leafHashes.slice(),
                 levels: levels, root: current[0], size: cleaned.length };
      }
      var next = [];
      var jobs = [];
      for (var i = 0; i < current.length; i += 2) {
        if (i + 1 < current.length) {
          (function (slot, left, right) {
            jobs.push(merkleNodeHash(left, right).then(function (h) { next[slot] = h; }));
          })(i / 2, current[i], current[i + 1]);
        } else {
          next[i / 2] = current[i]; /* odd node promoted unchanged */
        }
      }
      return Promise.all(jobs).then(function () {
        if (next.indexOf(null) >= 0) return null;
        levels.push(next);
        return step();
      });
    }
    return step();
  });
}

function getMerkleProof(entries, entry) {
  var target = typeof entry === "string" ? entry.trim() : "";
  if (target === "") return Promise.resolve(null);
  return buildMerkleTree(entries).then(function (tree) {
    if (!tree) return null;
    var index = tree.entries.indexOf(target);
    if (index < 0) return null;
    var proof = [];
    var cur = index;
    for (var level = 0; level < tree.levels.length - 1; level++) {
      var nodes = tree.levels[level];
      if (cur % 2 === 1) proof.push({ hash: nodes[cur - 1], side: "left" });
      else if (cur + 1 < nodes.length) proof.push({ hash: nodes[cur + 1], side: "right" });
      /* else: this node was promoted — no sibling at this level */
      cur = Math.floor(cur / 2);
    }
    return { entry: target, index: index, root: tree.root, size: tree.size,
             leafHash: tree.leafHashes[index], proof: proof };
  });
}

function verifyMerkleProof(entry, proof, rootHex) {
  var root = typeof rootHex === "string" ? rootHex.trim().toLowerCase() : "";
  if (!/^[0-9a-f]{64}$/.test(root)) return Promise.resolve(null);
  if (!Array.isArray(proof)) return Promise.resolve(null);
  var steps = [];
  for (var i = 0; i < proof.length; i++) {
    var s = proof[i];
    if (!s || typeof s.hash !== "string") return Promise.resolve(null);
    var h = s.hash.trim().toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(h) || (s.side !== "left" && s.side !== "right")) {
      return Promise.resolve(null);
    }
    steps.push({ hash: h, side: s.side });
  }
  return merkleLeafHash(entry).then(function (leaf) {
    if (leaf === null) return null;
    var chain = Promise.resolve(leaf);
    steps.forEach(function (s) {
      chain = chain.then(function (cur) {
        if (cur === null) return null;
        return s.side === "left" ? merkleNodeHash(s.hash, cur) : merkleNodeHash(cur, s.hash);
      });
    });
    return chain.then(function (finalHash) {
      if (finalHash === null) return null;
      return finalHash === root;
    });
  });
}

/* ---------- 13. Split a secret (XOR secret sharing) ---------- */
/* Real secret sharing, computed locally — the simplest true scheme.
   The secret's UTF-8 bytes are XORed with (count - 1) freshly random
   byte strings of the same length; the last share is whatever makes
   the XOR of ALL shares come back to the secret. Because every random
   share is uniform, any proper subset of the shares is itself just
   uniform random bytes: it carries no information about the secret's
   content at all (the one-time-pad argument) — that is a property of
   the maths, not a promise about this page.
   Honest limits: this is ALL-of-n sharing, deliberately. Every share
   is required, so losing one share loses the secret forever — real
   systems that need recovery use threshold (k-of-n) sharing such as
   Shamir's, where any k of n shares suffice; that scheme is named
   here, NOT implemented or claimed by this tool. A share is exactly
   as long as the secret, so a share's length leaks the secret's
   length. And a tool is not a vault: never paste a real seed phrase
   or a production secret into any web page, including this one —
   practise with throwaway secrets. */
var SHARE_FORMAT = "p4a-share-v1";
var SHARE_MIN_COUNT = 2;
var SHARE_MAX_COUNT = 8;
var SHARE_MAX_SECRET_CHARS = 512;

function secretToBytes(text) {
  if (typeof TextEncoder !== "undefined") {
    return new TextEncoder().encode(text);
  }
  var utf8 = unescape(encodeURIComponent(text));
  var bytes = new Uint8Array(utf8.length);
  for (var i = 0; i < utf8.length; i++) bytes[i] = utf8.charCodeAt(i) & 0xff;
  return bytes;
}

function bytesToSecret(bytes) {
  try {
    if (typeof TextDecoder !== "undefined") {
      return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    }
    var bin = "";
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return decodeURIComponent(escape(bin));
  } catch (e) {
    return null; /* not valid UTF-8 — the shares were tampered or mixed */
  }
}

function shareBytesToHex(bytes) {
  return Array.prototype.map.call(bytes, function (b) {
    return b.toString(16).padStart(2, "0");
  }).join("");
}

function splitSecret(secret, count) {
  if (typeof secret !== "string" || secret.trim() === "") return null;
  if (secret.length > SHARE_MAX_SECRET_CHARS) return null;
  if (typeof count !== "number" || !Number.isInteger(count) ||
      count < SHARE_MIN_COUNT || count > SHARE_MAX_COUNT) return null;
  var cryptoObj = (typeof globalThis !== "undefined" && globalThis.crypto) || null;
  if (!cryptoObj || typeof cryptoObj.getRandomValues !== "function") return null;
  var data = secretToBytes(secret);
  var randomShares = [];
  var i, j;
  for (i = 0; i < count - 1; i++) {
    var r = new Uint8Array(data.length);
    cryptoObj.getRandomValues(r);
    randomShares.push(r);
  }
  var last = new Uint8Array(data);
  randomShares.forEach(function (r) {
    for (j = 0; j < data.length; j++) last[j] ^= r[j];
  });
  var all = randomShares.concat([last]);
  return {
    count: count,
    shares: all.map(function (bytes, idx) {
      return SHARE_FORMAT + ":" + count + ":" + (idx + 1) + ":" + shareBytesToHex(bytes);
    })
  };
}

function parseShare(line) {
  if (typeof line !== "string") return null;
  var m = line.trim().toLowerCase().match(/^p4a-share-v1:(\d+):(\d+):([0-9a-f]+)$/);
  if (!m) return null;
  var total = parseInt(m[1], 10);
  var index = parseInt(m[2], 10);
  if (total < SHARE_MIN_COUNT || total > SHARE_MAX_COUNT) return null;
  if (index < 1 || index > total) return null;
  if (m[3].length === 0 || m[3].length % 2 !== 0) return null;
  var bytes = new Uint8Array(m[3].length / 2);
  for (var i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(m[3].slice(i * 2, i * 2 + 2), 16);
  }
  return { total: total, index: index, bytes: bytes };
}

/* Accepts the shares as one pasted block of text (one per line) or an
   array of lines. Returns the secret only for the COMPLETE set —
   exactly one of each index, all from one split, all the same
   length. Anything less, duplicated or mixed is null, never a
   best-effort guess: there is no partial recovery in all-of-n. */
function combineShares(input) {
  var lines;
  if (typeof input === "string") lines = input.split(/\r?\n/);
  else if (Array.isArray(input)) lines = input;
  else return null;
  var parsed = [];
  for (var i = 0; i < lines.length; i++) {
    if (typeof lines[i] === "string" && lines[i].trim() === "") continue;
    var p = parseShare(lines[i]);
    if (!p) return null;
    parsed.push(p);
  }
  if (parsed.length === 0) return null;
  var total = parsed[0].total;
  if (parsed.length !== total) return null;
  var seen = {};
  var len = parsed[0].bytes.length;
  if (len === 0) return null;
  for (i = 0; i < parsed.length; i++) {
    if (parsed[i].total !== total) return null; /* shares from two splits */
    if (parsed[i].bytes.length !== len) return null;
    if (seen[parsed[i].index]) return null; /* a duplicate is not a set */
    seen[parsed[i].index] = true;
  }
  var out = new Uint8Array(len);
  parsed.forEach(function (p) {
    for (var j = 0; j < len; j++) out[j] ^= p.bytes[j];
  });
  var secret = bytesToSecret(out);
  if (secret === null || secret.trim() === "") return null;
  return secret;
}

/* ---------- 14. Spend it once, stay private (notes & nullifiers) ---------- */
/* How a shielded system stops double-spending without knowing who spent
   what. A shielded note is represented on the public ledger only by a
   COMMITMENT — a hash of the note's secret. To spend the note, the owner
   publishes a NULLIFIER — a second hash of the same secret, made with a
   different versioned prefix (domain separation). The ledger's rule is
   then purely mechanical: a nullifier may appear only once, ever, so a
   second spend of the same note is rejected — yet from the two hashes
   alone nobody can tell which commitment a nullifier belongs to, because
   linking them means finding the secret behind either hash.
   Honest limits: this is a simplified TEACHING model of the idea, built
   from this page's own SHA-256 formats — it is NOT how a real Midnight
   note is constructed. Real shielded systems use random note secrets and
   keys nobody can guess, plus a zero-knowledge proof that the note
   exists and the spender owns it; a human-chosen secret here can be
   dictionary-checked against BOTH hashes (tool 11's lesson), and if the
   secret ever leaks, its commitment and nullifier become linkable
   retroactively. Publishing a nullifier also reveals that A note was
   spent at that moment — timing still leaks (tool 9's lesson). */
var NOTE_COMMIT_PREFIX = "privacy4all-note-commitment-v1:";
var NOTE_NULLIFIER_PREFIX = "privacy4all-note-nullifier-v1:";

function noteHash(prefix, secret) {
  if (typeof secret !== "string" || secret.trim() === "") return Promise.resolve(null);
  return sha256Hex(prefix + "\n" + secret);
}

function noteCommitment(secret) { return noteHash(NOTE_COMMIT_PREFIX, secret); }
function noteNullifier(secret) { return noteHash(NOTE_NULLIFIER_PREFIX, secret); }

/* A ledger list (commitments or spent nullifiers) must be an array of
   64-char hex strings. Input is normalised (trimmed, lowercased);
   anything malformed — or duplicated, which a real ledger set cannot
   contain — makes the whole list invalid (null), never a best guess. */
function normalizeHexList(list) {
  if (!Array.isArray(list)) return null;
  var out = [];
  var seen = {};
  for (var i = 0; i < list.length; i++) {
    if (typeof list[i] !== "string") return null;
    var v = list[i].trim().toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(v)) return null;
    if (seen[v]) return null;
    seen[v] = true;
    out.push(v);
  }
  return out;
}

/* Attempt to spend a note against a ledger state. Pure: the inputs are
   never mutated; a successful spend returns the NEW spent list.
   Outcomes: "spent" (first spend of a created note), "double-spend"
   (this note's nullifier is already on the ledger), "unknown-note"
   (no commitment for this secret was ever created — a real system
   rejects this with its existence proof, here with the list itself).
   Malformed inputs or an empty secret resolve to null, not a verdict. */
function attemptSpend(commitments, spentNullifiers, secret) {
  var commits = normalizeHexList(commitments);
  var spent = normalizeHexList(spentNullifiers);
  if (commits === null || spent === null) return Promise.resolve(null);
  return Promise.all([noteCommitment(secret), noteNullifier(secret)]).then(function (pair) {
    var commitment = pair[0], nullifier = pair[1];
    if (commitment === null || nullifier === null) return null;
    if (commits.indexOf(commitment) === -1) {
      return { status: "unknown-note", commitment: commitment, nullifier: nullifier, seen: spent.slice() };
    }
    if (spent.indexOf(nullifier) !== -1) {
      return { status: "double-spend", commitment: commitment, nullifier: nullifier, seen: spent.slice() };
    }
    return { status: "spent", commitment: commitment, nullifier: nullifier, seen: spent.concat([nullifier]) };
  });
}

/* ---------- 15. Split with a safety net (Shamir k-of-n) ---------- */
/* Shamir's threshold secret sharing, computed locally for real — the
   scheme tool 13 named but did not implement. Each byte of the secret
   is the constant term of a polynomial over GF(256) (the AES field,
   polynomial x^8+x^4+x^3+x+1) whose other coefficients are fresh
   random bytes; a share is the polynomial evaluated at a non-zero
   point x. Any THRESHOLD (k) shares rebuild each byte by Lagrange
   interpolation at x = 0; k-1 shares are consistent with every
   possible secret byte, so they reveal nothing about the content —
   that is a property of the maths with truly random coefficients.
   Honest limits: this is a TEACHING implementation, not an audited
   library — do not trust it with a real secret. There is NO checksum
   or authentication: with exactly k shares, one wrong or tampered
   share rebuilds a WRONG secret silently (extra honest shares are
   the way to outvote a bad one only if you can tell which rebuild is
   plausible). Each share is exactly as long as the secret, so a
   share's length leaks the secret's length. And never paste a real
   seed phrase or production secret into any web page, including this
   one — practise with throwaway secrets. */
var SHAMIR_FORMAT = "p4a-shamir-v1";
var SHAMIR_MIN_THRESHOLD = 2;
var SHAMIR_MAX_COUNT = 8;

/* GF(256) tables for generator 3 under the AES polynomial. */
var GF_EXP = new Uint8Array(512);
var GF_LOG = new Uint8Array(256);
(function buildGfTables() {
  var x = 1;
  for (var i = 0; i < 255; i++) {
    GF_EXP[i] = x;
    GF_LOG[x] = i;
    var x2 = x << 1;
    if (x2 & 0x100) x2 ^= 0x11b;
    x = (x2 & 0xff) ^ x; /* multiply by generator 3: x*2 ^ x */
  }
  for (var j = 255; j < 512; j++) GF_EXP[j] = GF_EXP[j - 255];
})();

function gfMul(a, b) {
  if (a === 0 || b === 0) return 0;
  return GF_EXP[GF_LOG[a] + GF_LOG[b]];
}

function gfDiv(a, b) {
  if (a === 0) return 0;
  if (b === 0) return null;
  var d = GF_LOG[a] - GF_LOG[b];
  if (d < 0) d += 255;
  return GF_EXP[d];
}

function splitThresholdSecret(secret, threshold, count) {
  if (typeof secret !== "string" || secret.trim() === "") return null;
  if (secret.length > SHARE_MAX_SECRET_CHARS) return null;
  if (typeof threshold !== "number" || !Number.isInteger(threshold) ||
      threshold < SHAMIR_MIN_THRESHOLD || threshold > SHAMIR_MAX_COUNT) return null;
  if (typeof count !== "number" || !Number.isInteger(count) ||
      count < threshold || count > SHAMIR_MAX_COUNT) return null;
  var cryptoObj = (typeof globalThis !== "undefined" && globalThis.crypto) || null;
  if (!cryptoObj || typeof cryptoObj.getRandomValues !== "function") return null;
  var data = secretToBytes(secret);
  var randomBytes = new Uint8Array((threshold - 1) * data.length);
  cryptoObj.getRandomValues(randomBytes);
  var shares = [];
  for (var x = 1; x <= count; x++) {
    var y = new Uint8Array(data.length);
    for (var j = 0; j < data.length; j++) {
      /* Horner evaluation in GF(256): y = s + c1*x + c2*x^2 + ... */
      var acc = 0;
      for (var deg = threshold - 1; deg >= 1; deg--) {
        var coeff = randomBytes[(deg - 1) * data.length + j];
        acc = gfMul(acc, x) ^ coeff;
      }
      y[j] = gfMul(acc, x) ^ data[j];
    }
    shares.push(SHAMIR_FORMAT + ":" + threshold + ":" + count + ":" + x + ":" + shareBytesToHex(y));
  }
  return { threshold: threshold, count: count, shares: shares };
}

function parseShamirShare(line) {
  if (typeof line !== "string") return null;
  var m = line.trim().toLowerCase().match(/^p4a-shamir-v1:(\d+):(\d+):(\d+):([0-9a-f]+)$/);
  if (!m) return null;
  var threshold = parseInt(m[1], 10);
  var count = parseInt(m[2], 10);
  var index = parseInt(m[3], 10);
  if (threshold < SHAMIR_MIN_THRESHOLD || threshold > SHAMIR_MAX_COUNT) return null;
  if (count < threshold || count > SHAMIR_MAX_COUNT) return null;
  if (index < 1 || index > count) return null;
  if (m[4].length === 0 || m[4].length % 2 !== 0) return null;
  var bytes = new Uint8Array(m[4].length / 2);
  for (var i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(m[4].slice(i * 2, i * 2 + 2), 16);
  }
  return { threshold: threshold, count: count, index: index, bytes: bytes };
}

/* Accepts the shares as one pasted block of text (one per line) or an
   array of lines. Rebuilds ONLY from at least THRESHOLD distinct,
   same-split shares of one length; fewer, duplicated or mixed sets
   are null, never a best-effort guess. (With exactly threshold honest
   shares the maths is exact; there is no integrity check — see the
   honest limits above.) */
function combineThresholdShares(input) {
  var lines;
  if (typeof input === "string") lines = input.split(/\r?\n/);
  else if (Array.isArray(input)) lines = input;
  else return null;
  var parsed = [];
  for (var i = 0; i < lines.length; i++) {
    if (typeof lines[i] === "string" && lines[i].trim() === "") continue;
    var p = parseShamirShare(lines[i]);
    if (!p) return null;
    parsed.push(p);
  }
  if (parsed.length === 0) return null;
  var threshold = parsed[0].threshold;
  var count = parsed[0].count;
  var len = parsed[0].bytes.length;
  if (len === 0) return null;
  if (parsed.length < threshold || parsed.length > count) return null;
  var seen = {};
  for (i = 0; i < parsed.length; i++) {
    if (parsed[i].threshold !== threshold || parsed[i].count !== count) return null;
    if (parsed[i].bytes.length !== len) return null;
    if (seen[parsed[i].index]) return null;
    seen[parsed[i].index] = true;
  }
  var out = new Uint8Array(len);
  for (var j = 0; j < len; j++) {
    var acc = 0;
    for (i = 0; i < parsed.length; i++) {
      /* Lagrange basis at x = 0: prod_{m != i} x_m / (x_i ^ x_m) */
      var num = 1, den = 1;
      for (var mIdx = 0; mIdx < parsed.length; mIdx++) {
        if (mIdx === i) continue;
        num = gfMul(num, parsed[mIdx].index);
        den = gfMul(den, parsed[i].index ^ parsed[mIdx].index);
      }
      var basis = gfDiv(num, den);
      if (basis === null) return null;
      acc ^= gfMul(parsed[i].bytes[j], basis);
    }
    out[j] = acc;
  }
  var secret = bytesToSecret(out);
  if (secret === null || secret.trim() === "") return null;
  return secret;
}

/* ---------- 16. Seal it so only they can read it ---------- */
/* Hashing (tools 8, 12, 14) is one-way: nobody can un-hash a
   commitment. ENCRYPTION is the opposite tool: reversible, but only
   for whoever holds the key. This tool seals a message with a
   password: PBKDF2-HMAC-SHA-256 (SEAL_ITERATIONS rounds, a fresh
   random 16-byte salt per seal) stretches the password into a
   256-bit key, and AES-GCM encrypts the message under a fresh
   random 12-byte IV. The sealed text carries salt, IV and
   ciphertext — all safe to publish — in one versioned line:
   p4a-sealed-v1:<saltHex>:<ivHex>:<cipherHex>. GCM is
   authenticated: a wrong password or a single changed character
   makes opening FAIL outright, instead of returning gibberish —
   the integrity check tools 13/15 honestly lack.
   Honest limits: this is a teaching implementation, not an audited
   encryption product. Its safety is exactly the password's safety:
   PBKDF2 slows an offline guessing attack but cannot save a weak
   or reused password (tool 11 measures that), and the ciphertext
   length reveals the message's approximate length. Anyone who gets
   BOTH the sealed text and the password can read the message —
   share them by different channels. Never paste a real seed phrase
   or production secret into any web page, including this one —
   practise with throwaway messages. */
var SEAL_FORMAT = "p4a-sealed-v1";
var SEAL_ITERATIONS = 210000;
var SEAL_MAX_MESSAGE_CHARS = 2000;
var SEAL_SALT_BYTES = 16;
var SEAL_IV_BYTES = 12;

function hexToBytes(hex) {
  if (typeof hex !== "string" || hex.length === 0 || hex.length % 2 !== 0 ||
      !/^[0-9a-f]+$/.test(hex)) return null;
  var bytes = new Uint8Array(hex.length / 2);
  for (var i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function parseSealed(text) {
  if (typeof text !== "string") return null;
  var m = text.trim().toLowerCase().match(/^p4a-sealed-v1:([0-9a-f]+):([0-9a-f]+):([0-9a-f]+)$/);
  if (!m) return null;
  var salt = hexToBytes(m[1]);
  var iv = hexToBytes(m[2]);
  var cipher = hexToBytes(m[3]);
  if (!salt || !iv || !cipher) return null;
  if (salt.length !== SEAL_SALT_BYTES || iv.length !== SEAL_IV_BYTES) return null;
  /* GCM tag is 16 bytes, so ciphertext is at least 1 byte + tag. */
  if (cipher.length < 17) return null;
  return { salt: salt, iv: iv, cipher: cipher };
}

function validSealInputs(message, password) {
  return typeof message === "string" && message.trim() !== "" &&
    message.length <= SEAL_MAX_MESSAGE_CHARS &&
    typeof password === "string" && password.trim() !== "";
}

function deriveSealKey(password, salt) {
  var subtle = (typeof globalThis !== "undefined" && globalThis.crypto && globalThis.crypto.subtle) || null;
  if (!subtle || typeof subtle.importKey !== "function") return Promise.resolve(null);
  return subtle.importKey("raw", secretToBytes(password), "PBKDF2", false, ["deriveKey"])
    .then(function (base) {
      return subtle.deriveKey(
        { name: "PBKDF2", salt: salt, iterations: SEAL_ITERATIONS, hash: "SHA-256" },
        base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
    }, function () { return null; })
    .then(function (key) { return key || null; }, function () { return null; });
}

function sealMessage(message, password) {
  if (!validSealInputs(message, password)) return Promise.resolve(null);
  var cryptoObj = (typeof globalThis !== "undefined" && globalThis.crypto) || null;
  if (!cryptoObj || typeof cryptoObj.getRandomValues !== "function" || !cryptoObj.subtle) {
    return Promise.resolve(null);
  }
  var salt = new Uint8Array(SEAL_SALT_BYTES);
  cryptoObj.getRandomValues(salt);
  var iv = new Uint8Array(SEAL_IV_BYTES);
  cryptoObj.getRandomValues(iv);
  return deriveSealKey(password, salt).then(function (key) {
    if (!key) return null;
    return cryptoObj.subtle.encrypt({ name: "AES-GCM", iv: iv }, key, secretToBytes(message))
      .then(function (buf) {
        return SEAL_FORMAT + ":" + shareBytesToHex(salt) + ":" + shareBytesToHex(iv) +
          ":" + shareBytesToHex(new Uint8Array(buf));
      }, function () { return null; });
  });
}

function unsealMessage(sealed, password) {
  var parsed = parseSealed(sealed);
  if (!parsed) return Promise.resolve(null);
  if (typeof password !== "string" || password.trim() === "") return Promise.resolve(null);
  var cryptoObj = (typeof globalThis !== "undefined" && globalThis.crypto) || null;
  if (!cryptoObj || !cryptoObj.subtle) return Promise.resolve(null);
  return deriveSealKey(password, parsed.salt).then(function (key) {
    if (!key) return null;
    return cryptoObj.subtle.decrypt({ name: "AES-GCM", iv: parsed.iv }, key, parsed.cipher)
      .then(function (buf) {
        var msg = bytesToSecret(new Uint8Array(buf));
        if (msg === null || msg.trim() === "") return null;
        if (msg.length > SEAL_MAX_MESSAGE_CHARS) return null;
        return msg;
      }, function () { return null; /* wrong password or tampered — GCM refuses */ });
  });
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = { redactText, planDisclosure, dustCapacity, FIELD_CATALOG, DUST_PER_NIGHT_MAX,
                     assessDappPermissions, PERMISSION_CATALOG,
                     evaluateProof, CLAIM_CATALOG,
                     getSnippet, searchSnippets, SNIPPET_CATALOG,
                     simulateDustLifecycle,
                     COMMIT_PREFIX, commitmentMessage, sha256Hex, makeCommitment, verifyCommitment,
                     getObserverView, OBSERVER_CATALOG,
                     getViewingView, VIEWING_CATALOG,
                     analyzeSecret, estimateCrackSeconds, formatApproxDuration,
                     generateSaltHex, saltedSecret, GUESSES_PER_SECOND,
                     MERKLE_LEAF_PREFIX, MERKLE_NODE_PREFIX, MERKLE_MAX_ENTRIES,
                     parseMerkleEntries, normalizeMerkleEntries, merkleLeafHash,
                     buildMerkleTree, getMerkleProof, verifyMerkleProof,
                     SHARE_FORMAT, SHARE_MIN_COUNT, SHARE_MAX_COUNT, SHARE_MAX_SECRET_CHARS,
                     splitSecret, parseShare, combineShares,
                     NOTE_COMMIT_PREFIX, NOTE_NULLIFIER_PREFIX,
                     noteCommitment, noteNullifier, normalizeHexList, attemptSpend,
                     SHAMIR_FORMAT, SHAMIR_MIN_THRESHOLD, SHAMIR_MAX_COUNT,
                     gfMul, gfDiv, splitThresholdSecret, parseShamirShare, combineThresholdShares,
                     SEAL_FORMAT, SEAL_ITERATIONS, SEAL_MAX_MESSAGE_CHARS,
                     parseSealed, sealMessage, unsealMessage };
}

if (typeof document !== "undefined") {
  document.addEventListener("DOMContentLoaded", function () {
    /* --- project filtering --- */
    var cards = Array.prototype.slice.call(document.querySelectorAll("#cards .card"));
    var q = document.getElementById("q");
    var status = document.getElementById("filter-status");
    var noResults = document.getElementById("no-results");
    var activeFilter = "all";
    function applyFilter() {
      var needle = (q.value || "").toLowerCase();
      var shown = 0;
      cards.forEach(function (card) {
        var catOk = activeFilter === "all" || (card.getAttribute("data-cat") || "").split(" ").indexOf(activeFilter) !== -1;
        var textOk = !needle || (card.getAttribute("data-name") + " " + card.textContent).toLowerCase().indexOf(needle) !== -1;
        var show = catOk && textOk;
        card.hidden = !show;
        if (show) shown++;
      });
      noResults.hidden = shown !== 0;
      status.textContent = shown + (shown === 1 ? " project shown" : " projects shown");
    }
    q.addEventListener("input", applyFilter);
    document.querySelectorAll(".chip").forEach(function (chip) {
      chip.addEventListener("click", function () {
        document.querySelectorAll(".chip").forEach(function (c) { c.classList.remove("active"); });
        chip.classList.add("active");
        activeFilter = chip.getAttribute("data-filter");
        applyFilter();
      });
    });
    applyFilter();

    /* --- redactor --- */
    document.getElementById("redactor").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var out = redactText(document.getElementById("redact-in").value);
      document.getElementById("redact-out").value = out.text;
      var bits = Object.keys(out.counts).filter(function (k) { return out.counts[k] > 0; })
        .map(function (k) { return out.counts[k] + " × " + k; });
      document.getElementById("redact-result").textContent = out.total === 0
        ? "Nothing matched the email / Cardano address / US phone patterns. Still read it once yourself before sharing — no checker catches everything."
        : "Redacted " + out.total + (out.total === 1 ? " item" : " items") + ": " + bits.join(", ") + ". Done locally — the original never left this page.";
    });

    /* --- disclosure planner --- */
    document.getElementById("planner").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var keys = Array.prototype.slice.call(document.querySelectorAll('input[name="field"]:checked'))
        .map(function (box) { return box.value; });
      var host = document.getElementById("plan-result");
      host.textContent = "";
      if (!keys.length) {
        host.textContent = "Tick at least one item they are asking for.";
        return;
      }
      var plan = planDisclosure(keys);
      var modeLabel = { share: "Share it", proof: "Prove it instead", keep: "Keep it private" };
      var ul = document.createElement("ul");
      ul.className = "plan-list";
      plan.items.forEach(function (item) {
        var li = document.createElement("li");
        var strong = document.createElement("strong");
        strong.textContent = item.label + " — " + modeLabel[item.mode] + ". ";
        li.appendChild(strong);
        li.appendChild(document.createTextNode(item.note));
        ul.appendChild(li);
      });
      host.appendChild(ul);
      var summary = document.createElement("p");
      summary.textContent = "Plan: " + plan.tally.share + " to share, " + plan.tally.proof +
        " to prove instead of revealing, " + plan.tally.keep + " to keep private. That is the Midnight pattern: disclosure by choice, not by default.";
      host.appendChild(summary);
    });

    /* --- DUST capacity --- */
    document.getElementById("dust").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var input = document.getElementById("night").value;
      var cap = dustCapacity(input);
      document.getElementById("dust-result").textContent = cap === null
        ? "Enter a NIGHT amount (a whole number, or up to 6 decimal places)."
        : input.trim() + " NIGHT can sustain up to ~" + cap + " DUST capacity (5 × NIGHT model). Actual generation depends on holdings and Midnight network parameters — this is a ceiling, not a promise.";
    });

    /* --- what does this dApp see? --- */
    document.getElementById("dapp-see").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var keys = Array.prototype.slice.call(document.querySelectorAll('input[name="perm"]:checked'))
        .map(function (box) { return box.value; });
      var host = document.getElementById("dapp-result");
      host.textContent = "";
      if (!keys.length) {
        host.textContent = "Tick at least one permission the dApp is asking for.";
        return;
      }
      var result = assessDappPermissions(keys);
      var levelLabel = { low: "Usually OK", caution: "Ask why first", high: "Don't grant blindly" };
      var ul = document.createElement("ul");
      ul.className = "plan-list";
      result.items.forEach(function (item) {
        var li = document.createElement("li");
        var strong = document.createElement("strong");
        strong.textContent = item.label + " — " + levelLabel[item.level] + ". ";
        li.appendChild(strong);
        li.appendChild(document.createTextNode(item.note));
        ul.appendChild(li);
      });
      host.appendChild(ul);
      var summary = document.createElement("p");
      var verdict = { low: "Low exposure: nothing here goes beyond connecting.",
        caution: "Review carefully: ask why each caution item is needed, and limit it where you can.",
        high: "High exposure: at least one request would let this dApp see or authorise far more than a routine visit needs. Do not grant those blindly.",
        none: "" }[result.overall];
      summary.textContent = "Overall: " + verdict + " Assessment done locally — nothing about your wallet left this page. This tool never connects a wallet or signs anything.";
      host.appendChild(summary);
    });

    /* --- prove it, don't show it — ZK claim simulator --- */
    document.getElementById("zk-prover").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var result = evaluateProof(document.getElementById("claim").value,
        document.getElementById("secret").value, document.getElementById("threshold").value);
      var host = document.getElementById("zk-result");
      host.textContent = "";
      if (!result) {
        host.textContent = "Enter your private value and the threshold as numbers (a whole number, or up to 6 decimal places).";
        return;
      }
      var sees = document.createElement("p");
      var strongSees = document.createElement("strong");
      strongSees.textContent = result.proved ? "Proved — without showing the value. " : "Not proved. ";
      sees.appendChild(strongSees);
      sees.appendChild(document.createTextNode("A verifier sees only this: “" + result.statement +
        "” — and whether it is true (" + (result.proved ? "yes" : "no") + ")."));
      host.appendChild(sees);
      var hides = document.createElement("p");
      var strongHides = document.createElement("strong");
      strongHides.textContent = "What stays hidden: ";
      hides.appendChild(strongHides);
      hides.appendChild(document.createTextNode(result.hidden));
      host.appendChild(hides);
      var note = document.createElement("p");
      note.textContent = "This is a local simulation of the pattern, not a cryptographic proof: your value was compared on this device only and never left this page. On Midnight, a real zero-knowledge proof gives the verifier the same two facts — the claim, and that it holds — with the value itself staying in your private state.";
      host.appendChild(note);
    });

    /* --- Compact snippet library --- */
    document.getElementById("snippets").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var snip = getSnippet(document.getElementById("snippet-select").value);
      var host = document.getElementById("snippet-result");
      host.textContent = "";
      if (!snip) {
        host.textContent = "Pick a pattern from the list.";
        return;
      }
      var note = document.createElement("p");
      note.textContent = snip.note;
      host.appendChild(note);
      [["Stays private", snip.priv], ["Goes public", snip.pub], ["Deliberately disclosed", snip.disclosed]].forEach(function (pair) {
        var p = document.createElement("p");
        var strong = document.createElement("strong");
        strong.textContent = pair[0] + ": ";
        p.appendChild(strong);
        p.appendChild(document.createTextNode(pair[1].join(" ")));
        host.appendChild(p);
      });
      var pre = document.createElement("pre");
      pre.className = "snippet-code";
      var code = document.createElement("code");
      code.textContent = snip.code;
      pre.appendChild(code);
      host.appendChild(pre);
      var warn = document.createElement("p");
      warn.textContent = "Simplified teaching pattern, not a production contract — check the current Compact docs and compile before real use. Everything here ran locally; nothing left this page.";
      host.appendChild(warn);
    });

    /* --- how DUST works — lifecycle explainer --- */
    document.getElementById("dust-life").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var r = simulateDustLifecycle(document.getElementById("life-night").value,
        document.getElementById("life-spend").value, document.getElementById("life-txs").value);
      var host = document.getElementById("dust-life-result");
      host.textContent = "";
      if (!r) {
        host.textContent = "Enter NIGHT held and a cost per transaction as numbers (whole, or up to 6 decimal places), and a whole number of transactions (1 or more).";
        return;
      }
      var steps = [
        "1 · Hold: holding NIGHT gives you up to " + r.capacity + " DUST capacity (the 5 × NIGHT ceiling from tool 3 — a ceiling, not a promise).",
        "2 · Generate: while you hold that NIGHT, DUST generates up to that ceiling. This model shows amounts, not time — it states no generation rate, because the real rate depends on Midnight network parameters.",
        "3 · Spend: at " + r.spendPerTx + " DUST per shielded transaction, that capacity covers " + r.affordableTxs +
          " of your " + r.txCount + " planned transactions, spending " + r.totalSpent + " DUST and leaving " + r.remaining + " DUST." +
          (r.uncoveredTxs > 0 ? " The other " + r.uncoveredTxs + " would have to wait for regeneration or more NIGHT." : ""),
        "4 · Regenerate: keep holding the same NIGHT and DUST generates back toward the same ceiling — " + r.toRegenerate +
          " DUST to refill what you spent. That is the point of DUST: a renewable resource generated by holding NIGHT, not a token you burn through once."
      ];
      var ul = document.createElement("ul");
      ul.className = "plan-list";
      steps.forEach(function (s) {
        var li = document.createElement("li");
        li.textContent = s;
        ul.appendChild(li);
      });
      host.appendChild(ul);
      var note = document.createElement("p");
      note.textContent = "Teaching model, run locally — no wallet connected, nothing left this page, and no real DUST amounts or times are promised.";
      host.appendChild(note);
    });

    /* --- commit now, reveal later --- */
    document.getElementById("commit-make").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var secret = document.getElementById("commit-secret").value;
      var out = document.getElementById("commit-out");
      var status = document.getElementById("commit-make-result");
      out.value = "";
      status.textContent = "Hashing locally…";
      makeCommitment(secret).then(function (hex) {
        if (hex === null) {
          status.textContent = "Type a secret first — anything you want to be able to prove later: a prediction, a bid, a choice. (If hashing is unavailable in this browser, open the page over HTTPS in a current browser.)";
          return;
        }
        out.value = hex;
        status.textContent = "Commitment made locally — your secret never left this page; only this hash is meant to be shared. Publish or save the hash now, keep the secret private, and reveal the secret later: anyone can recompute the hash from it and confirm you committed to exactly this, back when you published the hash.";
      });
    });
    document.getElementById("commit-check").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var status = document.getElementById("commit-check-result");
      status.textContent = "Checking locally…";
      verifyCommitment(document.getElementById("check-commitment").value,
        document.getElementById("check-secret").value).then(function (ok) {
        if (ok === null) {
          status.textContent = "Paste a full 64-character hex commitment and the revealed secret, typed exactly as it was committed — character for character, spaces included.";
          return;
        }
        status.textContent = ok
          ? "Match — the revealed secret produces exactly this commitment. Whoever published that hash earlier was committed to this secret; it was not swapped afterwards."
          : "No match — this secret does not produce that commitment. Either the secret is typed differently (check capitals and spaces) or it is not the secret that was committed.";
      });
    });

    /* --- what can an observer see? --- */
    document.getElementById("observer").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var view = getObserverView(document.getElementById("observer-select").value);
      var host = document.getElementById("observer-result");
      host.textContent = "";
      if (!view) {
        host.textContent = "Pick a scenario from the list.";
        return;
      }
      var note = document.createElement("p");
      note.textContent = view.note;
      host.appendChild(note);
      [["An observer reading the ledger CAN see", view.sees],
       ["An observer CANNOT see", view.cannot],
       ["What still leaks anyway", view.leaks]].forEach(function (pair) {
        var p = document.createElement("p");
        var strong = document.createElement("strong");
        strong.textContent = pair[0] + ":";
        p.appendChild(strong);
        host.appendChild(p);
        var ul = document.createElement("ul");
        ul.className = "plan-list";
        pair[1].forEach(function (item) {
          var li = document.createElement("li");
          li.textContent = item;
          ul.appendChild(li);
        });
        host.appendChild(ul);
      });
      var foot = document.createElement("p");
      foot.textContent = "Teaching model of ledger visibility only, run locally — nothing left this page, no wallet connected. Network-level privacy (timing, IP addresses) needs separate protection on top of any ledger.";
      host.appendChild(foot);
    });

    /* --- share a view, not your wallet — viewing-key scope simulator --- */
    document.getElementById("viewing-key").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var view = getViewingView(document.getElementById("viewing-select").value);
      var host = document.getElementById("viewing-result");
      host.textContent = "";
      if (!view) {
        host.textContent = "Pick a scope from the list.";
        return;
      }
      var note = document.createElement("p");
      note.textContent = view.note;
      host.appendChild(note);
      [["A viewer at this scope CAN see", view.sees],
       ["A viewer at this scope CANNOT see", view.cannot],
       ["Risks to weigh before granting it", view.risks]].forEach(function (pair) {
        var p = document.createElement("p");
        var strong = document.createElement("strong");
        strong.textContent = pair[0] + ":";
        p.appendChild(strong);
        host.appendChild(p);
        var ul = document.createElement("ul");
        ul.className = "plan-list";
        pair[1].forEach(function (item) {
          var li = document.createElement("li");
          li.textContent = item;
          ul.appendChild(li);
        });
        host.appendChild(ul);
      });
      var foot = document.createElement("p");
      foot.textContent = "Teaching model of scoped disclosure, run locally — no key was entered, generated or connected, and nothing left this page. Rule that survives every scope: viewing is read-only, but a disclosure once seen cannot be un-seen — grant the narrowest scope that answers the question.";
      host.appendChild(foot);
    });

    /* --- make it unguessable — strength + salt --- */
    document.getElementById("strength-check").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var secret = document.getElementById("strength-secret").value;
      var a = analyzeSecret(secret);
      var host = document.getElementById("strength-result");
      host.textContent = "";
      if (!a) {
        host.textContent = "Type the secret you plan to commit first — anything from one character up.";
        return;
      }
      var used = [];
      if (a.classes.lower) used.push("lowercase");
      if (a.classes.upper) used.push("capitals");
      if (a.classes.digit) used.push("digits");
      if (a.classes.symbol) used.push("symbols / spaces");
      var p = document.createElement("p");
      var strong = document.createElement("strong");
      strong.textContent = "Verdict: " + a.verdict + " — about " + a.entropyBits + " bits in the best case. ";
      p.appendChild(strong);
      p.appendChild(document.createTextNode(a.length + " characters drawn from " + used.join(", ") +
        " (a pool of about " + a.pool + "). At an assumed 10 billion guesses a second, an offline attacker " +
        "who had your commitment hash would need " + formatApproxDuration(estimateCrackSeconds(secret)) +
        " on average — IF every character had been picked uniformly at random. Human-chosen secrets are far " +
        "more predictable than that: words, names, dates and patterns fall to dictionary guessing much sooner, " +
        "so read this as a ceiling on safety, not a promise. Length is the lever you control most: every extra " +
        "random character multiplies the work, and a random salt from the generator below multiplies it far more."));
      host.appendChild(p);
    });
    document.getElementById("salt-make").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var out = document.getElementById("salt-out");
      var status = document.getElementById("salt-result");
      var salt = generateSaltHex(16);
      if (salt === null) {
        out.value = "";
        status.textContent = "Random generation is unavailable in this browser — open the page over HTTPS in a current browser.";
        return;
      }
      out.value = salt;
      status.textContent = "Salt generated locally on this device — nothing was sent anywhere. To use it with tool 8: " +
        "commit the combined text your-secret|" + salt + " (your secret, a | character, then this salt), keep BOTH the secret " +
        "and the salt private, and reveal both together later so anyone can recompute the hash. While the salt stays " +
        "secret, a guesser must find it too — 128 extra random bits. If you publish the salt alongside the commitment " +
        "instead, it still defeats precomputed rainbow tables, but a weak secret can still be dictionary-guessed on its own.";
    });

    /* --- prove you're on the list — Merkle inclusion proofs --- */
    document.getElementById("merkle").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var host = document.getElementById("merkle-result");
      host.textContent = "";
      var entries = parseMerkleEntries(document.getElementById("merkle-entries").value);
      if (!entries) {
        host.textContent = "Give me a clean list first: one entry per line, between 1 and " +
          MERKLE_MAX_ENTRIES + " entries, with no duplicates — a duplicated entry makes its " +
          "proof ambiguous (which copy is proved?), so duplicates are rejected, not merged.";
        return;
      }
      var entry = document.getElementById("merkle-entry").value.trim();
      if (!entry) {
        host.textContent = "Type the entry you want to prove is on the list.";
        return;
      }
      getMerkleProof(entries, entry).then(function (p) {
        if (!p) {
          host.textContent = "That entry is not on this list — entries must match exactly, " +
            "character for character. No proof exists for a non-member, and that is the point: " +
            "nobody can talk a verifier who knows the root into accepting one.";
          return;
        }
        var intro = document.createElement("p");
        var strong = document.createElement("strong");
        strong.textContent = "Member — position " + (p.index + 1) + " of " + p.size + ". ";
        intro.appendChild(strong);
        intro.appendChild(document.createTextNode("Hand a verifier just three things — the entry " +
          "itself, the proof below, and the published root — and they can confirm membership " +
          "without ever seeing the rest of the list."));
        host.appendChild(intro);
        var rootP = document.createElement("p");
        rootP.appendChild(document.createTextNode("List root (the one short value you publish): "));
        var rootCode = document.createElement("code");
        rootCode.textContent = p.root;
        rootP.appendChild(rootCode);
        host.appendChild(rootP);
        var leafP = document.createElement("p");
        leafP.appendChild(document.createTextNode("Your leaf hash: "));
        var leafCode = document.createElement("code");
        leafCode.textContent = p.leafHash;
        leafP.appendChild(leafCode);
        host.appendChild(leafP);
        if (p.proof.length === 0) {
          var solo = document.createElement("p");
          solo.textContent = "Single-entry list: the root IS your leaf hash, so the proof is " +
            "empty — anyone can hash the entry and compare it with the root directly.";
          host.appendChild(solo);
        } else {
          var stepsP = document.createElement("p");
          stepsP.textContent = "Proof — " + p.proof.length + " sibling hash" +
            (p.proof.length === 1 ? "" : "es") + ", bottom level up. The verifier hashes your " +
            "leaf together with each sibling, on the side named, level by level, and checks " +
            "the final hash equals the root:";
          host.appendChild(stepsP);
          var ol = document.createElement("ol");
          p.proof.forEach(function (s) {
            var li = document.createElement("li");
            li.appendChild(document.createTextNode("Sibling on the " + s.side + ": "));
            var c = document.createElement("code");
            c.textContent = s.hash;
            li.appendChild(c);
            ol.appendChild(li);
          });
          host.appendChild(ol);
        }
        return verifyMerkleProof(p.entry, p.proof, p.root).then(function (ok) {
          var foot = document.createElement("p");
          foot.textContent = (ok === true
            ? "This page just re-verified it: replaying the proof lands exactly on the root. "
            : "Verification did not come back clean — that should not happen for a proof this " +
              "page just built, so treat the list above as suspect. ") +
            "What the verifier learned: the entry itself, its position, the sibling hashes and " +
            "(from the proof length) the rough size of the list. Every other entry stayed " +
            "behind its hash — a Merkle proof hides a list's contents, it does not hide the " +
            "membership it proves. Teaching format, run locally — nothing left this page.";
          host.appendChild(foot);
        });
      });
    });

    /* --- split a secret — XOR secret sharing --- */
    document.getElementById("split-make").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var out = document.getElementById("split-out");
      var status = document.getElementById("split-result");
      var count = Number(document.getElementById("split-count").value);
      var res = splitSecret(document.getElementById("split-secret").value, count);
      if (!res) {
        out.value = "";
        status.textContent = "Enter a throwaway secret (up to " + SHARE_MAX_SECRET_CHARS +
          " characters) and a whole number of shares between " + SHARE_MIN_COUNT + " and " +
          SHARE_MAX_COUNT + ". (If splitting is unavailable in this browser, open the page " +
          "over HTTPS in a current browser.) Never a real seed phrase — see the warning above.";
        return;
      }
      out.value = res.shares.join("\n");
      status.textContent = "Split locally into " + res.count + " shares — your secret never " +
        "left this page. Each share on its own is random bytes and reveals nothing about the " +
        "secret's content; hand the shares out separately (different people, places or " +
        "devices), because only ALL " + res.count + " of them together, pasted into the " +
        "rebuild form below, bring the secret back. Lose one and it is gone — that is the " +
        "all-of-n bargain, so keep the shares as carefully as the secret itself.";
    });
    document.getElementById("split-join").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var out = document.getElementById("join-out");
      var status = document.getElementById("join-result");
      var secret = combineShares(document.getElementById("join-in").value);
      if (secret === null) {
        out.value = "";
        status.textContent = "That is not a complete set: paste every share from ONE split, " +
          "one per line — no missing share, no duplicates, no shares mixed in from another " +
          "split. All-of-n means there is no partial recovery and no best guess: a set that " +
          "is not complete and untampered rebuilds nothing.";
        return;
      }
      out.value = secret;
      status.textContent = "Rebuilt locally — the complete set XORs back to the exact secret, " +
        "character for character. Nothing left this page. Anyone who collected all the " +
        "shares could do the same, so once a secret has been rebuilt for use, treat the " +
        "shares as spent: split fresh shares if you need to store it again.";
    });

    /* --- notes & nullifiers — spend it once, stay private --- */
    var noteCommitments = [];
    var noteSpent = [];
    function noteLedgerStatus() {
      document.getElementById("note-ledger-status").textContent =
        "This page's pretend ledger, this session only: " + noteCommitments.length +
        " note" + (noteCommitments.length === 1 ? "" : "s") + " created, " + noteSpent.length +
        " spent. Refreshing the page wipes it — nothing here is a real chain.";
    }
    noteLedgerStatus();
    document.getElementById("note-create").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var out = document.getElementById("note-commit-out");
      var status = document.getElementById("note-create-result");
      noteCommitment(document.getElementById("note-secret").value).then(function (c) {
        if (c === null) {
          out.value = "";
          status.textContent = "Type a throwaway note secret first — never a real seed phrase or a secret protecting anything real.";
          return;
        }
        if (noteCommitments.indexOf(c) !== -1) {
          status.textContent = "That exact secret is already a note on this page's ledger — the same secret always makes the same commitment, which is exactly why real note secrets are random and never reused.";
          return;
        }
        noteCommitments.push(c);
        out.value = c;
        noteLedgerStatus();
        status.textContent = "Note created. The commitment above is the only thing that goes on the public ledger: a hash, not your secret, and not the note's value. Keep the secret itself private — whoever holds it can spend this note, and nobody else can.";
      });
    });
    document.getElementById("note-spend").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var out = document.getElementById("spend-nullifier-out");
      var status = document.getElementById("note-spend-result");
      attemptSpend(noteCommitments, noteSpent, document.getElementById("spend-secret").value).then(function (res) {
        if (res === null) {
          out.value = "";
          status.textContent = "Type the exact secret of a note you created above — character for character, spaces included.";
          return;
        }
        if (res.status === "unknown-note") {
          out.value = "";
          status.textContent = "Rejected — no note with that secret was created on this page's ledger. A shielded ledger only spends notes it can prove exist; a secret that was never committed spends nothing.";
          return;
        }
        if (res.status === "double-spend") {
          out.value = res.nullifier;
          status.textContent = "Double-spend blocked. That nullifier is already on the ledger, so this note has already been spent — the ledger does not need to know which note it was, who spent it, or what it bought to know it cannot be spent twice.";
          return;
        }
        noteSpent = res.seen;
        out.value = res.nullifier;
        noteLedgerStatus();
        status.textContent = "Spent. The nullifier above is now public and can never be used again — that is what stops the double-spend. An observer sees this nullifier and, from creation, the note's commitment, but cannot link the two from the hashes alone: linking them means finding the secret behind either hash. What does leak: that a note was spent, and when.";
      });
    });

    /* --- split with a safety net — Shamir k-of-n --- */
    document.getElementById("shamir-make").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var out = document.getElementById("shamir-out");
      var status = document.getElementById("shamir-result");
      var threshold = Number(document.getElementById("shamir-threshold").value);
      var count = Number(document.getElementById("shamir-count").value);
      var res = splitThresholdSecret(document.getElementById("shamir-secret").value, threshold, count);
      if (!res) {
        out.value = "";
        status.textContent = "Enter a throwaway secret (up to " + SHARE_MAX_SECRET_CHARS +
          " characters), a threshold of at least " + SHAMIR_MIN_THRESHOLD + ", and a share " +
          "count between the threshold and " + SHAMIR_MAX_COUNT + ". Never a real seed phrase — see the warning above.";
        return;
      }
      out.value = res.shares.join("\n");
      status.textContent = "Split locally into " + res.count + " shares — your secret never " +
        "left this page. Any " + res.threshold + " of them rebuild it; " + (res.threshold - 1) +
        " or fewer reveal nothing about its content. You can lose up to " + (res.count - res.threshold) +
        " share" + (res.count - res.threshold === 1 ? "" : "s") + " and still recover it — the " +
        "safety net tool 13's all-of-n split does not have. Hand the shares out separately, and " +
        "remember there is no checksum: a mistyped share rebuilds a wrong secret silently, so " +
        "copy shares exactly.";
    });
    document.getElementById("shamir-join").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var out = document.getElementById("shamir-join-out");
      var status = document.getElementById("shamir-join-result");
      var secret = combineThresholdShares(document.getElementById("shamir-join-in").value);
      if (secret === null) {
        out.value = "";
        status.textContent = "That set does not rebuild: paste at least the threshold number of " +
          "shares from ONE split, one per line — no duplicates, no shares mixed in from another " +
          "split. Fewer than the threshold reveal nothing at all, by design, so there is no " +
          "partial recovery and no best guess. A set that is big enough but contains a wrong or " +
          "mistyped share rebuilds a wrong secret — if the result looks like gibberish, check " +
          "each share character for character.";
        return;
      }
      out.value = secret;
      status.textContent = "Rebuilt locally — the shares you pasted interpolate back to the exact " +
        "secret, character for character. Nothing left this page. Read it carefully before trusting " +
        "it: this scheme has no checksum, so if one share was wrong the rebuilt text would be wrong " +
        "too, with no error shown.";
    });

    /* --- seal it so only they can read it — AES-GCM --- */
    document.getElementById("seal-make").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var out = document.getElementById("seal-out");
      var status = document.getElementById("seal-result");
      status.textContent = "Sealing locally…";
      sealMessage(document.getElementById("seal-message").value,
        document.getElementById("seal-password").value).then(function (sealed) {
        if (!sealed) {
          out.value = "";
          status.textContent = "Enter a throwaway message (up to " + SEAL_MAX_MESSAGE_CHARS +
            " characters) and a password that is not blank. Never a real seed phrase — see the warning above.";
          return;
        }
        out.value = sealed;
        status.textContent = "Sealed locally — your message and password never left this page. " +
          "The sealed text is safe to share on its own: it can only be opened with the password, " +
          "so send the password by a different channel. Anyone with both can read it, a weak " +
          "password can still be guessed offline (tool 11 measures that), and the sealed text's " +
          "length hints at the message's length.";
      });
    });
    document.getElementById("seal-open").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var out = document.getElementById("open-out");
      var status = document.getElementById("open-result");
      status.textContent = "Opening locally…";
      unsealMessage(document.getElementById("open-sealed").value,
        document.getElementById("open-password").value).then(function (msg) {
        if (msg === null) {
          out.value = "";
          status.textContent = "That does not open: the password is wrong, or the sealed text " +
            "was changed or pasted incompletely. AES-GCM checks integrity as it decrypts, so a " +
            "wrong password and a tampered message fail the same way — it never returns gibberish " +
            "for you to guess at. Check the password and paste the whole sealed line.";
          return;
        }
        out.value = msg;
        status.textContent = "Opened locally — exactly the message that was sealed, character " +
          "for character. Nothing left this page.";
      });
    });

    /* --- copy donation address --- */
    document.getElementById("copy-address").addEventListener("click", function () {
      var addr = document.getElementById("donation-address").textContent.trim();
      var done = function () { document.getElementById("copy-status").textContent = "ADA address copied."; };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(addr).then(done, function () {
          document.getElementById("copy-status").textContent = "Copy failed — select the address text manually.";
        });
      } else {
        document.getElementById("copy-status").textContent = "Select the address text to copy it.";
      }
    });
  });
}
