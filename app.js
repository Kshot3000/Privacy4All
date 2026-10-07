"use strict";
/* Privacy4All hub logic: project filtering, a local text redactor,
   a selective-disclosure planner, a NIGHT -> DUST capacity estimator,
   a "what does this dApp see?" permission explainer, a ZK claim
   simulator, a Compact snippet library, a DUST lifecycle explainer,
   a SHA-256 hash commitment maker/checker, a public-vs-shielded
   ledger observer explainer, and a viewing-key scope simulator.
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

if (typeof module !== "undefined" && module.exports) {
  module.exports = { redactText, planDisclosure, dustCapacity, FIELD_CATALOG, DUST_PER_NIGHT_MAX,
                     assessDappPermissions, PERMISSION_CATALOG,
                     evaluateProof, CLAIM_CATALOG,
                     getSnippet, searchSnippets, SNIPPET_CATALOG,
                     simulateDustLifecycle,
                     COMMIT_PREFIX, commitmentMessage, sha256Hex, makeCommitment, verifyCommitment,
                     getObserverView, OBSERVER_CATALOG,
                     getViewingView, VIEWING_CATALOG };
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
