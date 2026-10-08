"use strict";
/* Privacy4All hub logic: project filtering, a local text redactor,
   a selective-disclosure planner, a NIGHT -> DUST capacity estimator,
   a "what does this dApp see?" permission explainer, a ZK claim
   simulator, a Compact snippet library, a DUST lifecycle explainer,
   a SHA-256 hash commitment maker/checker, a public-vs-shielded
   ledger observer explainer, a viewing-key scope simulator, a
   commitment secret-strength checker with a random salt generator,
   a password-sealed (AES-GCM) message tool, and an ECDSA (P-256)
   message-signing tool.
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

/* ---------- 17. Sign it — prove it came from you ---------- */
/* Encryption (tool 16) hides a message; a SIGNATURE does the
   opposite job: the message stays public, but anyone can check
   that whoever holds one private key endorsed exactly these
   words, and that not one character changed since. This tool
   generates a real ECDSA key pair on the P-256 curve (the curve
   behind passkeys/WebAuthn; Bitcoin and Ethereum use its sibling
   secp256k1, which Web Crypto does not offer), signs locally
   with ECDSA over SHA-256, and handles keys as hex: the public
   key is the 91-byte SPKI encoding, the private key the 138-byte
   PKCS#8 encoding, and a signature is 64 bytes (r || s) in one
   versioned line: p4a-sig-v1:<sigHex>. The public key is safe to
   publish — it is how people recognise "you". The private key IS
   the identity: anyone holding it can sign as you, with no
   recovery and no undo. Honest limits: a signature does NOT hide
   the message, does NOT prove a legal name or real-world
   identity, and does NOT prove when the signing happened. Keys
   exist only in this page: nothing is stored or sent, and
   reloading loses the private key unless you saved it — and a
   saved private key is a secret to guard exactly like a seed
   phrase. Teaching implementation, not an audited wallet. Never
   paste a real wallet's private key into any web page, including
   this one — practise with throwaway keys. */
var SIGN_FORMAT = "p4a-sig-v1";
var SIGN_MAX_MESSAGE_CHARS = 2000;
var SIGN_PUBLIC_KEY_BYTES = 91;   /* SPKI encoding of a P-256 public key */
var SIGN_PRIVATE_KEY_BYTES = 138; /* PKCS#8 encoding of a P-256 private key */
var SIGN_SIGNATURE_BYTES = 64;    /* ECDSA P-256 raw signature, r || s */

function signCrypto() {
  var c = (typeof globalThis !== "undefined" && globalThis.crypto) || null;
  return (c && c.subtle && typeof c.subtle.generateKey === "function") ? c : null;
}

function parseKeyHex(text, expectedBytes) {
  if (typeof text !== "string") return null;
  var bytes = hexToBytes(text.trim().toLowerCase());
  if (!bytes || bytes.length !== expectedBytes) return null;
  return bytes;
}

function parseSignature(text) {
  if (typeof text !== "string") return null;
  var m = text.trim().toLowerCase().match(/^p4a-sig-v1:([0-9a-f]+)$/);
  if (!m) return null;
  var sig = hexToBytes(m[1]);
  if (!sig || sig.length !== SIGN_SIGNATURE_BYTES) return null;
  return { signature: sig };
}

function generateSigningKeyPair() {
  var cryptoObj = signCrypto();
  if (!cryptoObj) return Promise.resolve(null);
  return cryptoObj.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])
    .then(function (pair) {
      return Promise.all([
        cryptoObj.subtle.exportKey("spki", pair.publicKey),
        cryptoObj.subtle.exportKey("pkcs8", pair.privateKey)
      ]).then(function (keys) {
        return { publicKey: shareBytesToHex(new Uint8Array(keys[0])),
                 privateKey: shareBytesToHex(new Uint8Array(keys[1])) };
      }, function () { return null; });
    }, function () { return null; });
}

function importSigningKey(hex, expectedBytes, format, usages) {
  var bytes = parseKeyHex(hex, expectedBytes);
  if (!bytes) return Promise.resolve(null);
  var cryptoObj = signCrypto();
  if (!cryptoObj) return Promise.resolve(null);
  return cryptoObj.subtle.importKey(
    format, bytes, { name: "ECDSA", namedCurve: "P-256" }, true, usages)
    .then(function (key) { return key; }, function () { return null; });
}

function validSignMessage(message) {
  return typeof message === "string" && message.trim() !== "" &&
    message.length <= SIGN_MAX_MESSAGE_CHARS;
}

function signMessage(privateKeyHex, message) {
  if (!validSignMessage(message)) return Promise.resolve(null);
  return importSigningKey(privateKeyHex, SIGN_PRIVATE_KEY_BYTES, "pkcs8", ["sign"])
    .then(function (key) {
      if (!key) return null;
      var cryptoObj = signCrypto();
      return cryptoObj.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" }, key, secretToBytes(message))
        .then(function (sig) {
          return SIGN_FORMAT + ":" + shareBytesToHex(new Uint8Array(sig));
        }, function () { return null; });
    });
}

/* true = this exact message, signed by this key. false = well-formed
   inputs, but the signature does not match. null = malformed input
   (bad key, bad signature format, blank message) — distinct from a
   failed check, the same convention as tools 8 and 16. */
function verifySignature(publicKeyHex, message, signatureText) {
  var parsed = parseSignature(signatureText);
  if (!parsed) return Promise.resolve(null);
  if (!validSignMessage(message)) return Promise.resolve(null);
  return importSigningKey(publicKeyHex, SIGN_PUBLIC_KEY_BYTES, "spki", ["verify"])
    .then(function (key) {
      if (!key) return null;
      var cryptoObj = signCrypto();
      return cryptoObj.subtle.verify(
        { name: "ECDSA", hash: "SHA-256" }, key, parsed.signature, secretToBytes(message))
        .then(function (ok) { return ok === true; }, function () { return null; });
    });
}

/* ---------- 18. Agree on a secret nobody saw — key agreement ---------- */
/* Tool 16 needs a shared password and tool 17 proves who holds a
   key — but how do two people who have never met get a secret
   they BOTH know and nobody else does, over a channel everyone
   can read? Key agreement: each side generates an ECDH key pair
   on the P-256 curve, they exchange ONLY the public keys, and
   each side combines its own private key with the other's public
   key. The maths lands both sides on the same 32-byte shared
   secret — a value that is never exchanged, never sent, and
   cannot be worked out from the two public keys alone. That is
   the handshake underneath private messaging (my Night Messenger
   included, in spirit). Honest limits: the raw shared secret is
   an input to a key-derivation function, never a key to use
   directly — real systems hash it with context into session keys.
   Agreement alone does NOT prove who the other public key belongs
   to: an attacker in the middle who swaps both public keys gets
   two agreements, one with each side, and can relay and read —
   which is why real messengers let you compare a fingerprint of
   the secret (or of the keys) over a channel you trust. Displayed
   here only so both sides can be practised on one page: in a real
   app the secret is never shown. Teaching implementation, not an
   audited messaging app. Keys exist only in this page; never paste
   a real wallet's private key into any web page, including this
   one — practise with throwaway keys. */
var AGREE_PUBLIC_KEY_BYTES = 91;   /* SPKI encoding of a P-256 public key */
var AGREE_PRIVATE_KEY_BYTES = 138; /* PKCS#8 encoding of a P-256 private key */
var AGREE_SHARED_SECRET_BYTES = 32;
var AGREE_FINGERPRINT_PREFIX = "p4a-ecdh-fingerprint-v1";

function agreeCrypto() {
  var c = (typeof globalThis !== "undefined" && globalThis.crypto) || null;
  return (c && c.subtle && typeof c.subtle.generateKey === "function") ? c : null;
}

function generateAgreementKeyPair() {
  var cryptoObj = agreeCrypto();
  if (!cryptoObj) return Promise.resolve(null);
  return cryptoObj.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"])
    .then(function (pair) {
      return Promise.all([
        cryptoObj.subtle.exportKey("spki", pair.publicKey),
        cryptoObj.subtle.exportKey("pkcs8", pair.privateKey)
      ]).then(function (keys) {
        return { publicKey: shareBytesToHex(new Uint8Array(keys[0])),
                 privateKey: shareBytesToHex(new Uint8Array(keys[1])) };
      }, function () { return null; });
    }, function () { return null; });
}

function importAgreementKey(hex, expectedBytes, format, usages) {
  var bytes = parseKeyHex(hex, expectedBytes);
  if (!bytes) return Promise.resolve(null);
  var cryptoObj = agreeCrypto();
  if (!cryptoObj) return Promise.resolve(null);
  return cryptoObj.subtle.importKey(
    format, bytes, { name: "ECDH", namedCurve: "P-256" }, true, usages)
    .then(function (key) { return key; }, function () { return null; });
}

/* Both directions of an agreement land on the same secret:
   deriveSharedSecret(myPriv, theirPub) ===
   deriveSharedSecret(theirPriv, myPub). Anything malformed —
   wrong key size, junk hex, a public key offered as a private
   key — is null, never a wrong-but-plausible secret. */
function deriveSharedSecret(privateKeyHex, peerPublicKeyHex) {
  return importAgreementKey(privateKeyHex, AGREE_PRIVATE_KEY_BYTES, "pkcs8", ["deriveBits"])
    .then(function (priv) {
      if (!priv) return null;
      return importAgreementKey(peerPublicKeyHex, AGREE_PUBLIC_KEY_BYTES, "spki", [])
        .then(function (pub) {
          if (!pub) return null;
          var cryptoObj = agreeCrypto();
          return cryptoObj.subtle.deriveBits(
            { name: "ECDH", public: pub }, priv, AGREE_SHARED_SECRET_BYTES * 8)
            .then(function (bits) {
              var bytes = new Uint8Array(bits);
              if (bytes.length !== AGREE_SHARED_SECRET_BYTES) return null;
              return shareBytesToHex(bytes);
            }, function () { return null; });
        });
    });
}

function parseSharedSecret(text) {
  if (typeof text !== "string") return null;
  var hex = text.trim().toLowerCase();
  if (!/^[0-9a-f]+$/.test(hex)) return null;
  var bytes = hexToBytes(hex);
  if (!bytes || bytes.length !== AGREE_SHARED_SECRET_BYTES) return null;
  return hex;
}

/* A short public check value for a shared secret: safe to compare
   out loud or over another channel, because the fingerprint
   cannot be reversed into the secret. */
function sharedSecretFingerprint(secretHex) {
  var hex = parseSharedSecret(secretHex);
  if (hex === null) return Promise.resolve(null);
  return sha256Hex(AGREE_FINGERPRINT_PREFIX + "\n" + hex);
}

/* ---------- 19. Stretch one secret into proper keys — HKDF ---------- */
/* Tool 18 ends on a warning: the raw ECDH shared secret is never
   a key to use directly. This is the step that warning points
   at — KEY DERIVATION. HKDF (RFC 5869) over SHA-256 takes one
   input secret and stretches it into separate, independent
   32-byte keys, one per purpose: the purpose label is mixed in
   as HKDF's info string, so the messaging key, the storage key
   and the backup key from the same secret share nothing usable —
   leaking one reveals nothing about the others or the secret.
   An optional 16-byte salt (tool 11's generator makes them) is
   mixed in as HKDF's salt: same secret and purpose with a
   different salt is a different key again, which is how separate
   sessions stay separate. The salt is NOT a secret — both sides
   must simply agree on the same purpose and the same salt, and
   they may exchange the salt openly. Keys are plain 32-byte hex.
   Honest limits: derivation does not strengthen a weak input —
   a guessable secret derives guessable keys, because an attacker
   can run the same public derivation (tool 11 measures input
   strength; there is no password stretching here, by design —
   HKDF assumes its input is already high-entropy key material,
   like tool 18's output). Knowing a derived key does not let
   anyone work backwards to the secret or sideways to another
   purpose's key. Teaching implementation, not an audited
   key-management product. Never paste a real seed phrase or
   production secret into any web page, including this one —
   practise with throwaway secrets. */
var DERIVE_KEY_BYTES = 32;
var DERIVE_SALT_BYTES = 16;
var DERIVE_SECRET_MIN_BYTES = 16;
var DERIVE_SECRET_MAX_BYTES = 64;
var DERIVE_PURPOSE_CATALOG = {
  "messaging": { label: "Messaging — encrypt the conversation",
                 info: "privacy4all-hkdf-v1 messaging",
                 note: "Use this key for the conversation, and nothing else. The storage and backup keys derived from the same secret are unrelated keys, so leaking this one exposes neither them nor the secret." },
  "storage": { label: "Local storage — encrypt data at rest",
               info: "privacy4all-hkdf-v1 storage",
               note: "Use this key for data stored on the device, and nothing else. It is not the messaging key: a copy of stored data plus this key still does not open the conversation." },
  "backup": { label: "Backup — encrypt an exported backup",
              info: "privacy4all-hkdf-v1 backup",
              note: "Use this key for one exported backup, and nothing else. Rotate the salt for the next backup and it gets a fresh, unrelated key from the same secret." }
};

function getDerivePurpose(id) {
  if (typeof id !== "string") return null;
  return Object.prototype.hasOwnProperty.call(DERIVE_PURPOSE_CATALOG, id)
    ? DERIVE_PURPOSE_CATALOG[id] : null;
}

function parseDeriveSecret(text) {
  if (typeof text !== "string") return null;
  var hex = text.trim().toLowerCase();
  var bytes = hexToBytes(hex);
  if (!bytes || bytes.length < DERIVE_SECRET_MIN_BYTES ||
      bytes.length > DERIVE_SECRET_MAX_BYTES) return null;
  return hex;
}

/* Blank salt is valid and means "no salt" (HKDF then uses zeros,
   per RFC 5869). A given salt must be exactly 16 bytes of hex —
   the size tool 11's generator makes. Anything else is null. */
function parseDeriveSalt(text) {
  if (typeof text !== "string") return null;
  var hex = text.trim().toLowerCase();
  if (hex === "") return new Uint8Array(0);
  var bytes = hexToBytes(hex);
  if (!bytes || bytes.length !== DERIVE_SALT_BYTES) return null;
  return bytes;
}

function parseDerivedKey(text) {
  if (typeof text !== "string") return null;
  var hex = text.trim().toLowerCase();
  var bytes = hexToBytes(hex);
  if (!bytes || bytes.length !== DERIVE_KEY_BYTES) return null;
  return hex;
}

function deriveSessionKey(secretHex, purposeId, saltText) {
  var hex = parseDeriveSecret(secretHex);
  var purpose = getDerivePurpose(purposeId);
  var salt = parseDeriveSalt(saltText === undefined || saltText === null ? "" : saltText);
  if (hex === null || !purpose || salt === null) return Promise.resolve(null);
  var cryptoObj = agreeCrypto();
  if (!cryptoObj) return Promise.resolve(null);
  return cryptoObj.subtle.importKey("raw", hexToBytes(hex), "HKDF", false, ["deriveBits"])
    .then(function (base) {
      return cryptoObj.subtle.deriveBits(
        { name: "HKDF", hash: "SHA-256", salt: salt,
          info: secretToBytes(purpose.info) },
        base, DERIVE_KEY_BYTES * 8)
        .then(function (bits) {
          var bytes = new Uint8Array(bits);
          if (bytes.length !== DERIVE_KEY_BYTES) return null;
          return shareBytesToHex(bytes);
        }, function () { return null; });
    }, function () { return null; });
}

/* true = this key is exactly what those inputs derive.
   false = well-formed inputs, but a different key. null =
   malformed input — distinct from a failed check. */
function checkDerivedKey(secretHex, purposeId, saltText, keyText) {
  var expected = parseDerivedKey(keyText);
  if (expected === null) return Promise.resolve(null);
  return deriveSessionKey(secretHex, purposeId, saltText)
    .then(function (derived) {
      if (derived === null) return null;
      return derived === expected;
    });
}

/* ---------- 20. Use the key — lock a message with a derived key ---------- */
/* Tools 18 and 19 end with a key nobody has used yet. This is
   where it gets used: the 32-byte key tool 19 derived (the
   "messaging" purpose is the one meant for this) imports
   directly as an AES-GCM key — no password, no stretching and
   no salt, because the key is already high-entropy key
   material, which is exactly what HKDF was for. Encryption is
   real AES-GCM locally via Web Crypto with a fresh random
   12-byte IV per message, in one versioned line:
   p4a-keysealed-v1:<ivHex>:<cipherHex>. The GCM tag rides at
   the end of the ciphertext, so a wrong key, a tampered byte
   or a truncated seal fails outright, never gibberish — and
   there is deliberately no password fallback: holding the key
   is the whole credential, so whoever the key leaks to reads
   everything sealed with it, and sealed length still leaks
   the message's approximate length. Contrast tool 16: that
   one starts from a human password and must stretch it
   (PBKDF2, salt in the seal) before it is key material; this
   one starts from tool 19's output and must not re-stretch
   what is already a key. Honest limits: teaching
   implementation, not an audited messaging app — real
   messengers add ratcheting, message numbering and key
   erasure on top of this shape. Keys exist only in this page:
   nothing is stored or sent. Never paste a real wallet key
   or a production session key into any web page, including
   this one — practise with throwaway keys from tools 18–19. */
var KEYSEAL_FORMAT = "p4a-keysealed-v1";
var KEYSEAL_KEY_BYTES = 32;
var KEYSEAL_IV_BYTES = 12;
var KEYSEAL_MAX_MESSAGE_CHARS = 2000;

function parseKeySealed(text) {
  if (typeof text !== "string") return null;
  var m = text.trim().toLowerCase().match(/^p4a-keysealed-v1:([0-9a-f]+):([0-9a-f]+)$/);
  if (!m) return null;
  var iv = hexToBytes(m[1]);
  var cipher = hexToBytes(m[2]);
  if (!iv || !cipher) return null;
  if (iv.length !== KEYSEAL_IV_BYTES) return null;
  /* GCM tag is 16 bytes, so ciphertext is at least 1 byte + tag. */
  if (cipher.length < 17) return null;
  return { iv: iv, cipher: cipher };
}

function importSessionKey(keyText) {
  var hex = parseDerivedKey(keyText);
  if (hex === null) return Promise.resolve(null);
  /* A derived key is exactly KEYSEAL_KEY_BYTES long by
     construction (tool 19); keep the two constants pinned. */
  if (hexToBytes(hex).length !== KEYSEAL_KEY_BYTES) return Promise.resolve(null);
  var cryptoObj = agreeCrypto();
  if (!cryptoObj) return Promise.resolve(null);
  return cryptoObj.subtle.importKey("raw", hexToBytes(hex),
    { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"])
    .then(function (key) { return key; }, function () { return null; });
}

function validKeySealMessage(message) {
  return typeof message === "string" && message.trim() !== "" &&
    message.length <= KEYSEAL_MAX_MESSAGE_CHARS;
}

function sealWithSessionKey(message, keyText) {
  if (!validKeySealMessage(message)) return Promise.resolve(null);
  var cryptoObj = (typeof globalThis !== "undefined" && globalThis.crypto) || null;
  if (!cryptoObj || typeof cryptoObj.getRandomValues !== "function" || !cryptoObj.subtle) {
    return Promise.resolve(null);
  }
  var iv = new Uint8Array(KEYSEAL_IV_BYTES);
  cryptoObj.getRandomValues(iv);
  return importSessionKey(keyText).then(function (key) {
    if (!key) return null;
    return cryptoObj.subtle.encrypt({ name: "AES-GCM", iv: iv }, key, secretToBytes(message))
      .then(function (buf) {
        return KEYSEAL_FORMAT + ":" + shareBytesToHex(iv) +
          ":" + shareBytesToHex(new Uint8Array(buf));
      }, function () { return null; });
  });
}

function openWithSessionKey(sealed, keyText) {
  var parsed = parseKeySealed(sealed);
  if (!parsed) return Promise.resolve(null);
  var cryptoObj = (typeof globalThis !== "undefined" && globalThis.crypto) || null;
  if (!cryptoObj || !cryptoObj.subtle) return Promise.resolve(null);
  return importSessionKey(keyText).then(function (key) {
    if (!key) return null;
    return cryptoObj.subtle.decrypt({ name: "AES-GCM", iv: parsed.iv }, key, parsed.cipher)
      .then(function (buf) {
        var msg = bytesToSecret(new Uint8Array(buf));
        if (msg === null || msg.trim() === "") return null;
        if (msg.length > KEYSEAL_MAX_MESSAGE_CHARS) return null;
        return msg;
      }, function () { return null; /* wrong key or tampered — GCM refuses */ });
  });
}

/* ---------- 21. Know it's really from them — sign it, then seal it ---------- */
/* Tool 20's seal proves one thing only: whoever opened the
   message holds the same session key as whoever locked it. It
   does NOT prove which person locked it — anyone who holds the
   shared session key can seal a message in anyone's name, and
   the opener cannot tell the difference. AES-GCM proves the
   key, not the person. This tool closes that gap the way real
   messengers do: sign first, then seal. The sender signs the
   message with their tool-17 signing key, and the signature
   rides INSIDE the seal next to the message, as a small
   versioned JSON envelope (p4a-signed-v1). The opener opens the
   seal, then checks the signature against the sender's public
   key. The two results stay separate on purpose: a message can
   open perfectly and still fail the signature check — private,
   but not from who it claims to be from — and that case returns
   the message with verified === false instead of hiding it, so
   the distinction is visible rather than papered over.
   Malformed input is null, distinct from a failed check, the
   same convention as the rest of the suite: a bad session key,
   a tampered seal, an envelope that is not a signed envelope at
   all (a plain tool-20 seal included), or a malformed sender
   public key. The outer line gets its own version,
   p4a-authsealed-v1, so the two seal formats can never be
   mistaken for each other. Honest limits: teaching
   implementation, not an audited messaging app — the signature
   proves the signing key, not a legal name (tool 17's limit,
   unchanged), and it only means anything if the public key
   really is the sender's, which has to be established outside
   this page (compare it where a swap would be visible, the
   tool-18 fingerprint lesson). Keys exist only in this page;
   never paste a real wallet's private key into any web page,
   including this one — practise with throwaway keys. */
var AUTHSEAL_FORMAT = "p4a-authsealed-v1";
var AUTHSEAL_ENVELOPE_FORMAT = "p4a-signed-v1";
/* The message plus its signature plus the envelope's JSON must
   fit inside tool 20's 2000-char seal, so the message itself
   caps lower here. */
var AUTHSEAL_MAX_MESSAGE_CHARS = 1800;

function parseAuthSealed(text) {
  if (typeof text !== "string") return null;
  var m = text.trim().toLowerCase().match(/^p4a-authsealed-v1:([0-9a-f]+):([0-9a-f]+)$/);
  if (!m) return null;
  var iv = hexToBytes(m[1]);
  var cipher = hexToBytes(m[2]);
  if (!iv || !cipher) return null;
  if (iv.length !== KEYSEAL_IV_BYTES) return null;
  if (cipher.length < 17) return null;
  return { iv: iv, cipher: cipher };
}

function validAuthMessage(message) {
  return typeof message === "string" && message.trim() !== "" &&
    message.length <= AUTHSEAL_MAX_MESSAGE_CHARS;
}

function parseSignedEnvelope(text) {
  if (typeof text !== "string") return null;
  var env;
  try { env = JSON.parse(text); } catch (e) { return null; }
  if (!env || typeof env !== "object") return null;
  if (env.format !== AUTHSEAL_ENVELOPE_FORMAT) return null;
  if (!validAuthMessage(env.message)) return null;
  if (!parseSignature(env.signature)) return null;
  return { message: env.message, signature: env.signature };
}

function signAndSealMessage(privateKeyHex, message, keyText) {
  if (!validAuthMessage(message)) return Promise.resolve(null);
  return signMessage(privateKeyHex, message).then(function (sig) {
    if (!sig) return null;
    var inner = JSON.stringify({ format: AUTHSEAL_ENVELOPE_FORMAT,
                                 message: message, signature: sig });
    if (inner.length > KEYSEAL_MAX_MESSAGE_CHARS) return null;
    return sealWithSessionKey(inner, keyText).then(function (sealed) {
      if (!sealed) return null;
      return AUTHSEAL_FORMAT + sealed.slice(KEYSEAL_FORMAT.length);
    });
  });
}

/* Returns { message, verified } for a well-formed authenticated
   seal: verified is true only when the signature inside checks
   out against senderPublicKeyHex. A message that opens but was
   signed by a different key comes back with verified === false
   and its text intact — read it, but not as theirs. Anything
   malformed, tampered or locked with another key is null. */
function openAuthenticatedMessage(sealed, keyText, senderPublicKeyHex) {
  var parsed = parseAuthSealed(sealed);
  if (!parsed) return Promise.resolve(null);
  var asKeySealed = KEYSEAL_FORMAT + ":" + shareBytesToHex(parsed.iv) +
    ":" + shareBytesToHex(parsed.cipher);
  return openWithSessionKey(asKeySealed, keyText).then(function (inner) {
    if (inner === null) return null;
    var env = parseSignedEnvelope(inner);
    if (!env) return null;
    return verifySignature(senderPublicKeyHex, env.message, env.signature)
      .then(function (ok) {
        if (ok === null) return null;
        return { message: env.message, verified: ok };
      });
  });
}

/* ---------- 22. One key per message — the ratchet ---------- */
/* Tool 20 ends with a warning worth acting on: its one session
   key locks every message, so whoever the key leaks to reads
   everything locked with it, past and future. Real messengers
   answer that with a ratchet: the key moves after every single
   message, and this tool builds the simple symmetric version.
   A chain state (p4a-chain-v1:<index>:<chainKeyHex>) holds a
   position counter and one 32-byte chain key — at position 0
   the chain key IS the tool-19 session key. Each step runs
   HKDF-SHA-256 twice over the chain key with two different
   info strings: one output is this message's own key (used
   once, through tool 20's exact seal), the other is the next
   chain key. HKDF is one-way, so the step cannot be run
   backwards: from a later chain state there is no way to
   recompute an earlier message key, which is the whole point —
   overwrite an old state and the messages it opened are gone
   for good, even to someone who later gets the current state.
   That is forward secrecy for the past. The honest limits are
   just as much the lesson: the chain is symmetric, so it
   protects the past only — a leaked current state opens every
   message after it until both sides run tools 18–19 again and
   start a fresh chain; messages open strictly in order (this
   simple chain has no store for skipped message keys, which
   real messengers add); each direction needs its own chain
   (start the reply chain from a different tool-19 purpose or
   salt, or the two directions' keys collide); and a chain is
   capped at RATCHET_MAX_INDEX messages and then refuses,
   rather than run unbounded. A failed open advances nothing:
   the caller's state is untouched, so an out-of-order message
   can simply be retried once the missing one arrives. Honest
   label: teaching implementation, not an audited messaging
   app. States and keys exist only in this page; never paste a
   real wallet key or a production session key into any web
   page, including this one — practise with throwaway keys
   from tools 18–19. */
var RATCHET_STATE_FORMAT = "p4a-chain-v1";
var RATCHET_MSG_INFO = "privacy4all-ratchet-v1 message";
var RATCHET_NEXT_INFO = "privacy4all-ratchet-v1 next";
var RATCHET_MAX_INDEX = 1000000;

function ratchetHkdf(chainKeyHex, info) {
  var cryptoObj = agreeCrypto();
  if (!cryptoObj) return Promise.resolve(null);
  return cryptoObj.subtle.importKey("raw", hexToBytes(chainKeyHex), "HKDF", false, ["deriveBits"])
    .then(function (base) {
      return cryptoObj.subtle.deriveBits(
        { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0),
          info: secretToBytes(info) },
        base, DERIVE_KEY_BYTES * 8)
        .then(function (bits) {
          var bytes = new Uint8Array(bits);
          if (bytes.length !== DERIVE_KEY_BYTES) return null;
          return shareBytesToHex(bytes);
        }, function () { return null; });
    }, function () { return null; });
}

/* One ratchet step: this message's own key, and the next chain
   key. Deterministic — both sides step identically from the
   same state — and domain-separated, so a message key is never
   also a chain key. Malformed chain key is null. */
function ratchetStep(chainKeyText) {
  var hex = parseDerivedKey(chainKeyText);
  if (hex === null) return Promise.resolve(null);
  return ratchetHkdf(hex, RATCHET_MSG_INFO).then(function (messageKey) {
    if (messageKey === null) return null;
    return ratchetHkdf(hex, RATCHET_NEXT_INFO).then(function (nextChainKey) {
      if (nextChainKey === null) return null;
      return { messageKey: messageKey, nextChainKey: nextChainKey };
    });
  });
}

function formatChainState(index, chainKeyText) {
  var hex = parseDerivedKey(chainKeyText);
  if (hex === null) return null;
  if (typeof index !== "number" || !isFinite(index) ||
      Math.floor(index) !== index || index < 0 || index > RATCHET_MAX_INDEX) return null;
  return RATCHET_STATE_FORMAT + ":" + index + ":" + hex;
}

function parseChainState(text) {
  if (typeof text !== "string") return null;
  var m = text.trim().toLowerCase().match(/^p4a-chain-v1:([0-9]+):([0-9a-f]+)$/);
  if (!m) return null;
  var index = Number(m[1]);
  if (!isFinite(index) || index > RATCHET_MAX_INDEX) return null;
  /* One spelling per state: "007" is not position 7. */
  if (String(index) !== m[1]) return null;
  var hex = parseDerivedKey(m[2]);
  if (hex === null) return null;
  return { index: index, chainKey: hex };
}

/* A chain starts at position 0 with the session key itself as
   the first chain key — which is why the key must be fresh per
   conversation (tools 18–19), never reused across chains. */
function startChainState(sessionKeyText) {
  return formatChainState(0, sessionKeyText);
}

/* Returns { sealed, state }: the message sealed under this
   position's own key (exactly tool 20's line), and the next
   state to keep. The state that was passed in is spent. */
function sealRatchetMessage(stateText, message) {
  var state = parseChainState(stateText);
  if (state === null || !validKeySealMessage(message)) return Promise.resolve(null);
  return ratchetStep(state.chainKey).then(function (step) {
    if (step === null) return null;
    var next = formatChainState(state.index + 1, step.nextChainKey);
    if (next === null) return null;
    return sealWithSessionKey(message, step.messageKey).then(function (sealed) {
      if (sealed === null) return null;
      return { sealed: sealed, state: next };
    });
  });
}

/* Returns { message, state } on success. Anything else — a
   message from a later position, a replay of an earlier one, a
   tampered seal, the wrong chain — is null, and the caller's
   state has NOT advanced, so the message can be retried when
   its turn comes. */
function openRatchetMessage(stateText, sealed) {
  var state = parseChainState(stateText);
  if (state === null || parseKeySealed(sealed) === null) return Promise.resolve(null);
  return ratchetStep(state.chainKey).then(function (step) {
    if (step === null) return null;
    var next = formatChainState(state.index + 1, step.nextChainKey);
    if (next === null) return null;
    return openWithSessionKey(sealed, step.messageKey).then(function (message) {
      if (message === null) return null;
      return { message: message, state: next };
    });
  });
}

/* ---------- 23. Heal the chain — a fresh agreement restarts the ratchet ---------- */
/* Tool 22 is honest about its own limit: the symmetric chain
   protects the past, but a leaked current state opens every
   message after it — until both sides agree fresh keys. Real
   messengers heal automatically with a second, asymmetric
   ratchet; this tool is that healing step, done by hand, in
   its simplest form. Both holders of one direction's chain
   make fresh tool-18 agreement pairs and swap the public keys
   openly (public keys need no secrecy — but they still need
   to really be each other's, which is tool 18's fingerprint
   lesson). Each side then runs ECDH to a fresh shared secret
   that only the two new private keys can produce, and mixes
   it with the chain key both sides already hold: HKDF with
   the fresh secret as the input keying material and the
   current chain key as the salt, under its own info label.
   The salt is what binds the heal to THIS chain: knowing
   only the leaked chain key is not enough (no fresh secret),
   and knowing only the fresh secret is not enough either
   (no chain key) — the healed key exists nowhere until the
   two ingredients meet on a holder's own device. That is
   post-compromise security for what comes next: someone
   holding the leaked state cannot follow the chain past the
   heal, because following takes a private key they never
   had. The healed state is a brand-new chain at position 0 —
   position restarts on purpose, because this is a new chain,
   not a continuation: pre-heal seals do not open under it
   (their keys are in the past the ratchet already erased),
   and post-heal seals do not open under the old state.
   Both sides must heal from exactly the same current state:
   healing is per direction-chain, and if the two copies of
   the state have diverged, the healed keys diverge too and
   seals simply fail — closed, never wrong-but-plausible.
   The honest limits are the other half of the lesson:
   healing protects only what comes after it — it does not
   unlock the past, resurrect deleted states, or help at all
   while a leak is still live on a compromised device; and
   one manual heal is a teaching simplification of a step
   real messengers run on every reply. Honest label: teaching
   implementation, not an audited messaging app. States and
   keys exist only in this page; never paste a real wallet
   key, a production session key or a live chain state into
   any web page, including this one — practise with
   throwaway keys from tools 18–19. */
var HEAL_INFO = "privacy4all-heal-v1 chain";

function healHkdf(secretHex, chainKeyHex) {
  var cryptoObj = agreeCrypto();
  if (!cryptoObj) return Promise.resolve(null);
  return cryptoObj.subtle.importKey("raw", hexToBytes(secretHex), "HKDF", false, ["deriveBits"])
    .then(function (base) {
      return cryptoObj.subtle.deriveBits(
        { name: "HKDF", hash: "SHA-256", salt: hexToBytes(chainKeyHex),
          info: secretToBytes(HEAL_INFO) },
        base, DERIVE_KEY_BYTES * 8)
        .then(function (bits) {
          var bytes = new Uint8Array(bits);
          if (bytes.length !== DERIVE_KEY_BYTES) return null;
          return shareBytesToHex(bytes);
        }, function () { return null; });
    }, function () { return null; });
}

/* Returns the healed chain state — a p4a-chain-v1 line at
   position 0 whose key neither side could have computed
   from the old state alone — or null for a malformed state
   or malformed/swapped keys. Both directions of the heal
   land on the same state: healChainState(S, myPriv, theirPub)
   === healChainState(S, theirPriv, myPub). */
function healChainState(stateText, privateKeyHex, peerPublicKeyHex) {
  var state = parseChainState(stateText);
  if (state === null) return Promise.resolve(null);
  return deriveSharedSecret(privateKeyHex, peerPublicKeyHex).then(function (fresh) {
    if (fresh === null) return null;
    return healHkdf(fresh, state.chainKey).then(function (healedKey) {
      if (healedKey === null) return null;
      return formatChainState(0, healedKey);
    });
  });
}

/* ---------- 24. Hide the length — pad it to one size before sealing ---------- */
/* Every seal in this suite is honest about the same leak:
   tools 13, 15, 16 and 20 all state it — the sealed text's
   length tracks the message's length, so anyone who can see
   the sealed text (a relay, a ledger watcher, a curious
   server) learns roughly how much was said, even though they
   cannot read a word. "Yes", a four-figure amount and a long
   confession seal to visibly different sizes. The standard
   fix is padding: before sealing, the message is extended
   to a fixed size, so every sealed text in a size class is
   exactly the same length and the watcher learns only which
   class, not the length. This tool pads at the byte level:
   an 8-byte header ("P4AP" magic plus the message's true
   byte length, big-endian) goes in front of the message's
   UTF-8 bytes, fresh random bytes from Web Crypto fill the
   rest, and the whole block — exactly one of the labelled
   bucket sizes — is sealed with AES-GCM under a tool-19
   session key in its own format, p4a-paddedseal-v1. The
   padding sits INSIDE the seal, so the GCM tag covers the
   filler too: tampering with it fails outright like any
   other tampering. Opening decrypts, checks the block is
   exactly a bucket with an intact header, reads exactly the
   labelled number of message bytes and ignores the rest.
   Bucket boundaries: a message whose bytes plus the header
   exactly fill a bucket stays in it; one byte more moves up
   to the next. Honest limits: padding hides length only
   inside a bucket — which bucket a message landed in still
   shows, timing and frequency are untouched, and a watcher
   who sees many messages can still learn plenty from the
   pattern; real messengers pad inside a ratcheted protocol
   with constant-rate cover traffic on top. Teaching
   implementation, not an audited messaging app. Keys and
   messages exist only in this page: nothing is stored or
   sent. Never paste a real wallet key or a production
   session key into any web page, including this one —
   practise with throwaway keys from tools 18–19. */
var PADDEDSEAL_FORMAT = "p4a-paddedseal-v1";
var PAD_MAGIC = "P4AP";
var PAD_HEADER_BYTES = 8;
var PAD_BUCKETS = [256, 1024, 4096, 16384];
var PAD_MAX_MESSAGE_BYTES = PAD_BUCKETS[PAD_BUCKETS.length - 1] - PAD_HEADER_BYTES;

/* The bucket a message of this many UTF-8 bytes is padded
   to — the smallest labelled bucket that fits the bytes
   plus the header — or null when it fits no bucket. */
function paddedBucketFor(byteLength) {
  if (typeof byteLength !== "number" || !Number.isInteger(byteLength) ||
      byteLength < 1) return null;
  for (var i = 0; i < PAD_BUCKETS.length; i++) {
    if (byteLength + PAD_HEADER_BYTES <= PAD_BUCKETS[i]) return PAD_BUCKETS[i];
  }
  return null;
}

/* The padded block itself: header, message bytes, random
   filler, exactly one bucket long — or null for a blank,
   non-string or over-cap message. Pure structure plus
   randomness: the same message pads differently every time,
   and that is the point. */
function buildPaddedPayload(message) {
  if (typeof message !== "string" || message.trim() === "") return null;
  var data = secretToBytes(message);
  var bucket = paddedBucketFor(data.length);
  if (bucket === null) return null;
  var cryptoObj = (typeof globalThis !== "undefined" && globalThis.crypto) || null;
  if (!cryptoObj || typeof cryptoObj.getRandomValues !== "function") return null;
  var payload = new Uint8Array(bucket);
  for (var i = 0; i < 4; i++) payload[i] = PAD_MAGIC.charCodeAt(i);
  payload[4] = (data.length >>> 24) & 0xff;
  payload[5] = (data.length >>> 16) & 0xff;
  payload[6] = (data.length >>> 8) & 0xff;
  payload[7] = data.length & 0xff;
  payload.set(data, PAD_HEADER_BYTES);
  if (bucket > PAD_HEADER_BYTES + data.length) {
    cryptoObj.getRandomValues(payload.subarray(PAD_HEADER_BYTES + data.length));
  }
  return payload;
}

/* Reads a padded block back: exactly one bucket long, magic
   intact, the labelled length in range, the message bytes
   valid UTF-8 and non-blank. The filler is never read —
   any bytes there extract the same message. Anything else
   is null, never a best guess. */
function extractPaddedMessage(payload) {
  if (!(payload instanceof Uint8Array)) return null;
  if (PAD_BUCKETS.indexOf(payload.length) === -1) return null;
  for (var i = 0; i < 4; i++) {
    if (payload[i] !== PAD_MAGIC.charCodeAt(i)) return null;
  }
  var len = payload[4] * 16777216 + payload[5] * 65536 +
    payload[6] * 256 + payload[7];
  if (len < 1 || PAD_HEADER_BYTES + len > payload.length) return null;
  var msg = bytesToSecret(payload.slice(PAD_HEADER_BYTES, PAD_HEADER_BYTES + len));
  if (msg === null || msg.trim() === "") return null;
  return msg;
}

function parsePaddedSealed(text) {
  if (typeof text !== "string") return null;
  var m = text.trim().toLowerCase().match(/^p4a-paddedseal-v1:([0-9a-f]+):([0-9a-f]+)$/);
  if (!m) return null;
  var iv = hexToBytes(m[1]);
  var cipher = hexToBytes(m[2]);
  if (!iv || !cipher) return null;
  if (iv.length !== KEYSEAL_IV_BYTES) return null;
  /* The ciphertext is one whole padded bucket plus the
     16-byte GCM tag — any other length was never padded. */
  if (PAD_BUCKETS.indexOf(cipher.length - 16) === -1) return null;
  return { iv: iv, cipher: cipher };
}

function sealPaddedMessage(message, keyText) {
  var payload = buildPaddedPayload(message);
  if (payload === null) return Promise.resolve(null);
  var cryptoObj = (typeof globalThis !== "undefined" && globalThis.crypto) || null;
  if (!cryptoObj || typeof cryptoObj.getRandomValues !== "function" || !cryptoObj.subtle) {
    return Promise.resolve(null);
  }
  var iv = new Uint8Array(KEYSEAL_IV_BYTES);
  cryptoObj.getRandomValues(iv);
  return importSessionKey(keyText).then(function (key) {
    if (!key) return null;
    return cryptoObj.subtle.encrypt({ name: "AES-GCM", iv: iv }, key, payload)
      .then(function (buf) {
        return PADDEDSEAL_FORMAT + ":" + shareBytesToHex(iv) +
          ":" + shareBytesToHex(new Uint8Array(buf));
      }, function () { return null; });
  });
}

function openPaddedMessage(sealed, keyText) {
  var parsed = parsePaddedSealed(sealed);
  if (!parsed) return Promise.resolve(null);
  var cryptoObj = (typeof globalThis !== "undefined" && globalThis.crypto) || null;
  if (!cryptoObj || !cryptoObj.subtle) return Promise.resolve(null);
  return importSessionKey(keyText).then(function (key) {
    if (!key) return null;
    return cryptoObj.subtle.decrypt({ name: "AES-GCM", iv: parsed.iv }, key, parsed.cipher)
      .then(function (buf) {
        return extractPaddedMessage(new Uint8Array(buf));
      }, function () { return null; /* wrong key or tampered — GCM refuses */ });
  });
}

/* ---------- 25. Out of order, still private — skipped message keys ---------- */
/* Tool 22 is honest about the limit this tool removes: its
   chain opens messages strictly in order, because it keeps
   no store for skipped message keys. Real networks do not
   deliver in order — a message is delayed, retried, routed
   another way — and real messengers (Signal's protocol is
   the famous one) answer with a skipped-key store. Two
   changes make it work here. First, the seal carries its
   position: p4a-oooseal-v1:<position>:<iv>:<cipher> is tool
   20's exact AES-GCM seal under that position's ratchet key,
   with the position it was sealed at written on the outside,
   so the receiver knows which key it needs before opening
   anything. Second, the receiver keeps a small store,
   p4a-skipped-v1, of message keys for positions the chain
   stepped past: when the message for position 5 arrives
   while the chain sits at 3, the chain steps forward,
   positions 3 and 4's message keys go into the store, 5
   opens now, and when 3 and 4 finally arrive their stored
   keys open them — each stored key is erased the moment it
   is used, so a late message opens exactly once and a replay
   of it finds no key and a chain that has already passed it:
   null, never a second opening. The store is bounded on
   purpose: at most SKIPPED_MAX_KEYS keys kept — and that cap
   is also the jump cap, because one open never steps more
   positions than the store could hold the skipped keys for.
   A bigger jump would mean stepping the chain thousands of
   times and warehousing keys for messages that may never
   arrive, which is exactly the denial-of-service shape real
   protocols cap for the same reason; a refusal changes
   nothing, so the message can be retried once the gap
   closes honestly. A store entry at or beyond the chain's
   current position can never be legitimate — the store and
   the state belong to different chains, or one of them is
   stale — so that pairing is refused outright rather than
   guessed at. Everything is atomic in the suite's usual
   way: inputs are never mutated, and a failed open returns
   null with no new state and no new store, so nothing is
   consumed by a message that did not open. Honest limits:
   every stored key is a past message's whole secret kept
   alive past its turn — forward secrecy for those positions
   is PAUSED, not held, until the late message arrives and
   the key is erased, and someone who copies the store reads
   exactly the messages it holds keys for; the position on
   the outside is metadata a watcher can see, like tool 24's
   bucket; and this is still the symmetric chain — tool 23's
   heal remains the answer to a leak. Honest label: teaching
   implementation, not an audited messaging app. States,
   stores and keys exist only in this page; never paste a
   real wallet key, a production session key or a live chain
   state into any web page, including this one — practise
   with throwaway keys from tools 18–19. */
var OOOSEAL_FORMAT = "p4a-oooseal-v1";
var SKIPPED_FORMAT = "p4a-skipped-v1";
var SKIPPED_MAX_KEYS = 32;

function parseNumberedSealed(text) {
  if (typeof text !== "string") return null;
  var m = text.trim().toLowerCase().match(/^p4a-oooseal-v1:([0-9]+):([0-9a-f]+):([0-9a-f]+)$/);
  if (!m) return null;
  var position = Number(m[1]);
  if (!isFinite(position) || position > RATCHET_MAX_INDEX) return null;
  /* One spelling per position: "007" is not position 7. */
  if (String(position) !== m[1]) return null;
  var iv = hexToBytes(m[2]);
  var cipher = hexToBytes(m[3]);
  if (!iv || !cipher) return null;
  if (iv.length !== KEYSEAL_IV_BYTES) return null;
  if (cipher.length < 17) return null;
  return { position: position, iv: iv, cipher: cipher };
}

/* The store as one canonical line: positions strictly
   ascending, each paired with one valid 32-byte message
   key. An empty store is the bare prefix. Anything else —
   duplicates, disorder, junk keys, too many entries — is
   null, never a best guess. */
function formatSkippedStore(entries) {
  if (!Array.isArray(entries) || entries.length > SKIPPED_MAX_KEYS) return null;
  var seen = {};
  var clean = [];
  for (var i = 0; i < entries.length; i++) {
    var e = entries[i];
    if (!e || typeof e !== "object") return null;
    if (typeof e.index !== "number" || !isFinite(e.index) ||
        Math.floor(e.index) !== e.index || e.index < 0 ||
        e.index > RATCHET_MAX_INDEX) return null;
    var hex = parseDerivedKey(e.key);
    if (hex === null) return null;
    if (seen[e.index]) return null;
    seen[e.index] = true;
    clean.push({ index: e.index, key: hex });
  }
  clean.sort(function (a, b) { return a.index - b.index; });
  var parts = [];
  for (var j = 0; j < clean.length; j++) parts.push(clean[j].index + ":" + clean[j].key);
  return SKIPPED_FORMAT + ":" + parts.join(",");
}

function parseSkippedStore(text) {
  if (typeof text !== "string") return null;
  var t = text.trim().toLowerCase();
  if (t.indexOf(SKIPPED_FORMAT + ":") !== 0) return null;
  var rest = t.slice(SKIPPED_FORMAT.length + 1);
  if (rest === "") return [];
  var parts = rest.split(",");
  if (parts.length > SKIPPED_MAX_KEYS) return null;
  var entries = [];
  var prev = -1;
  for (var i = 0; i < parts.length; i++) {
    var m = parts[i].match(/^([0-9]+):([0-9a-f]+)$/);
    if (!m) return null;
    var index = Number(m[1]);
    if (!isFinite(index) || index > RATCHET_MAX_INDEX) return null;
    if (String(index) !== m[1]) return null;
    if (index <= prev) return null; /* strictly ascending: no reorder, no duplicates */
    var hex = parseDerivedKey(m[2]);
    if (hex === null) return null;
    entries.push({ index: index, key: hex });
    prev = index;
  }
  return entries;
}

function emptySkippedStore() {
  return formatSkippedStore([]);
}

/* Returns { sealed, state }: the message sealed under this
   position's own key in the numbered format — the position
   rides on the outside so a receiver can find the key —
   and the next chain state. The state passed in is spent,
   exactly as in tool 22. */
function sealNumberedMessage(stateText, message) {
  var state = parseChainState(stateText);
  if (state === null || !validKeySealMessage(message)) return Promise.resolve(null);
  return ratchetStep(state.chainKey).then(function (step) {
    if (step === null) return null;
    var next = formatChainState(state.index + 1, step.nextChainKey);
    if (next === null) return null;
    return sealWithSessionKey(message, step.messageKey).then(function (sealed) {
      if (sealed === null) return null;
      return { sealed: OOOSEAL_FORMAT + ":" + state.index +
        sealed.slice(KEYSEAL_FORMAT.length), state: next };
    });
  });
}

/* Returns { message, state, store } on success, null for
   anything else — and on null the caller's state and store
   are untouched, because nothing here mutates its inputs.
   A position behind the chain opens only from the store and
   consumes its key; a position ahead steps the chain,
   banking the skipped positions' keys — and the store cap
   is also the jump cap: one open never steps more positions
   than the store could hold the skipped keys for. */
function openNumberedMessage(stateText, storeText, sealedText) {
  var state = parseChainState(stateText);
  var store = parseSkippedStore(storeText);
  var seal = parseNumberedSealed(sealedText);
  if (state === null || store === null || seal === null) return Promise.resolve(null);
  for (var s = 0; s < store.length; s++) {
    /* A stored key at or past the chain's position means the
       store and the state do not belong together. */
    if (store[s].index >= state.index) return Promise.resolve(null);
  }
  var inner = KEYSEAL_FORMAT + ":" + shareBytesToHex(seal.iv) +
    ":" + shareBytesToHex(seal.cipher);
  if (seal.position < state.index) {
    var found = null;
    var rest = [];
    for (var i = 0; i < store.length; i++) {
      if (store[i].index === seal.position) found = store[i];
      else rest.push(store[i]);
    }
    if (found === null) return Promise.resolve(null);
    return openWithSessionKey(inner, found.key).then(function (message) {
      if (message === null) return null;
      var outStore = formatSkippedStore(rest);
      if (outStore === null) return null;
      return { message: message, state: formatChainState(state.index, state.chainKey),
        store: outStore };
    });
  }
  var gap = seal.position - state.index;
  if (store.length + gap > SKIPPED_MAX_KEYS) return Promise.resolve(null);
  var banked = store.slice();
  var walk = Promise.resolve({ chainKey: state.chainKey, messageKey: null });
  for (var j = state.index; j <= seal.position; j++) {
    walk = (function (jj, acc) {
      return acc.then(function (cur) {
        if (cur === null) return null;
        return ratchetStep(cur.chainKey).then(function (step) {
          if (step === null) return null;
          if (jj < seal.position) banked.push({ index: jj, key: step.messageKey });
          return { chainKey: step.nextChainKey, messageKey: step.messageKey };
        });
      });
    })(j, walk);
  }
  return walk.then(function (done) {
    if (done === null) return null;
    var next = formatChainState(seal.position + 1, done.chainKey);
    if (next === null) return null;
    return openWithSessionKey(inner, done.messageKey).then(function (message) {
      if (message === null) return null;
      var outStore = formatSkippedStore(banked);
      if (outStore === null) return null;
      return { message: message, state: next, store: outStore };
    });
  });
}

/* ---------- 26. For their key only — a sealed box anyone can close ---------- */
/* Every seal so far needs something shared in advance: tool
   16 a password both sides know, tools 20–25 a session key
   both sides derived together in tool 18's live, two-sided
   agreement. That leaves the most ordinary case unserved:
   sending something private to someone who is not there —
   they published a public key, and that is all you have.
   This is the sealed box, the pattern behind "encrypt to
   their public key" in PGP and behind libsodium's sealed
   boxes: anyone who knows your public key can close a box
   for you, and only the matching private key opens it —
   no handshake and no shared password. The sender makes a
   fresh, one-message ECDH pair (tool 18's keys and sizes),
   agrees it with the recipient's public key, stretches the
   result with HKDF exactly once — the ephemeral public
   key as the salt, so the box's key is bound to this box
   and to no other use, under its own info label — and
   seals with tool 20's exact AES-GCM. The box is one
   versioned line, p4a-box-v1:<ephemeral public key>:<iv>:
   <cipher>: the ephemeral public key rides on the outside
   in plain view, because it is not a secret — the
   recipient mixes it with their private key, lands on the
   same secret, re-derives the same key and opens; anyone
   else who tries lands on a different secret and the GCM
   tag refuses. The sender's ephemeral private key is
   never stored, shown or sent: once the box is closed it
   has done its only job, and there is deliberately no way
   to re-derive a box's key from the line alone. The
   honest limits are the other half of the lesson: a box
   proves nothing about who sent it — the recipient's
   public key is public, so anyone can close a box in
   anyone's name (tool 21's signature inside a seal is
   this suite's answer when the sender matters); there is
   no ratchet here, so if your private key is copied
   later, every box ever closed to it opens — forward
   secrecy belongs to tools 22–25, whose keys are erased
   as they are used; and a public key only protects you
   if it really is theirs — a swapped key closes every
   box to the swapper instead, which nothing inside the
   box can detect. Honest label: teaching implementation,
   not an audited messaging app. Keys exist only in this
   page; never paste a real wallet key or a production
   private key into any web page, including this one —
   practise with throwaway keys from tool 18. */
var BOX_FORMAT = "p4a-box-v1";
var BOX_KEY_INFO = "privacy4all-box-v1 key";
var BOX_MAX_MESSAGE_CHARS = KEYSEAL_MAX_MESSAGE_CHARS;

function parseBoxSealed(text) {
  if (typeof text !== "string") return null;
  var m = text.trim().toLowerCase().match(/^p4a-box-v1:([0-9a-f]+):([0-9a-f]+):([0-9a-f]+)$/);
  if (!m) return null;
  var ephemeral = hexToBytes(m[1]);
  var iv = hexToBytes(m[2]);
  var cipher = hexToBytes(m[3]);
  if (!ephemeral || !iv || !cipher) return null;
  if (ephemeral.length !== AGREE_PUBLIC_KEY_BYTES) return null;
  if (iv.length !== KEYSEAL_IV_BYTES) return null;
  /* GCM tag is 16 bytes, so ciphertext is at least 1 byte + tag. */
  if (cipher.length < 17) return null;
  return { ephemeralPublicKey: m[1], iv: iv, cipher: cipher };
}

/* The one stretching step: HKDF-SHA-256 over the ECDH
   secret, salted with the ephemeral public key itself.
   The salt is public — it rides on the box — and that is
   the point: the derived key is bound to this one box,
   and the same secret under any other ephemeral key (or
   under tool 19's purposes, or tool 23's heal label)
   derives an unrelated key. */
function deriveBoxKey(secretHex, ephemeralPublicKeyHex) {
  var secret = parseSharedSecret(secretHex);
  var eph = parseKeyHex(ephemeralPublicKeyHex, AGREE_PUBLIC_KEY_BYTES);
  if (secret === null || !eph) return Promise.resolve(null);
  var cryptoObj = agreeCrypto();
  if (!cryptoObj) return Promise.resolve(null);
  return cryptoObj.subtle.importKey("raw", hexToBytes(secret), "HKDF", false, ["deriveBits"])
    .then(function (base) {
      return cryptoObj.subtle.deriveBits(
        { name: "HKDF", hash: "SHA-256", salt: eph,
          info: secretToBytes(BOX_KEY_INFO) },
        base, DERIVE_KEY_BYTES * 8)
        .then(function (bits) {
          var bytes = new Uint8Array(bits);
          if (bytes.length !== DERIVE_KEY_BYTES) return null;
          return shareBytesToHex(bytes);
        }, function () { return null; });
    }, function () { return null; });
}

/* Close a box: only the recipient's public key and the
   message go in; a p4a-box-v1 line comes out. A fresh
   ephemeral pair is made per box, so two boxes to the
   same person share nothing — not the ephemeral key, not
   the derived key, not the IV. Malformed public keys
   (including a private key pasted by mistake) and blank
   or over-long messages are null, never a plausible box. */
function sealBoxMessage(recipientPublicKeyHex, message) {
  if (!validKeySealMessage(message)) return Promise.resolve(null);
  if (parseKeyHex(recipientPublicKeyHex, AGREE_PUBLIC_KEY_BYTES) === null) {
    return Promise.resolve(null);
  }
  return generateAgreementKeyPair().then(function (eph) {
    if (eph === null) return null;
    return deriveSharedSecret(eph.privateKey, recipientPublicKeyHex).then(function (secret) {
      if (secret === null) return null;
      return deriveBoxKey(secret, eph.publicKey).then(function (key) {
        if (key === null) return null;
        return sealWithSessionKey(message, key).then(function (sealed) {
          if (sealed === null) return null;
          return BOX_FORMAT + ":" + eph.publicKey + sealed.slice(KEYSEAL_FORMAT.length);
        });
      });
    });
  });
}

/* Open a box: the recipient's private key mixes with the
   ephemeral public key on the box, landing on the same
   secret the sender reached from the other side. A wrong
   private key, a swapped ephemeral key, a tampered byte
   — every failure is the same null, never gibberish and
   never a hint about which part failed. */
function openBoxMessage(privateKeyHex, sealedText) {
  var parsed = parseBoxSealed(sealedText);
  if (parsed === null) return Promise.resolve(null);
  return deriveSharedSecret(privateKeyHex, parsed.ephemeralPublicKey).then(function (secret) {
    if (secret === null) return null;
    return deriveBoxKey(secret, parsed.ephemeralPublicKey).then(function (key) {
      if (key === null) return null;
      var inner = KEYSEAL_FORMAT + ":" + shareBytesToHex(parsed.iv) +
        ":" + shareBytesToHex(parsed.cipher);
      return openWithSessionKey(inner, key);
    });
  });
}

/* ---------- 27. A box that names its sender — sign it, then close it in the box ---------- */
/* Tool 26 built the sealed box and named its own limit in
   the same breath: a box proves nothing about who sent it,
   because the recipient's public key is public and anyone
   can close a box in anyone's name. Tool 21 is the suite's
   answer when the sender matters — a signature inside the
   seal — but it needs a session key both sides derived
   together, which is exactly what the box case does not
   have. This tool puts the two together: sign first, then
   close it in the box. The sender signs the message with
   their tool-17 signing key, the signature rides inside
   the box in the same p4a-signed-v1 envelope tool 21 uses
   — inside, so only the recipient ever sees it and a
   watcher cannot even tell this box is signed — and the
   envelope is closed exactly like tool 26's box: a fresh
   one-message ECDH pair, HKDF stretched once, AES-GCM
   through tool 20. Two deliberate separations: the HKDF
   step uses its own info label, so a signed box and a
   plain box closed from the same secret and the same
   ephemeral key would still derive unrelated keys, and
   the outer line gets its own format, p4a-authbox-v1 —
   neither box can be relabelled into the other, and the
   relabelled line fails closed at the GCM tag before any
   envelope is even read. Opening keeps tool 21's honest
   split: opening and verifying stay two separate answers,
   { message, verified } — a box can open perfectly and
   still not be from who it claims, and that case returns
   the text with verified === false instead of hiding it.
   The honest limits are inherited from both parents and
   stated plainly: the signature proves the signing key,
   not a legal name; both public keys have to really be
   theirs — a swapped recipient key hands every box to the
   swapper, and a swapped sender key makes a stranger's
   signature verify under the wrong name; there is still
   no ratchet, so a recipient private key copied later
   opens every signed box ever closed to it, signatures
   and all; and a copied box line opens again — nothing
   in the envelope proves when it was signed or that it
   was sent once, so freshness and replay protection are
   the application's job, not the box's. Honest label:
   teaching implementation, not an audited messaging app.
   Keys exist only in this page; never paste a real
   wallet key or a production private key into any web
   page, including this one — practise with throwaway
   keys from tools 17 and 18. */
var AUTHBOX_FORMAT = "p4a-authbox-v1";
var AUTHBOX_KEY_INFO = "privacy4all-authbox-v1 key";
/* Same cap as tool 21: the message plus its signature
   plus the envelope's JSON must fit tool 20's seal. */
var AUTHBOX_MAX_MESSAGE_CHARS = AUTHSEAL_MAX_MESSAGE_CHARS;

function parseAuthBoxSealed(text) {
  if (typeof text !== "string") return null;
  var m = text.trim().toLowerCase().match(/^p4a-authbox-v1:([0-9a-f]+):([0-9a-f]+):([0-9a-f]+)$/);
  if (!m) return null;
  var ephemeral = hexToBytes(m[1]);
  var iv = hexToBytes(m[2]);
  var cipher = hexToBytes(m[3]);
  if (!ephemeral || !iv || !cipher) return null;
  if (ephemeral.length !== AGREE_PUBLIC_KEY_BYTES) return null;
  if (iv.length !== KEYSEAL_IV_BYTES) return null;
  if (cipher.length < 17) return null;
  return { ephemeralPublicKey: m[1], iv: iv, cipher: cipher };
}

/* Tool 26's stretching step under this tool's own info
   label: same secret, same ephemeral salt, different
   label, unrelated key. That domain separation is what
   makes the two box formats non-interchangeable even
   before their prefixes are read. */
function deriveAuthBoxKey(secretHex, ephemeralPublicKeyHex) {
  var secret = parseSharedSecret(secretHex);
  var eph = parseKeyHex(ephemeralPublicKeyHex, AGREE_PUBLIC_KEY_BYTES);
  if (secret === null || !eph) return Promise.resolve(null);
  var cryptoObj = agreeCrypto();
  if (!cryptoObj) return Promise.resolve(null);
  return cryptoObj.subtle.importKey("raw", hexToBytes(secret), "HKDF", false, ["deriveBits"])
    .then(function (base) {
      return cryptoObj.subtle.deriveBits(
        { name: "HKDF", hash: "SHA-256", salt: eph,
          info: secretToBytes(AUTHBOX_KEY_INFO) },
        base, DERIVE_KEY_BYTES * 8)
        .then(function (bits) {
          var bytes = new Uint8Array(bits);
          if (bytes.length !== DERIVE_KEY_BYTES) return null;
          return shareBytesToHex(bytes);
        }, function () { return null; });
    }, function () { return null; });
}

/* Close a signed box: the recipient's public key, the
   sender's signing private key and the message go in; a
   p4a-authbox-v1 line comes out. Signing happens first
   and the envelope is what gets sealed, so the signature
   itself is as private as the message. A malformed
   recipient key (a private key pasted by mistake
   included), a signing key that cannot sign, or a blank
   or over-long message is null, never a plausible box. */
function sealAuthenticatedBoxMessage(recipientPublicKeyHex, signingPrivateKeyHex, message) {
  if (!validAuthMessage(message)) return Promise.resolve(null);
  if (parseKeyHex(recipientPublicKeyHex, AGREE_PUBLIC_KEY_BYTES) === null) {
    return Promise.resolve(null);
  }
  return signMessage(signingPrivateKeyHex, message).then(function (sig) {
    if (!sig) return null;
    var inner = JSON.stringify({ format: AUTHSEAL_ENVELOPE_FORMAT,
                                 message: message, signature: sig });
    if (inner.length > KEYSEAL_MAX_MESSAGE_CHARS) return null;
    return generateAgreementKeyPair().then(function (eph) {
      if (eph === null) return null;
      return deriveSharedSecret(eph.privateKey, recipientPublicKeyHex).then(function (secret) {
        if (secret === null) return null;
        return deriveAuthBoxKey(secret, eph.publicKey).then(function (key) {
          if (key === null) return null;
          return sealWithSessionKey(inner, key).then(function (sealed) {
            if (sealed === null) return null;
            return AUTHBOX_FORMAT + ":" + eph.publicKey + sealed.slice(KEYSEAL_FORMAT.length);
          });
        });
      });
    });
  });
}

/* Open a signed box: returns { message, verified }.
   verified is true only when the signature inside checks
   out against senderPublicKeyHex. A box that opens but
   was signed by a different key comes back with its text
   intact and verified === false — read it, but not as
   theirs. A wrong recipient key, a tampered or
   relabelled line, an inner text that is not a signed
   envelope at all, or a malformed sender public key is
   null: the box fails closed, and says nothing about
   which part failed. */
function openAuthenticatedBoxMessage(privateKeyHex, sealedText, senderPublicKeyHex) {
  var parsed = parseAuthBoxSealed(sealedText);
  if (parsed === null) return Promise.resolve(null);
  return deriveSharedSecret(privateKeyHex, parsed.ephemeralPublicKey).then(function (secret) {
    if (secret === null) return null;
    return deriveAuthBoxKey(secret, parsed.ephemeralPublicKey).then(function (key) {
      if (key === null) return null;
      var inner = KEYSEAL_FORMAT + ":" + shareBytesToHex(parsed.iv) +
        ":" + shareBytesToHex(parsed.cipher);
      return openWithSessionKey(inner, key).then(function (text) {
        if (text === null) return null;
        var env = parseSignedEnvelope(text);
        if (!env) return null;
        return verifySignature(senderPublicKeyHex, env.message, env.signature)
          .then(function (ok) {
            if (ok === null) return null;
            return { message: env.message, verified: ok };
          });
      });
    });
  });
}

/* ---------- 28. Is that really their key? — the safety number ---------- */
/* Every tool from 17 on ends on the same warning: a
   signature, a box, an agreement — all of them prove the
   KEY, and the key only helps if the public key you hold
   is really theirs. The swap that defeats the whole suite
   happens before any message: a directory, a profile page
   or a person in the middle hands you a different public
   key, and from then on every check passes — against the
   swapper's key. This tool is the check that runs BEFORE
   trust: a SAFETY NUMBER for a pair of public keys. Each
   key is hashed in with a domain label after sorting the
   two, so both people compute exactly the same number from
   the same two published keys, in either order, without
   meeting and without any secret — the number is built
   from public keys alone, so it is safe to read aloud,
   print, or post, and revealing it reveals nothing about
   any private key. Twelve groups of five digits: long
   enough that a swapper cannot realistically find a key
   that lands on the same number, short enough to compare
   over a phone call. The comparison belongs on a channel
   you already trust — a voice you recognise, in person —
   because a number delivered over the same channel that
   delivered the key proves nothing: the swapper swaps
   both. Honest limits, stated plainly: the number proves
   the keys, not a legal name — it binds a key to whoever
   read the number to you, and to nothing else; it must
   be re-compared whenever a key changes, because a new
   key is a new number; this page's digit format is its
   own teaching format (first 60 hex characters of the
   digest, five hex characters to a five-digit group),
   not any messenger's published safety-number format;
   and a 60-digit number is a truncated hash — collision
   resistance here is a practical teaching property, not
   a proof. Teaching implementation, not an audited
   identity system. Never paste a real wallet key into
   any web page, including this one — public keys from
   tools 17 and 18 are the only things this tool takes,
   and even those should be throwaway practise keys. */
var SAFETY_PREFIX = "privacy4all-safetynumber-v1";
var SAFETY_GROUPS = 12;
var SAFETY_GROUP_DIGITS = 5;

function parseSafetyPublicKey(text) {
  var bytes = parseKeyHex(text, AGREE_PUBLIC_KEY_BYTES);
  if (!bytes) return null;
  return shareBytesToHex(bytes);
}

/* The display half, pure and synchronous so it can be
   checked against a plain digest: the first 60 hex
   characters of the hash become twelve five-digit
   groups, each group one five-hex-character chunk read
   as a number under 100000 and zero-padded — leading
   zeros are digits here, never dropped. Anything that
   is not a full 64-character SHA-256 hex digest is
   null, never a plausible-looking short number. */
function formatSafetyNumber(hashHex) {
  if (typeof hashHex !== "string") return null;
  var hex = hashHex.trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(hex)) return null;
  var head = hex.slice(0, SAFETY_GROUPS * SAFETY_GROUP_DIGITS);
  var groups = [];
  for (var i = 0; i < head.length; i += SAFETY_GROUP_DIGITS) {
    var chunk = parseInt(head.slice(i, i + SAFETY_GROUP_DIGITS), 16) % 100000;
    groups.push(("00000" + chunk).slice(-SAFETY_GROUP_DIGITS));
  }
  return groups.join(" ");
}

function parseSafetyNumber(text) {
  if (typeof text !== "string") return null;
  var digits = text.replace(/[\s-]+/g, "");
  if (!/^[0-9]{60}$/.test(digits)) return null;
  return digits;
}

/* Both sides compute the same number: the two keys are
   sorted before hashing, so mine-then-theirs and
   theirs-then-mine are one number, not two. A private
   key pasted by mistake (138 bytes, not 91), a short
   key, or junk is null — never a number for the wrong
   thing. Either tool-17 signing keys or tool-18
   agreement keys work: both are the same 91-byte SPKI
   encoding, and the number cares about the key bytes,
   not which tool made them. */
function safetyNumberForKeys(publicKeyA, publicKeyB) {
  var a = parseSafetyPublicKey(publicKeyA);
  var b = parseSafetyPublicKey(publicKeyB);
  if (a === null || b === null) return Promise.resolve(null);
  var lo = a < b ? a : b;
  var hi = a < b ? b : a;
  return sha256Hex(SAFETY_PREFIX + "\n" + lo + "\n" + hi)
    .then(function (hash) {
      if (hash === null) return null;
      return formatSafetyNumber(hash);
    });
}

/* The verdict half: true only when the number computed
   from these two keys is exactly the number read over
   the trusted channel. Spacing, grouping and line
   breaks in the expected number are ignored — people
   read numbers aloud in their own grouping — but a
   malformed expected number (too short, too long,
   letters) is null, never false: false means "these
   keys, that well-formed number, no match", and the
   two answers must never blur. */
function checkSafetyNumber(publicKeyA, publicKeyB, expectedText) {
  var expected = parseSafetyNumber(expectedText);
  if (expected === null) return Promise.resolve(null);
  return safetyNumberForKeys(publicKeyA, publicKeyB).then(function (actual) {
    if (actual === null) return null;
    return actual.replace(/ /g, "") === expected;
  });
}

/* ---------- 29. A fresh destination for every payment — one-time destinations ---------- */
/* Every tool so far protects the CONTENT of a message or
   the fact behind a proof. This one protects the ADDRESS
   itself. A single published address, reused for every
   payment, is a correlation machine: anyone watching the
   ledger can total what its owner received, see when, and
   link every payer who ever used it — no decryption
   needed, because the link is the address. The stealth
   pattern answers it with a ONE-TIME DESTINATION per
   payment. The sender makes a fresh, one-payment
   agreement pair (tool 18), mixes its private half with
   the recipient's published public key, and hashes the
   shared secret under this tool's own label: that digest
   is the destination, a fresh 64-hex identifier nobody
   can connect to the published key from the outside. The
   ephemeral public key travels with the payment in plain
   view — it is not a secret — and the recipient SCANS
   with it: mixing their private key with the ephemeral
   public key lands on the same secret, the same hash,
   the same destination, and a match means "this one is
   mine". A stranger scanning with the wrong private key
   lands on a different secret and a different
   destination. Two payments to the same person produce
   two unrelated destinations, because each rides on a
   fresh ephemeral pair. The one-payment private key is
   never stored, shown or sent — like tool 26's box key,
   it has exactly one job. Honest limits, stated plainly:
   this is a teaching model of the recognition half of
   stealth addressing — real schemes (Monero-style,
   EIP-5564-style) derive a one-time public KEY on the
   curve, so the recipient also derives the matching
   one-time private key that spends; here the destination
   is an identifier computed from the shared secret, it
   is not an address on any chain, and nothing here moves
   or holds funds. The sender necessarily knows the
   destination they made — unlinkability here is against
   outside watchers, not against the payer. Scanning needs
   the ephemeral key that travelled with the payment: lose
   it and that destination can no longer be recognised by
   anyone. And a fresh destination hides WHO was paid, not
   THAT a payment happened — amounts, timing and
   network-level metadata still leak (tool 9's lesson).
   Teaching implementation, not an audited wallet. Never
   paste a real wallet key or a production private key
   into any web page, including this one — practise with
   throwaway keys from tool 18. */
var ONETIME_PREFIX = "privacy4all-onetime-v1";
var ONETIME_DESTINATION_BYTES = 32;

function parseOneTimeDestination(text) {
  if (typeof text !== "string") return null;
  var hex = text.trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(hex)) return null;
  return hex;
}

/* The destination is a labelled hash of the shared
   secret alone — never of the recipient's public key,
   which anyone can see. The label domain-separates it
   from tool 18's fingerprint of the same secret: same
   input, different question, different digest. A secret
   that is not exactly 32 bytes is null, never a
   destination for the wrong thing. */
function oneTimeDestinationForSecret(secretHex) {
  var hex = parseSharedSecret(secretHex);
  if (hex === null) return Promise.resolve(null);
  return sha256Hex(ONETIME_PREFIX + "\n" + hex);
}

/* The sender's half: a fresh ephemeral pair per payment,
   mixed with the recipient's published key. A private
   key offered as the recipient key (138 bytes, not 91),
   a short key or junk is null before any pair is made. */
function makeOneTimeDestination(recipientPublicKeyHex) {
  if (parseKeyHex(recipientPublicKeyHex, AGREE_PUBLIC_KEY_BYTES) === null) {
    return Promise.resolve(null);
  }
  return generateAgreementKeyPair().then(function (eph) {
    if (!eph) return null;
    return deriveSharedSecret(eph.privateKey, recipientPublicKeyHex)
      .then(function (secret) {
        if (secret === null) return null;
        return oneTimeDestinationForSecret(secret).then(function (dest) {
          if (dest === null) return null;
          return { ephemeralPublicKey: eph.publicKey, destination: dest };
        });
      });
  });
}

/* The recipient's half: the same secret from the other
   side — their private key, the ephemeral public key
   that travelled with the payment. Malformed keys are
   null (deriveSharedSecret validates both lengths). */
function scanOneTimeDestination(privateKeyHex, ephemeralPublicKeyHex) {
  return deriveSharedSecret(privateKeyHex, ephemeralPublicKeyHex)
    .then(function (secret) {
      if (secret === null) return null;
      return oneTimeDestinationForSecret(secret);
    });
}

/* The verdict: true only when the destination this
   private key computes from this ephemeral key is
   exactly the destination in question. A malformed
   claimed destination (not 64 hex) is null, never
   false: false means "these keys, that well-formed
   destination, not yours", and the two answers must
   never blur — the same rule as tool 28's checker. */
function checkOneTimeDestination(privateKeyHex, ephemeralPublicKeyHex, destinationText) {
  var expected = parseOneTimeDestination(destinationText);
  if (expected === null) return Promise.resolve(null);
  return scanOneTimeDestination(privateKeyHex, ephemeralPublicKeyHex)
    .then(function (actual) {
      if (actual === null) return null;
      return actual === expected;
    });
}

/* ---------- 30. The key that can spend it — one-time spend keys ---------- */
/* Tool 29 ends on an honest gap: it models the RECOGNITION
   half of stealth addressing — the recipient can spot a
   payment as theirs — but real schemes (Monero-style,
   EIP-5564-style) also derive a one-time public KEY on the
   curve, so the recipient derives the matching one-time
   PRIVATE key that spends. This tool builds that spend
   half, with real P-256 curve arithmetic done locally in
   plain BigInt code — no library, nothing sent anywhere.
   The shared secret (tool 18) is hashed once under this
   tool's own label; that digest, read as a number below
   the curve order, is the TWEAK. The sender adds tweak×G
   to the recipient's published point: that sum is the
   one-time public key. The recipient adds the same tweak
   to their private scalar: (r + t)×G = r×G + t×G is the
   same point, so the tweaked private key matches the
   one-time public key exactly, and nobody else can derive
   either side — the tweak needs the secret, and the
   secret needs a private key. Keys stay in this hub's
   formats throughout: the one-time public key is a
   91-byte SPKI key exactly like tool 18's, and the
   one-time private key is a 138-byte PKCS#8 key rebuilt
   around the tweaked scalar, so the tools here can import
   it like any other practise key. Honest limits, stated
   plainly: the key is still not an address on any chain
   and nothing here moves or holds funds — it is the
   derivation half of the pattern, shown on the curve
   Midnight's own practise keys use here (P-256; real
   stealth schemes run on their own curves and encodings,
   and their exact tweak hashes differ). Whoever holds
   the recipient's ordinary private key plus the
   one-payment public key can derive the spend key — that
   IS the design — so a copied private key endangers every
   payment ever sent to it, exactly as tool 29 warned for
   recognition. And the curve code is a teaching
   implementation: affine arithmetic with a modular
   inverse per step, chosen because it can be read and
   checked line by line, not for speed or side-channel
   resistance — production wallets use audited,
   constant-time libraries. Never paste a real wallet key
   or a production private key into any web page,
   including this one — practise with throwaway keys from
   tool 18. */
var SPENDKEY_PREFIX = "privacy4all-spendkey-v1";
var SPENDKEY_SPKI_PREFIX_HEX = "3059301306072a8648ce3d020106082a8648ce3d030107034200";
var P256_P = BigInt("0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
var P256_B = BigInt("0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b");
var P256_GX = BigInt("0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296");
var P256_GY = BigInt("0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5");
var P256_N = BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
var P256_ZERO = BigInt(0);
var P256_ONE = BigInt(1);
var P256_TWO = BigInt(2);
var P256_THREE = BigInt(3);

function p256Mod(x) {
  var r = x % P256_P;
  return r < P256_ZERO ? r + P256_P : r;
}

/* Modular inverse by Fermat's little theorem — the field
   prime is public, so x^(p-2) mod p is x's inverse. Slow
   next to an audited library, and chosen anyway: it is
   five lines anyone can verify. Zero has no inverse and
   returns null, never a plausible number. */
function p256Invert(x) {
  var base = p256Mod(x);
  if (base === P256_ZERO) return null;
  var exp = P256_P - P256_TWO;
  var result = P256_ONE;
  while (exp > P256_ZERO) {
    if ((exp & P256_ONE) === P256_ONE) result = p256Mod(result * base);
    base = p256Mod(base * base);
    exp = exp >> P256_ONE;
  }
  return result;
}

/* Points are {x, y} BigInt pairs; null is the point at
   infinity, the group's identity. Addition handles the
   three shapes honestly: identity on either side, a point
   plus its own reflection (infinity), doubling, and the
   general chord. Inputs are assumed on the curve —
   parseP256Point is the gatekeeper that checks. */
function p256PointAdd(p1, p2) {
  if (p1 === null) return p2;
  if (p2 === null) return p1;
  if (p1.x === p2.x && p256Mod(p1.y + p2.y) === P256_ZERO) return null;
  var lambda;
  if (p1.x === p2.x && p1.y === p2.y) {
    var invDy = p256Invert(P256_TWO * p1.y);
    if (invDy === null) return null;
    lambda = p256Mod((P256_THREE * p1.x * p1.x - P256_THREE) * invDy);
  } else {
    var invDx = p256Invert(p2.x - p1.x);
    if (invDx === null) return null;
    lambda = p256Mod((p2.y - p1.y) * invDx);
  }
  var x = p256Mod(lambda * lambda - p1.x - p2.x);
  var y = p256Mod(lambda * (p1.x - x) - p1.y);
  return { x: x, y: y };
}

/* Double-and-add over the scalar's bits. A scalar of zero
   (or reduced to it) is the identity, null. */
function p256PointMultiply(scalar, point) {
  var k = scalar % P256_N;
  if (k < P256_ZERO) k += P256_N;
  var result = null;
  var addend = point;
  while (k > P256_ZERO) {
    if ((k & P256_ONE) === P256_ONE) result = p256PointAdd(result, addend);
    addend = p256PointAdd(addend, addend);
    k = k >> P256_ONE;
  }
  return result;
}

function p256IntToHex(value) {
  var hex = value.toString(16);
  while (hex.length < 64) hex = "0" + hex;
  return hex;
}

/* A public key is a point only if it is exactly tool 18's
   91-byte SPKI shape, carries the fixed P-256 SPKI prefix
   and the uncompressed-point marker, both coordinates are
   under the field prime, and the point satisfies the
   curve equation y² = x³ − 3x + b. Anything else — a
   private key (138 bytes), a truncated key, a point from
   another curve — is null, never a point for the wrong
   thing. */
function parseP256Point(publicKeyHex) {
  var bytes = parseKeyHex(publicKeyHex, AGREE_PUBLIC_KEY_BYTES);
  if (!bytes) return null;
  var hex = shareBytesToHex(bytes);
  if (hex.slice(0, SPENDKEY_SPKI_PREFIX_HEX.length) !== SPENDKEY_SPKI_PREFIX_HEX) return null;
  var pointHex = hex.slice(SPENDKEY_SPKI_PREFIX_HEX.length);
  if (pointHex.slice(0, 2) !== "04") return null;
  var x = BigInt("0x" + pointHex.slice(2, 66));
  var y = BigInt("0x" + pointHex.slice(66, 130));
  if (x >= P256_P || y >= P256_P) return null;
  if (p256Mod(y * y) !== p256Mod(x * x * x - P256_THREE * x + P256_B)) return null;
  return { x: x, y: y };
}

function formatP256PublicKey(point) {
  if (point === null) return null;
  return SPENDKEY_SPKI_PREFIX_HEX + "04" + p256IntToHex(point.x) + p256IntToHex(point.y);
}

/* The tweak as a scalar: a full 64-hex digest read as a
   number and reduced under the curve order. A digest that
   reduces to zero would tweak nothing, so it is null,
   never a key that quietly equals the untweaked one —
   and anything that is not a whole digest is null too. */
function spendTweakFromHash(hashHex) {
  if (typeof hashHex !== "string") return null;
  var hex = hashHex.trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(hex)) return null;
  var tweak = BigInt("0x" + hex) % P256_N;
  if (tweak === P256_ZERO) return null;
  return p256IntToHex(tweak);
}

/* A tweak offered directly (by the two functions below,
   or by a caller) must be a whole 64-hex scalar in
   [1, n−1] — zero and the order itself are null. */
function parseSpendTweak(text) {
  if (typeof text !== "string") return null;
  var hex = text.trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(hex)) return null;
  var tweak = BigInt("0x" + hex);
  if (tweak === P256_ZERO || tweak >= P256_N) return null;
  return hex;
}

/* The tweak for one payment: a labelled hash of the
   shared secret alone, so it is domain-separated from
   tool 29's destination and tool 18's fingerprint of the
   same secret — same input, different question, unrelated
   output. A secret that is not exactly 32 bytes is null. */
function oneTimeSpendTweak(secretHex) {
  var hex = parseSharedSecret(secretHex);
  if (hex === null) return Promise.resolve(null);
  return sha256Hex(SPENDKEY_PREFIX + "\n" + hex)
    .then(function (hash) {
      if (hash === null) return null;
      return spendTweakFromHash(hash);
    });
}

/* The sender's half of the spend pattern, synchronous
   once the tweak exists: one-time point = recipient point
   + tweak×G, returned as a 91-byte SPKI key in exactly
   tool 18's format. Malformed keys or tweaks are null. */
function oneTimePublicKeyForTweak(recipientPublicKeyHex, tweakHex) {
  var point = parseP256Point(recipientPublicKeyHex);
  var tweak = parseSpendTweak(tweakHex);
  if (point === null || tweak === null) return null;
  var tweaked = p256PointAdd(point, p256PointMultiply(BigInt("0x" + tweak), { x: P256_GX, y: P256_GY }));
  return formatP256PublicKey(tweaked);
}

function base64UrlToHex(text) {
  if (typeof text !== "string" || !text) return null;
  try {
    var b64 = text.replace(/-/g, "+").replace(/_/g, "/");
    while (b64.length % 4 !== 0) b64 += "=";
    var binary = atob(b64);
    var out = "";
    for (var i = 0; i < binary.length; i++) {
      var h = binary.charCodeAt(i).toString(16);
      out += h.length === 1 ? "0" + h : h;
    }
    return out;
  } catch (e) {
    return null;
  }
}

/* The two facts inside a tool-18 private key that the
   recipient's half needs — its scalar and its point —
   read back out through the platform's own JWK export
   rather than by guessing at DER offsets: the scalar is
   the secret d, the point is x‖y. A public key offered as
   a private key, a short key or junk never imports, so
   it is null. */
function agreementPrivateParts(privateKeyHex) {
  return importAgreementKey(privateKeyHex, AGREE_PRIVATE_KEY_BYTES, "pkcs8", ["deriveBits"])
    .then(function (key) {
      if (!key) return null;
      var cryptoObj = agreeCrypto();
      if (!cryptoObj) return null;
      return cryptoObj.subtle.exportKey("jwk", key)
        .then(function (jwk) {
          var scalar = base64UrlToHex(jwk.d);
          var x = base64UrlToHex(jwk.x);
          var y = base64UrlToHex(jwk.y);
          if (!scalar || !x || !y) return null;
          if (!/^[0-9a-f]{64}$/.test(scalar) || !/^[0-9a-f]{64}$/.test(x) || !/^[0-9a-f]{64}$/.test(y)) return null;
          return { scalarHex: scalar, pointHex: "04" + x + y };
        }, function () { return null; });
    });
}

/* Replace the run of hex at a found position, by position
   — never a pattern replace, so a value that happens to
   appear twice is spliced where it was actually found. */
function spliceHex(hex, index, length, replacement) {
  return hex.slice(0, index) + replacement + hex.slice(index + length);
}

/* The recipient's half, once the tweak exists: the
   one-time scalar is (their scalar + tweak) mod n, and
   the one-time private key is their own PKCS#8 line with
   exactly two runs spliced — the scalar, and the public
   point embedded beside it — each found by searching for
   the values the platform itself exported, so no DER
   offset is ever assumed. The rebuilt line is then
   re-imported and its exported scalar and point compared
   against what was intended; a line that does not check
   out is null, never a plausible wrong key. A sum that
   lands on zero is null (it would spend nothing). */
function oneTimePrivateKeyForTweak(privateKeyHex, tweakHex) {
  var tweak = parseSpendTweak(tweakHex);
  if (tweak === null) return Promise.resolve(null);
  var canonical = parseKeyHex(privateKeyHex, AGREE_PRIVATE_KEY_BYTES);
  if (!canonical) return Promise.resolve(null);
  var pkcs8Hex = shareBytesToHex(canonical);
  return agreementPrivateParts(privateKeyHex).then(function (parts) {
    if (!parts) return null;
    var recipientPoint = parseP256Point(SPENDKEY_SPKI_PREFIX_HEX + parts.pointHex);
    if (recipientPoint === null) return null;
    var oneScalar = (BigInt("0x" + parts.scalarHex) + BigInt("0x" + tweak)) % P256_N;
    if (oneScalar === P256_ZERO) return null;
    var onePoint = p256PointAdd(recipientPoint, p256PointMultiply(BigInt("0x" + tweak), { x: P256_GX, y: P256_GY }));
    if (onePoint === null) return null;
    var onePointHex = "04" + p256IntToHex(onePoint.x) + p256IntToHex(onePoint.y);
    var scalarIndex = pkcs8Hex.indexOf(parts.scalarHex);
    var pointIndex = pkcs8Hex.indexOf(parts.pointHex);
    if (scalarIndex < 0 || pointIndex < 0) return null;
    var rebuilt = spliceHex(pkcs8Hex, pointIndex, parts.pointHex.length, onePointHex);
    rebuilt = spliceHex(rebuilt, scalarIndex, parts.scalarHex.length, p256IntToHex(oneScalar));
    if (parseKeyHex(rebuilt, AGREE_PRIVATE_KEY_BYTES) === null) return null;
    return agreementPrivateParts(rebuilt).then(function (check) {
      if (!check) return null;
      if (check.scalarHex !== p256IntToHex(oneScalar) || check.pointHex !== onePointHex) return null;
      return rebuilt;
    });
  });
}

/* The sender's whole job: validate the published key,
   make a fresh one-payment pair (tool 18), derive the
   secret, and publish the one-time public key the payment
   goes to. The ephemeral private key is never stored,
   shown or sent — like tool 29's, it has exactly one job.
   A private key offered as the recipient key, a short key
   or junk is null before any pair is made. */
function makeOneTimeSpendKey(recipientPublicKeyHex) {
  if (parseP256Point(recipientPublicKeyHex) === null) return Promise.resolve(null);
  return generateAgreementKeyPair().then(function (eph) {
    if (!eph) return null;
    return deriveSharedSecret(eph.privateKey, recipientPublicKeyHex)
      .then(function (secret) {
        if (secret === null) return null;
        return oneTimeSpendTweak(secret).then(function (tweak) {
          if (tweak === null) return null;
          var pub = oneTimePublicKeyForTweak(recipientPublicKeyHex, tweak);
          if (pub === null) return null;
          return { ephemeralPublicKey: eph.publicKey, oneTimePublicKey: pub };
        });
      });
  });
}

/* The recipient's whole job: the same secret from the
   other side — their private key, the one-payment public
   key that travelled with the payment — then the tweak,
   then the matching private key. Malformed keys are null
   (deriveSharedSecret validates both lengths). */
function claimOneTimeSpendKey(privateKeyHex, ephemeralPublicKeyHex) {
  return deriveSharedSecret(privateKeyHex, ephemeralPublicKeyHex)
    .then(function (secret) {
      if (secret === null) return null;
      return oneTimeSpendTweak(secret).then(function (tweak) {
        if (tweak === null) return null;
        return oneTimePrivateKeyForTweak(privateKeyHex, tweak);
      });
    });
}

/* The verdict: true only when this private key's own
   point is exactly the claimed one-time public key — the
   pair really is a pair. Well-formed keys that do not
   match are false, never null; a malformed key on either
   side is null, never false: "not a pair" and "cannot be
   checked" must never blur, the same rule as tools 28
   and 29. */
function matchOneTimeSpendKey(oneTimePrivateKeyHex, oneTimePublicKeyHex) {
  var claimed = parseP256Point(oneTimePublicKeyHex);
  if (claimed === null) return Promise.resolve(null);
  return agreementPrivateParts(oneTimePrivateKeyHex).then(function (parts) {
    if (!parts) return null;
    return parts.pointHex === "04" + p256IntToHex(claimed.x) + p256IntToHex(claimed.y);
  });
}

/* ---------- 31. Eyes without hands — view keys ---------- */
/* Tools 29 and 30 share one honest flaw, and both name it:
   the key that SCANS for payments is the key that SPENDS
   them. Recognising a payment (tool 29) needs the
   recipient's private key, and claiming the spend key
   (tool 30) needs that same key — so a bookkeeper, an
   auditor, a watch-only wallet on a phone, or a family
   member who should be able to SEE what arrived can only
   be helped by handing over the power to take it. Real
   stealth schemes (Monero-style) split the job in two:
   a VIEW key pair and a SPEND key pair, published side
   by side. The agreement secret is made against the
   VIEW public key, so whoever holds the view private
   key — and only them — can re-derive the secret from
   each payment's one-payment public key: they land on
   the destination (this tool's own label,
   privacy4all-viewscan-v1) and, because the spend
   PUBLIC key is public, on the payment's one-time
   public key too. Watching is complete. Spending is
   not: the tweak (this tool's second label,
   privacy4all-viewspend-v1, domain-separated from
   tool 30's) is added to the SPEND private scalar, and
   the view holder does not have that scalar — adding
   the tweak to the view scalar instead derives a
   well-formed key that matches nothing, which the
   tests pin. Claiming therefore takes BOTH private
   keys: view to find the tweak, spend to use it. The
   split cuts both ways, and that is stated plainly:
   the spend private key alone cannot even scan in
   this construction, so losing the view key means
   losing sight of payments until it is recovered; and
   the view key is still a secret worth guarding — its
   holder sees every payment this published pair ever
   receives, past and future, until the keys rotate.
   Honest limits: the destination and keys are still
   not addresses on any chain and nothing here moves
   or holds funds; this is the derivation pattern on
   the P-256 curve this hub's practise keys use, and
   real schemes differ in curves, encodings and hash
   choices. Teaching implementation, not an audited
   wallet. Never paste a real wallet key or a
   production private key into any web page, including
   this one — practise with throwaway keys from
   tool 18. */
var VIEWKEY_SCAN_PREFIX = "privacy4all-viewscan-v1";
var VIEWKEY_SPEND_PREFIX = "privacy4all-viewspend-v1";

/* The watch-side destination for one payment's secret:
   a labelled hash of the secret alone, under this
   tool's own scan label — domain-separated from tool
   29's destination and tool 18's fingerprint of the
   same secret. A secret that is not exactly 32 bytes
   is null, never a destination for the wrong thing. */
function watchedDestinationForSecret(secretHex) {
  var hex = parseSharedSecret(secretHex);
  if (hex === null) return Promise.resolve(null);
  return sha256Hex(VIEWKEY_SCAN_PREFIX + "\n" + hex);
}

/* The spend-side tweak for one payment's secret: the
   same construction as tool 30's tweak, under this
   tool's own spend label, so a payment made to a
   view/spend pair never collides with a tool-30
   payment made from the same secret. A secret that is
   not exactly 32 bytes is null, never a zero tweak. */
function watchedSpendTweak(secretHex) {
  var hex = parseSharedSecret(secretHex);
  if (hex === null) return Promise.resolve(null);
  return sha256Hex(VIEWKEY_SPEND_PREFIX + "\n" + hex)
    .then(function (hash) {
      if (hash === null) return null;
      return spendTweakFromHash(hash);
    });
}

/* Everything a secret determines for one watched
   payment: the destination a watcher recognises, and
   the one-time public key the payment goes to — the
   second needs only the spend PUBLIC key, which is
   why watching never needs the spend private key. */
function watchedPartsFromSecret(secretHex, spendPublicKeyHex) {
  if (parseP256Point(spendPublicKeyHex) === null) return Promise.resolve(null);
  return watchedDestinationForSecret(secretHex).then(function (dest) {
    if (dest === null) return null;
    return watchedSpendTweak(secretHex).then(function (tweak) {
      if (tweak === null) return null;
      var pub = oneTimePublicKeyForTweak(spendPublicKeyHex, tweak);
      if (pub === null) return null;
      return { destination: dest, oneTimePublicKey: pub };
    });
  });
}

/* The sender's job: validate BOTH published keys (each
   a real point on the curve — a private key offered as
   either is null before any pair is made), make a
   fresh one-payment pair, and mix its private half
   with the recipient's VIEW public key. The one-payment
   private key is never stored, shown or sent. */
function makeWatchedPayment(viewPublicKeyHex, spendPublicKeyHex) {
  if (parseP256Point(viewPublicKeyHex) === null ||
      parseP256Point(spendPublicKeyHex) === null) {
    return Promise.resolve(null);
  }
  return generateAgreementKeyPair().then(function (eph) {
    if (!eph) return null;
    return deriveSharedSecret(eph.privateKey, viewPublicKeyHex)
      .then(function (secret) {
        if (secret === null) return null;
        return watchedPartsFromSecret(secret, spendPublicKeyHex)
          .then(function (parts) {
            if (parts === null) return null;
            return { ephemeralPublicKey: eph.publicKey,
                     destination: parts.destination,
                     oneTimePublicKey: parts.oneTimePublicKey };
          });
      });
  });
}

/* The watcher's job: the same secret from the other
   side — the VIEW private key, the one-payment public
   key that travelled with the payment — then the same
   destination and one-time public key the sender made.
   No spend key is involved on this side at all. A
   stranger scanning with their own private key lands
   on a different destination and a different one-time
   public key: watching says "not mine", never an
   error, because their inputs were well-formed. */
function scanWatchedPayment(viewPrivateKeyHex, spendPublicKeyHex, ephemeralPublicKeyHex) {
  if (parseP256Point(spendPublicKeyHex) === null) return Promise.resolve(null);
  return deriveSharedSecret(viewPrivateKeyHex, ephemeralPublicKeyHex)
    .then(function (secret) {
      if (secret === null) return null;
      return watchedPartsFromSecret(secret, spendPublicKeyHex);
    });
}

/* The verdict: true only when the destination this
   view key computes from this one-payment key is
   exactly the destination in question. A malformed
   claimed destination is null, never false — the same
   never-blur rule as tools 28, 29 and 30. */
function checkWatchedPayment(viewPrivateKeyHex, spendPublicKeyHex, ephemeralPublicKeyHex, destinationText) {
  var expected = parseOneTimeDestination(destinationText);
  if (expected === null) return Promise.resolve(null);
  return scanWatchedPayment(viewPrivateKeyHex, spendPublicKeyHex, ephemeralPublicKeyHex)
    .then(function (parts) {
      if (parts === null) return null;
      return parts.destination === expected;
    });
}

/* The claim — the one place the spend private key is
   needed, and it is not enough on its own: the tweak
   comes from the secret, and the secret comes from
   the VIEW private key. Both private keys, or no spend
   key. The view key alone is tried in the tests: the
   key it derives by standing in for the spend key is
   well-formed and matches nothing. */
function claimWatchedSpendKey(viewPrivateKeyHex, spendPrivateKeyHex, ephemeralPublicKeyHex) {
  return deriveSharedSecret(viewPrivateKeyHex, ephemeralPublicKeyHex)
    .then(function (secret) {
      if (secret === null) return null;
      return watchedSpendTweak(secret).then(function (tweak) {
        if (tweak === null) return null;
        return oneTimePrivateKeyForTweak(spendPrivateKeyHex, tweak);
      });
    });
}

/* ---------- 32. Prove you know the key — Schnorr proof of knowledge ----------

   Tool 5 simulates the zero-knowledge pattern and says
   so, in so many words: "a teaching simulation, not a
   cryptographic proof". This tool runs a real one — the
   Schnorr identification protocol, the classic proof of
   knowledge that modern zero-knowledge systems grow
   from, computed locally on the same P-256 curve and
   with the same plain BigInt arithmetic as tool 30.
   The prover holds a private key (a tool 17 signing key
   or a tool 18 agreement key — both are the same
   138-byte P-256 shape) and wants to convince a verifier
   they hold it, revealing nothing about the key itself.
   Three moves, and the ORDER is the security:

   1. Commit. The prover picks a fresh secret nonce k,
      publishes the commitment R = k×G, and keeps k in a
      prover-only state line (p4a-zkproof-v1). Nothing
      about the private key is in R — it is one more
      public key, for a key nobody will ever use again.
   2. Challenge. Only AFTER the commitment is fixed does
      the verifier pick a fresh, unpredictable challenge
      number c. A challenge of zero is refused: with
      c = 0 the answer is the nonce itself and proves
      nothing about the key.
   3. Respond. The prover answers s = k + c·x (mod n),
      where x is the private scalar. The verifier checks
      s×G = R + c×Y against the public key Y. The
      equation balances only if the answer was built
      from the private number behind Y and the nonce
      behind R — and s itself is safe to show, because
      one equation in the two unknowns k and x gives
      neither away.

   The two ways this breaks are stated as plainly in the
   page text, and both are pinned by tests. If the
   prover sees the challenge BEFORE fixing the
   commitment, they can work backwards (pick s, set
   R = s×G − c×Y) and "prove" knowledge of a key they
   do not hold — the commitment coming first is not
   ceremony, it is the proof. And a nonce must answer
   exactly one challenge: two answers from one
   commitment, s1 − s2 = (c1 − c2)·x, hand anyone the
   private scalar itself — so one state line, one
   challenge, then it is thrown away.

   A finished proof is not a signature: it signs no
   message, authorises nothing, and proves knowledge of
   a private key, not a legal name — and an old answer
   replayed against a verifier's NEW challenge fails,
   which is the freshness a signature does not give.
   The verifier's verdict keeps the house split: true
   for a balancing proof, false (never null) for
   well-formed pieces that do not balance, null for
   malformed pieces — "it failed" and "that cannot even
   be checked" never blur. Honestly labelled: this is a
   teaching implementation, not an audited wallet, not
   one of Midnight's Compact circuit proofs, and this
   one page plays both sides, so it demonstrates the
   maths, not a live exchange. Never paste a real wallet
   key or a production private key into any web page,
   including this one — practise with throwaway keys
   from tools 17 and 18. */
var ZKPROOF_STATE_FORMAT = "p4a-zkproof-v1";

/* A proof scalar — a nonce, a challenge, a private
   number — is a whole 64-hex value in [1, n−1]. Zero is
   refused for all three: a zero nonce commits to
   nothing, a zero challenge proves nothing, and zero
   is not a private key. The order itself is refused:
   it is the identity in disguise. */
function parseProofScalar(text) {
  if (typeof text !== "string") return null;
  var hex = text.trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(hex)) return null;
  var value = BigInt("0x" + hex);
  if (value === P256_ZERO || value >= P256_N) return null;
  return hex;
}

/* A response may honestly be zero (with probability
   about 2^-256), so its gate is [0, n−1]: a whole
   64-hex value under the order, zero allowed. */
function parseProofResponse(text) {
  if (typeof text !== "string") return null;
  var hex = text.trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(hex)) return null;
  if (BigInt("0x" + hex) >= P256_N) return null;
  return hex;
}

/* A fresh scalar from the platform's own randomness,
   reduced under the order and never zero — the same
   source tools 11 and 16 draw from. No randomness, no
   scalar: null, never a predictable number. */
function randomProofScalar() {
  var cryptoObj = (typeof globalThis !== "undefined" && globalThis.crypto) || null;
  if (!cryptoObj || typeof cryptoObj.getRandomValues !== "function") return null;
  for (var attempt = 0; attempt < 8; attempt++) {
    var bytes = new Uint8Array(32);
    cryptoObj.getRandomValues(bytes);
    var value = BigInt("0x" + shareBytesToHex(bytes)) % P256_N;
    if (value !== P256_ZERO) return p256IntToHex(value);
  }
  return null;
}

/* The commitment for one nonce: R = k×G, as a 91-byte
   SPKI public key in exactly the hub's usual format.
   Synchronous and deterministic, so tests can pin it
   against Node's own curve arithmetic. */
function proofCommitmentForNonce(nonceHex) {
  var nonce = parseProofScalar(nonceHex);
  if (nonce === null) return null;
  var point = p256PointMultiply(BigInt("0x" + nonce), { x: P256_GX, y: P256_GY });
  return formatP256PublicKey(point);
}

/* The prover-only state line: the format tag, the
   nonce, and the commitment it belongs to, so a state
   can never be quietly paired with a different
   commitment at answer time. Malformed pieces are
   null — a state that does not check out carries
   nothing. */
function formatProofState(nonceHex, commitmentHex) {
  var nonce = parseProofScalar(nonceHex);
  var point = parseP256Point(commitmentHex);
  if (nonce === null || point === null) return null;
  return ZKPROOF_STATE_FORMAT + ":" + nonce + ":" + formatP256PublicKey(point);
}

function parseProofState(text) {
  if (typeof text !== "string") return null;
  var parts = text.trim().split(":");
  if (parts.length !== 3 || parts[0] !== ZKPROOF_STATE_FORMAT) return null;
  var nonce = parseProofScalar(parts[1]);
  var point = parseP256Point(parts[2]);
  if (nonce === null || point === null) return null;
  return { nonce: nonce, commitment: formatP256PublicKey(point) };
}

/* Move 1, the prover's start: validate the private key
   by reading its own parts back through the platform
   (a public key offered as a private key, a short key
   or junk never imports, so it is null before any nonce
   exists), then draw a fresh nonce, commit to it, and
   hand back the public commitment and the secret state
   line. The state holds the nonce — never the private
   key, which is asked again at answer time and never
   stored anywhere. */
function makeProofCommitment(privateKeyHex) {
  return agreementPrivateParts(privateKeyHex).then(function (parts) {
    if (!parts) return null;
    var nonce = randomProofScalar();
    if (nonce === null) return null;
    var commitment = proofCommitmentForNonce(nonce);
    var state = formatProofState(nonce, commitment);
    if (commitment === null || state === null) return null;
    return { commitment: commitment, state: state };
  });
}

/* Move 2, the verifier's whole job: a fresh challenge,
   drawn only once a commitment is fixed in front of
   them. Unpredictability is the entire contribution —
   a challenge the prover could have guessed is a
   challenge they could have worked backwards from. */
function generateProofChallenge() {
  return randomProofScalar();
}

/* Move 3's arithmetic, synchronous once the three
   numbers exist: s = (k + c·x) mod n. A response of
   exactly zero is refused as null rather than handed
   over — it would mean the answer carries no trace of
   either secret, and it arises with probability about
   2^-256, so refusing costs nothing real. */
function proofResponseForScalar(scalarHex, nonceHex, challengeHex) {
  var scalar = parseProofScalar(scalarHex);
  var nonce = parseProofScalar(nonceHex);
  var challenge = parseProofScalar(challengeHex);
  if (scalar === null || nonce === null || challenge === null) return null;
  var s = (BigInt("0x" + nonce) + BigInt("0x" + challenge) * BigInt("0x" + scalar)) % P256_N;
  if (s === P256_ZERO) return null;
  return p256IntToHex(s);
}

/* Move 3, the prover's answer: the state supplies the
   nonce, the private key supplies the scalar, the
   verifier's challenge binds them. A state or
   challenge that does not parse is null before the key
   is even read. */
function respondToProofChallenge(privateKeyHex, stateText, challengeHex) {
  var state = parseProofState(stateText);
  var challenge = parseProofScalar(challengeHex);
  if (state === null || challenge === null) return Promise.resolve(null);
  return agreementPrivateParts(privateKeyHex).then(function (parts) {
    if (!parts) return null;
    return proofResponseForScalar(parts.scalarHex, state.nonce, challenge);
  });
}

/* The verifier's verdict: s×G against R + c×Y, point
   for point. True only when the equation balances;
   false — never null — for well-formed pieces that do
   not balance (the wrong key, the wrong challenge, a
   replayed answer, a stranger's response); null for
   any malformed piece, so "not proved" and "cannot be
   checked" never blur. A zero response can balance
   only against the point at infinity, which no
   well-formed right-hand side here can be, so it is
   simply false. */
function verifyProof(publicKeyHex, commitmentHex, challengeHex, responseHex) {
  var pubPoint = parseP256Point(publicKeyHex);
  var commitPoint = parseP256Point(commitmentHex);
  var challenge = parseProofScalar(challengeHex);
  var response = parseProofResponse(responseHex);
  if (pubPoint === null || commitPoint === null || challenge === null || response === null) return null;
  var lhs = p256PointMultiply(BigInt("0x" + response), { x: P256_GX, y: P256_GY });
  if (lhs === null) return false;
  var rhs = p256PointAdd(commitPoint, p256PointMultiply(BigInt("0x" + challenge), pubPoint));
  if (rhs === null) return false;
  return lhs.x === rhs.x && lhs.y === rhs.y;
}

/* ---------- 33. A proof that signs itself — Fiat–Shamir Schnorr signatures ----------

   Tool 32's proof needs a verifier in the room: they
   draw the challenge, by hand, after the commitment is
   fixed — and that live exchange is exactly what makes
   it a proof rather than a signature. This tool takes
   the verifier out of the room. The Fiat–Shamir
   transform replaces the drawn challenge with a hash:
   e = SHA-256, under the label privacy4all-schnorr-v1,
   of the commitment and the message together, reduced
   under the curve order. The commitment still comes
   first — it is an input to the hash, so the challenge
   cannot exist before it — but now nobody has to draw
   anything: the signer computes the challenge
   themselves, answers it exactly as tool 32 does
   (s = k + e·x mod n, reusing that tool's arithmetic
   unchanged), and publishes the commitment and the
   answer as one signature line (p4a-schnorr-v1).
   Anyone, anywhere, at any later time, recomputes the
   same hash from the message and checks the same
   equation, s×G = R + e×Y. That is what a signature
   is: tool 32's proof, made non-interactive.

   What changes, and what does not. A signature binds
   a message — that binding is the whole point, and it
   is also the loss tool 32's page text warns about:
   a signature can be shown around forever, so it
   proves the key signed THAT message, to anyone, not
   that the holder is present answering you now.
   Freshness is gone; transferability is the feature.
   The nonce rule does not soften: one nonce behind
   two signatures hands anyone the private scalar,
   s1 − s2 = (e1 − e2)·x, exactly as in tool 32 — the
   tests pin the recovery against this tool's own
   pieces. And a challenge hashed from too little
   would be no challenge at all: the label keeps this
   hash from ever colliding with another tool's use of
   the same pieces, and the commitment inside the
   hash is what stops a signer from choosing the
   answer first and working backwards, the forgery
   tool 32 demonstrates.

   The verifier's verdict keeps the house split: true
   for a balancing signature, false — never null — for
   well-formed pieces that do not balance (a changed
   message, a nudged answer, the wrong key), null for
   malformed pieces. Honestly labelled: this is a
   real Schnorr signature computed and checked
   locally, but it is NOT the signature format any
   chain or wallet checks — tool 17's ECDSA remains
   the signature a P-256 wallet would produce, real
   Schnorr deployments (Bitcoin's BIP-340 among them)
   use their own curves, encodings and hash
   constructions, and nothing here is an audited
   wallet or side-channel resistant. Never paste a
   real wallet key or a production private key into
   any web page, including this one — practise with
   throwaway keys from tools 17 and 18. */
var SCHNORR_FORMAT = "p4a-schnorr-v1";
var SCHNORR_CHALLENGE_PREFIX = "privacy4all-schnorr-v1";
var SCHNORR_MAX_MESSAGE_CHARS = 2000;

/* The signed thing must be a real message: a whole,
   non-blank string under the same ceiling tool 17
   signs under. Anything else is null before any key
   is read. */
function validSchnorrMessage(message) {
  return typeof message === "string" && message.trim() !== "" &&
    message.length <= SCHNORR_MAX_MESSAGE_CHARS;
}

/* The challenge nobody draws: SHA-256 over the label,
   the commitment (canonicalised, so the hash names
   the point and not one spelling of it) and the
   message, reduced under the order. A reduced digest
   of zero is refused as null — with e = 0 the answer
   would be the nonce itself and would sign nothing;
   the signer simply draws a fresh nonce and tries
   again, an event with probability about 2^-256. */
function schnorrChallenge(commitmentHex, message) {
  var point = parseP256Point(commitmentHex);
  if (point === null || !validSchnorrMessage(message)) return Promise.resolve(null);
  var canonical = formatP256PublicKey(point);
  return sha256Hex(SCHNORR_CHALLENGE_PREFIX + "\n" + canonical + "\n" + message)
    .then(function (digest) {
      if (digest === null) return null;
      var value = BigInt("0x" + digest) % P256_N;
      if (value === P256_ZERO) return null;
      return p256IntToHex(value);
    });
}

/* The signature line: the format tag, the commitment
   (a whole 91-byte public key) and the response (a
   whole 64-hex scalar, zero allowed — an honest zero
   arises with probability about 2^-256 and the parser
   must not call it malformed). Pieces that do not
   check out are null, never a half-built line. */
function formatSchnorrSignature(commitmentHex, responseHex) {
  var point = parseP256Point(commitmentHex);
  var response = parseProofResponse(responseHex);
  if (point === null || response === null) return null;
  return SCHNORR_FORMAT + ":" + formatP256PublicKey(point) + ":" + response;
}

function parseSchnorrSignature(text) {
  if (typeof text !== "string") return null;
  var parts = text.trim().split(":");
  if (parts.length !== 3 || parts[0] !== SCHNORR_FORMAT) return null;
  var point = parseP256Point(parts[1]);
  var response = parseProofResponse(parts[2]);
  if (point === null || response === null) return null;
  return { commitment: formatP256PublicKey(point), response: response };
}

/* Signing: draw a fresh nonce, commit to it, hash the
   challenge out of the commitment and the message,
   and answer with tool 32's own arithmetic. A zero
   challenge or a zero answer — each a 2^-256 event —
   draws a fresh nonce and retries rather than handing
   over a signature that signs nothing. */
function signSchnorrMessage(privateKeyHex, message) {
  if (!validSchnorrMessage(message)) return Promise.resolve(null);
  return agreementPrivateParts(privateKeyHex).then(function (parts) {
    if (!parts) return null;
    var attempt = function (triesLeft) {
      var nonce = randomProofScalar();
      if (nonce === null) return Promise.resolve(null);
      var commitment = proofCommitmentForNonce(nonce);
      if (commitment === null) return Promise.resolve(null);
      return schnorrChallenge(commitment, message).then(function (challenge) {
        if (challenge === null) {
          return triesLeft > 1 ? attempt(triesLeft - 1) : null;
        }
        var response = proofResponseForScalar(parts.scalarHex, nonce, challenge);
        if (response === null) {
          return triesLeft > 1 ? attempt(triesLeft - 1) : null;
        }
        return formatSchnorrSignature(commitment, response);
      });
    };
    return attempt(8);
  });
}

/* Verifying: recompute the challenge from the message
   and the signature's own commitment, then check tool
   32's equation, s×G = R + e×Y. True only when it
   balances; false — never null — for well-formed
   pieces that do not balance (a message changed after
   signing, an answer nudged by one, a stranger's key,
   a commitment swapped in from another signature);
   null for any malformed piece, so "not signed" and
   "cannot be checked" never blur. */
function verifySchnorrSignature(publicKeyHex, message, signatureText) {
  var parsed = parseSchnorrSignature(signatureText);
  var pubPoint = parseP256Point(publicKeyHex);
  if (parsed === null || pubPoint === null || !validSchnorrMessage(message)) {
    return Promise.resolve(null);
  }
  return schnorrChallenge(parsed.commitment, message).then(function (challenge) {
    if (challenge === null) return null;
    var lhs = p256PointMultiply(BigInt("0x" + parsed.response), { x: P256_GX, y: P256_GY });
    if (lhs === null) return false;
    var commitPoint = parseP256Point(parsed.commitment);
    var rhs = p256PointAdd(commitPoint, p256PointMultiply(BigInt("0x" + challenge), pubPoint));
    if (rhs === null) return false;
    return lhs.x === rhs.x && lhs.y === rhs.y;
  });
}

/* ---------- 34. One of us signed it — ring signatures ----------

   Tools 17 and 33 answer "did THIS key sign?" — and the
   answer names the signer to anyone who checks. This
   tool answers a weaker question on purpose: "did ONE
   of these keys sign?" The signature is a ring
   signature (the Abe–Ohkubo–Suzuki construction, the
   classic Schnorr ring): the signer picks a ring of
   public keys — theirs among them, the rest borrowed
   from anyone whose key is published — and produces
   one line that verifies against the whole ring and
   no single member. The maths is a chain of tool 33's
   hashed challenges closed into a loop. Each member i
   contributes a link point E_i = z_i×G + c_i×Y_i, and
   each link's challenge is hashed from the previous
   link: c_{i+1} = SHA-256, under the label
   privacy4all-ring-v1, of that link point and the
   message. The signer alone can close the loop: they
   invent the other members' answers outright (random
   c and z values need no private key — the link point
   is computed forwards from them), walk the chain
   around from their own position, and at the last
   step the chain hands them the one challenge their
   own link must answer; their answer z_s = k − c_s·x
   is the only place in the whole signature where a
   private key is used, and it is algebraically
   indistinguishable from the invented answers around
   it. Verification walks the same chain from the
   seed challenge c_0 and checks it comes back to
   c_0 exactly: the loop closes only if every link
   balances, and exactly one link was answered with a
   private key — but the walk cannot say which.

   What that buys, and what it does not. The ambiguity
   is the privacy: a verifier learns "one of these
   keys signed" and nothing more — not with better
   maths, not with more time; every member is an
   equally good suspect from the signature alone. But
   the ring is the whole anonymity set: with two keys
   the ambiguity is a coin flip, and the six-key cap
   here is a page-practicality limit, not a strength
   claim. The flip side is just as plain: nobody in
   the ring had to agree to be in it. A ring is
   assembled from published public keys by the signer
   alone — the other members need not know, consent,
   or even exist as people the signer has met — so a
   ring signature is NOT a group endorsement and must
   never be read as "these people agreed": it proves
   one of the listed keys signed, full stop, and
   borrowing a famous key into your ring lends your
   statement none of their authority. This teaching
   version also carries no key image, so two
   signatures by the same signer cannot be linked by
   the signatures alone; real deployments choose
   deliberately here — Monero, the best-known ring
   signature system, adds a key image precisely so a
   ring member cannot spend the same note twice
   undetected, trading unlinkability away on purpose.
   The verdict keeps the house split: true for a loop
   that closes, false — never null — for well-formed
   pieces whose loop does not close (a changed
   message, a nudged answer, a member swapped out),
   null for malformed pieces. Honestly labelled: this
   is a real ring signature computed and checked
   locally, but it is not the signature format any
   chain or wallet checks; like tools 32 and 33 this
   is the maths in the open, not one of Midnight's
   Compact circuit proofs, and not an audited wallet
   and not side-channel resistant. Never paste a real
   wallet key or a production private key into any web
   page, including this one — practise with throwaway
   keys from tools 17 and 18. */
var RING_FORMAT = "p4a-ring-v1";
var RING_CHALLENGE_PREFIX = "privacy4all-ring-v1";
var RING_MIN_KEYS = 2;
var RING_MAX_KEYS = 6;

/* The ring itself: a list of whole public keys, one
   per line or comma-separated, or an array of them.
   Each is canonicalised, duplicates are refused — a
   doubled key would fake a bigger anonymity set than
   exists — and the count is held to this page's
   honest limits: at least two (a ring of one is just
   a signature, and tool 33 already signs), at most
   six. Anything else is null. */
function parseRingPublicKeys(text) {
  var tokens;
  if (Array.isArray(text)) tokens = text;
  else if (typeof text === "string") tokens = text.split(/[\s,;]+/);
  else return null;
  var keys = [];
  for (var i = 0; i < tokens.length; i++) {
    if (typeof tokens[i] !== "string") return null;
    if (tokens[i].trim() === "") continue;
    var point = parseP256Point(tokens[i]);
    if (point === null) return null;
    var canonical = formatP256PublicKey(point);
    if (keys.indexOf(canonical) !== -1) return null;
    keys.push(canonical);
  }
  if (keys.length < RING_MIN_KEYS || keys.length > RING_MAX_KEYS) return null;
  return keys;
}

/* One link's challenge: SHA-256 over the label, the
   link point (canonicalised, so the hash names the
   point and not one spelling of it) and the message,
   reduced under the order. A reduced digest of zero
   is refused as null — a zero challenge would make
   the next link carry no trace of that member's key;
   it arises with probability about 2^-256 and the
   signer simply starts again. */
function ringChallenge(message, pointHex) {
  var point = parseP256Point(pointHex);
  if (point === null || !validSchnorrMessage(message)) return Promise.resolve(null);
  var canonical = formatP256PublicKey(point);
  return sha256Hex(RING_CHALLENGE_PREFIX + "\n" + canonical + "\n" + message)
    .then(function (digest) {
      if (digest === null) return null;
      var value = BigInt("0x" + digest) % P256_N;
      if (value === P256_ZERO) return null;
      return p256IntToHex(value);
    });
}

/* One link of the chain, computed forwards:
   E = z×G + c×Y, returned as a canonical public key.
   A zero answer honestly contributes no z×G term, and
   the sum can be the point at infinity only when the
   pieces were arranged against each other — either
   way an unusable link is null, never a half-point.
   Synchronous and deterministic, so tests can pin it
   against Node's own curve arithmetic. */
function ringPointFor(challengeHex, responseHex, publicKeyHex) {
  var challenge = parseProofScalar(challengeHex);
  var response = parseProofResponse(responseHex);
  var pubPoint = parseP256Point(publicKeyHex);
  if (challenge === null || response === null || pubPoint === null) return null;
  var responsePoint = BigInt("0x" + response) === P256_ZERO ? null :
    p256PointMultiply(BigInt("0x" + response), { x: P256_GX, y: P256_GY });
  var challengePoint = p256PointMultiply(BigInt("0x" + challenge), pubPoint);
  var sum = p256PointAdd(responsePoint, challengePoint);
  if (sum === null) return null;
  return formatP256PublicKey(sum);
}

/* The signature line: the format tag, the seed
   challenge c_0 the verifier's walk starts from, and
   one answer per ring member, in ring order. It
   carries no key material and no marker of the
   signer's position — the answers are deliberately
   indistinguishable, the signer's included. Pieces
   that do not check out are null. */
function formatRingSignature(seedHex, responses) {
  var seed = parseProofScalar(seedHex);
  if (seed === null || !Array.isArray(responses)) return null;
  if (responses.length < RING_MIN_KEYS || responses.length > RING_MAX_KEYS) return null;
  var parts = [];
  for (var i = 0; i < responses.length; i++) {
    var response = parseProofResponse(responses[i]);
    if (response === null) return null;
    parts.push(response);
  }
  return RING_FORMAT + ":" + seed + ":" + parts.join(",");
}

function parseRingSignature(text) {
  if (typeof text !== "string") return null;
  var parts = text.trim().split(":");
  if (parts.length !== 3 || parts[0] !== RING_FORMAT) return null;
  var seed = parseProofScalar(parts[1]);
  if (seed === null) return null;
  var raw = parts[2].split(",");
  if (raw.length < RING_MIN_KEYS || raw.length > RING_MAX_KEYS) return null;
  var responses = [];
  for (var i = 0; i < raw.length; i++) {
    var response = parseProofResponse(raw[i]);
    if (response === null) return null;
    responses.push(response);
  }
  return { seed: seed, responses: responses };
}

/* Where the signer's own key sits in the ring: the
   private key's public point, read back through the
   platform when the key was imported, matched point
   for point against the ring's members. Not found is
   -1 — a key that is not in the ring cannot sign for
   it, however the request is phrased. */
function ringSignerIndex(points, parts) {
  var sx = BigInt("0x" + parts.pointHex.slice(2, 66));
  var sy = BigInt("0x" + parts.pointHex.slice(66, 130));
  for (var i = 0; i < points.length; i++) {
    if (points[i].x === sx && points[i].y === sy) return i;
  }
  return -1;
}

/* Signing: fix the signer's own link first from a
   fresh nonce (the commitment-first rule of tools 32
   and 33, kept), hash the next challenge out of it,
   then walk the ring inventing each other member's
   answer and link forwards — no private key but the
   signer's is touched, or exists, anywhere in this —
   until the walk arrives back at the signer's
   position carrying the one challenge only they can
   answer: z_s = k − c_s·x (mod n). A zero hashed
   challenge or an unusable link anywhere — each a
   vanishingly rare event — starts the attempt over
   with a fresh nonce rather than handing over a line
   that proves less than it claims. A private key
   whose public half is not in the ring is null: it
   cannot sign for a ring it is not part of. */
function signRingMessage(privateKeyHex, ringText, message) {
  var keys = parseRingPublicKeys(ringText);
  if (keys === null || !validSchnorrMessage(message)) return Promise.resolve(null);
  return agreementPrivateParts(privateKeyHex).then(function (parts) {
    if (!parts) return null;
    var points = [];
    for (var i = 0; i < keys.length; i++) points.push(parseP256Point(keys[i]));
    var s = ringSignerIndex(points, parts);
    if (s < 0) return null;
    var n = keys.length;
    var x = BigInt("0x" + parts.scalarHex);
    var attempt = function (triesLeft) {
      var nonce = randomProofScalar();
      if (nonce === null) return Promise.resolve(null);
      var c = new Array(n);
      var z = new Array(n);
      var startPoint = p256PointMultiply(BigInt("0x" + nonce), { x: P256_GX, y: P256_GY });
      if (startPoint === null) return Promise.resolve(null);
      var walk = ringChallenge(message, formatP256PublicKey(startPoint)).then(function (first) {
        if (first === null) return null;
        c[(s + 1) % n] = first;
        return true;
      });
      var chainStep = function (j) {
        walk = walk.then(function (ok) {
          if (!ok) return null;
          var i = (s + j) % n;
          var invented = randomProofScalar();
          if (invented === null) return null;
          z[i] = invented;
          var link = ringPointFor(c[i], invented, keys[i]);
          if (link === null) return null;
          return ringChallenge(message, link).then(function (next) {
            if (next === null) return null;
            c[(i + 1) % n] = next;
            return true;
          });
        });
      };
      for (var j = 1; j < n; j++) chainStep(j);
      return walk.then(function (ok) {
        if (!ok) return triesLeft > 1 ? attempt(triesLeft - 1) : null;
        var zs = (BigInt("0x" + nonce) - BigInt("0x" + c[s]) * x) % P256_N;
        if (zs < P256_ZERO) zs += P256_N;
        z[s] = p256IntToHex(zs);
        var line = formatRingSignature(c[0], z);
        if (line === null) return triesLeft > 1 ? attempt(triesLeft - 1) : null;
        return line;
      });
    };
    return attempt(8);
  });
}

/* Verifying: walk the chain from the signature's own
   seed, recomputing each link from that member's
   answer and key and hashing the next challenge out
   of it, and check the walk comes home to the seed
   exactly. True only when the loop closes; false —
   never null — for well-formed pieces whose loop
   does not close (a message changed after signing, an
   answer nudged by one, a ring member swapped or the
   ring reordered — order is part of the chain);
   null for any malformed piece, including an answer
   count that does not match the ring, so "not proved"
   and "cannot be checked" never blur. The walk
   establishes that exactly one ring member's private
   key was used — and, by construction, cannot say
   which one. */
function verifyRingSignature(ringText, message, signatureText) {
  var keys = parseRingPublicKeys(ringText);
  var parsed = parseRingSignature(signatureText);
  if (keys === null || parsed === null || !validSchnorrMessage(message)) {
    return Promise.resolve(null);
  }
  if (parsed.responses.length !== keys.length) return Promise.resolve(null);
  var walk = Promise.resolve(parsed.seed);
  var step = function (i) {
    walk = walk.then(function (current) {
      if (current === null || current === false) return current;
      var link = ringPointFor(current, parsed.responses[i], keys[i]);
      if (link === null) return false;
      return ringChallenge(message, link);
    });
  };
  for (var i = 0; i < keys.length; i++) step(i);
  return walk.then(function (finalChallenge) {
    if (finalChallenge === null || finalChallenge === false) return finalChallenge;
    return finalChallenge === parsed.seed;
  });
}

/* ---------- 35. Signed twice? It shows — linkable ring signatures ----------

   Tool 34 ends on a deliberate omission, named in its
   own text: it carries no key image, so two of its
   signatures by the same signer cannot be linked by
   the signatures alone — and real deployments, Monero
   first among them, choose the other way on purpose.
   This tool makes that other choice: the LSAG form of
   tool 34's ring, with a key image. The image is a
   second point bound to the signer's key alone:
   I = x×Hp(Y), where Hp hashes the signer's public
   key to a curve point nobody knows the discrete log
   of — built here by try-and-increment: hash the key
   under this tool's own label with a counter, read
   the digest as an x coordinate, keep the first x
   that lands on the curve (P-256's prime is 3 mod 4,
   so the square root is one exponentiation), and
   take the even root so the choice is canonical.
   Because Hp(Y)'s discrete log is unknown, nobody can
   compute a member's image from their public key
   alone and go down the ring matching images to
   names — the image names nobody. But the same key
   always produces the same image, whatever the ring,
   whatever the message, so two signatures carrying
   the same image came from the same key: linked,
   without being identified. The chain doubles
   accordingly: each member's link is now a pair,
   E_i = z_i×G + c_i×Y_i as before and
   F_i = z_i×Hp(Y_i) + c_i×I beside it, and each
   challenge hashes BOTH points with the message
   under the label privacy4all-linkable-ring-v1. The
   signer closes the loop exactly as in tool 34 —
   invent the other answers forwards, answer the
   final challenge with z_s = k − c_s·x — and the
   algebra closes on both points at once precisely
   because I really is x×Hp(Y_s): only the signer's
   private key can make the F chain come home.
   What the trade costs, stated plainly: linkability
   is the privacy given up. In this teaching version
   the image is tied to the member key itself, so the
   same signer is linkable across every ring and
   every message they ever sign here — real Monero
   ties its image to a one-time key per note, so only
   spending THE SAME note twice links, a narrower
   exposure than this page's. And linked is not
   identified: a matched image proves one key acted
   twice and still never says which member it was —
   the anonymity of tool 34 survives inside each
   single signature; what dies is the deniability
   that two signatures were strangers. The verdict
   keeps the house split: true, false — never null —
   for well-formed pieces whose loop does not close,
   null for malformed pieces. Honestly labelled: this
   is a real linkable ring signature computed and
   checked locally, but it is not the signature
   format any chain or wallet checks; like tools 32
   to 34 this is the maths in the open, not one of
   Midnight's Compact circuit proofs, and not an
   audited wallet and not side-channel resistant.
   Never paste a real wallet key or a production
   private key into any web page, including this one
   — practise with throwaway keys from tools 17
   and 18. */
var LINKRING_FORMAT = "p4a-lring-v1";
var LINKRING_CHALLENGE_PREFIX = "privacy4all-linkable-ring-v1";
var LINKRING_HASH_PREFIX = "privacy4all-linkable-hash-v1";
var LINKRING_MIN_KEYS = 2;
var LINKRING_MAX_KEYS = 6;

/* Field exponentiation by square-and-multiply — the
   one piece of field arithmetic tool 30's helpers do
   not already provide, needed for the square root
   below. Written in the same five-line spirit as
   p256Invert, which is this with exponent p−2. */
function p256Pow(base, exponent) {
  var b = p256Mod(base);
  var e = exponent;
  var result = P256_ONE;
  while (e > P256_ZERO) {
    if ((e & P256_ONE) === P256_ONE) result = p256Mod(result * b);
    b = p256Mod(b * b);
    e = e >> P256_ONE;
  }
  return result;
}

/* Hash a public key to a curve point whose discrete
   log nobody knows: try-and-increment over a counter,
   the digest read as an x coordinate, kept when
   x³−3x+b is a quadratic residue (checked by taking
   the root: the field prime is 3 mod 4, so a root of
   a residue is rhs^((p+1)/4)), with the even root
   chosen so every caller lands on the same point.
   Half of all x coordinates qualify, so 256 tries
   failing is a 2^-256 event. A key that is not a
   whole P-256 public key is null. */
function hashToPointP256(publicKeyHex) {
  var point = parseP256Point(publicKeyHex);
  if (point === null) return Promise.resolve(null);
  var canonical = formatP256PublicKey(point);
  var sqrtExponent = (P256_P + P256_ONE) / BigInt(4);
  var attempt = function (counter) {
    if (counter > 255) return Promise.resolve(null);
    return sha256Hex(LINKRING_HASH_PREFIX + "\n" + canonical + "\n" + counter)
      .then(function (digest) {
        if (digest === null) return null;
        var x = BigInt("0x" + digest) % P256_P;
        var rhs = p256Mod(x * x * x - P256_THREE * x + P256_B);
        var y = p256Pow(rhs, sqrtExponent);
        if (p256Mod(y * y) !== rhs) return attempt(counter + 1);
        if ((y & P256_ONE) === P256_ONE) y = P256_P - y;
        return formatP256PublicKey({ x: x, y: y });
      });
  };
  return attempt(0);
}

/* One link's challenge: SHA-256 over the label, BOTH
   link points (canonicalised) and the message,
   reduced under the order; zero refused as in
   tool 34. */
function linkableChallenge(message, eHex, fHex) {
  var ePoint = parseP256Point(eHex);
  var fPoint = parseP256Point(fHex);
  if (ePoint === null || fPoint === null || !validSchnorrMessage(message)) {
    return Promise.resolve(null);
  }
  return sha256Hex(LINKRING_CHALLENGE_PREFIX + "\n" +
      formatP256PublicKey(ePoint) + "\n" + formatP256PublicKey(fPoint) +
      "\n" + message)
    .then(function (digest) {
      if (digest === null) return null;
      var value = BigInt("0x" + digest) % P256_N;
      if (value === P256_ZERO) return null;
      return p256IntToHex(value);
    });
}

/* One link of the doubled chain, computed forwards:
   E = z×G + c×Y and F = z×Hp(Y) + c×I, as canonical
   points. Either sum landing on the point at
   infinity — pieces arranged against each other —
   is null, never a half-link. Synchronous and
   deterministic, like ringPointFor, so tests can pin
   it against Node's own curve arithmetic. */
function linkablePointPair(challengeHex, responseHex, publicKeyHex, hashPointHex, imageHex) {
  var challenge = parseProofScalar(challengeHex);
  var response = parseProofResponse(responseHex);
  var pubPoint = parseP256Point(publicKeyHex);
  var hashPoint = parseP256Point(hashPointHex);
  var imagePoint = parseP256Point(imageHex);
  if (challenge === null || response === null || pubPoint === null ||
      hashPoint === null || imagePoint === null) return null;
  var z = BigInt("0x" + response);
  var c = BigInt("0x" + challenge);
  var zG = z === P256_ZERO ? null : p256PointMultiply(z, { x: P256_GX, y: P256_GY });
  var e = p256PointAdd(zG, p256PointMultiply(c, pubPoint));
  var zH = z === P256_ZERO ? null : p256PointMultiply(z, hashPoint);
  var f = p256PointAdd(zH, p256PointMultiply(c, imagePoint));
  if (e === null || f === null) return null;
  return { e: formatP256PublicKey(e), f: formatP256PublicKey(f) };
}

/* The key image for one key pair: I = x×Hp(Y). The
   private key must be the private half of the public
   key offered — an image for some other pairing is
   refused as null, never computed. */
function linkableKeyImage(privateKeyHex, publicKeyHex) {
  var pubPoint = parseP256Point(publicKeyHex);
  if (pubPoint === null) return Promise.resolve(null);
  return agreementPrivateParts(privateKeyHex).then(function (parts) {
    if (!parts) return null;
    var sx = BigInt("0x" + parts.pointHex.slice(2, 66));
    var sy = BigInt("0x" + parts.pointHex.slice(66, 130));
    if (sx !== pubPoint.x || sy !== pubPoint.y) return null;
    return hashToPointP256(publicKeyHex).then(function (hashHex) {
      if (hashHex === null) return null;
      var image = p256PointMultiply(BigInt("0x" + parts.scalarHex),
        parseP256Point(hashHex));
      return image === null ? null : formatP256PublicKey(image);
    });
  });
}

/* The signature line: the format tag, the key image
   (a point in the same canonical shape as a public
   key — it is a point, not a key, and spends
   nothing), the seed challenge, and one answer per
   ring member, in ring order. */
function formatLinkableRingSignature(imageHex, seedHex, responses) {
  var imagePoint = parseP256Point(imageHex);
  var seed = parseProofScalar(seedHex);
  if (imagePoint === null || seed === null || !Array.isArray(responses)) return null;
  if (responses.length < LINKRING_MIN_KEYS || responses.length > LINKRING_MAX_KEYS) return null;
  var parts = [];
  for (var i = 0; i < responses.length; i++) {
    var response = parseProofResponse(responses[i]);
    if (response === null) return null;
    parts.push(response);
  }
  return LINKRING_FORMAT + ":" + formatP256PublicKey(imagePoint) + ":" +
    seed + ":" + parts.join(",");
}

function parseLinkableRingSignature(text) {
  if (typeof text !== "string") return null;
  var parts = text.trim().split(":");
  if (parts.length !== 4 || parts[0] !== LINKRING_FORMAT) return null;
  var imagePoint = parseP256Point(parts[1]);
  var seed = parseProofScalar(parts[2]);
  if (imagePoint === null || seed === null) return null;
  var raw = parts[3].split(",");
  if (raw.length < LINKRING_MIN_KEYS || raw.length > LINKRING_MAX_KEYS) return null;
  var responses = [];
  for (var i = 0; i < raw.length; i++) {
    var response = parseProofResponse(raw[i]);
    if (response === null) return null;
    responses.push(response);
  }
  return { image: formatP256PublicKey(imagePoint), seed: seed, responses: responses };
}

/* The link check itself: two signature lines are
   linked exactly when they carry the same key image.
   True or false for two well-formed lines, null when
   either cannot be parsed — "cannot be compared"
   never blurs into "not linked". */
function linkableRingSignaturesLinked(firstText, secondText) {
  var first = parseLinkableRingSignature(firstText);
  var second = parseLinkableRingSignature(secondText);
  if (first === null || second === null) return null;
  return first.image === second.image;
}

/* Every member's hash point, gathered in ring order;
   one unhashable member fails the whole list as
   null. */
function linkableHashPoints(keys) {
  var hashHexes = [];
  var chain = Promise.resolve(true);
  var collect = function (i) {
    chain = chain.then(function (ok) {
      if (!ok) return false;
      return hashToPointP256(keys[i]).then(function (hashHex) {
        if (hashHex === null) return false;
        hashHexes[i] = hashHex;
        return true;
      });
    });
  };
  for (var i = 0; i < keys.length; i++) collect(i);
  return chain.then(function (ok) { return ok ? hashHexes : null; });
}

/* Signing: tool 34's walk over a doubled chain. The
   key image is fixed from the signer's key before
   the walk starts; the signer's own pair of links is
   fixed from a fresh nonce; the walk invents each
   other member's answer and pair forwards until it
   arrives back at the signer's position carrying
   the one challenge only they can answer,
   z_s = k − c_s·x — which closes the F chain too,
   because I = x×Hp(Y_s) makes z_s×Hp(Y_s) + c_s×I
   come out to exactly k×Hp(Y_s). */
function signLinkableRingMessage(privateKeyHex, ringText, message) {
  var keys = parseRingPublicKeys(ringText);
  if (keys === null || !validSchnorrMessage(message)) return Promise.resolve(null);
  return agreementPrivateParts(privateKeyHex).then(function (parts) {
    if (!parts) return null;
    var points = [];
    for (var i = 0; i < keys.length; i++) points.push(parseP256Point(keys[i]));
    var s = ringSignerIndex(points, parts);
    if (s < 0) return null;
    return linkableHashPoints(keys).then(function (hashHexes) {
      if (hashHexes === null) return null;
      var x = BigInt("0x" + parts.scalarHex);
      var imagePoint = p256PointMultiply(x, parseP256Point(hashHexes[s]));
      if (imagePoint === null) return null;
      var image = formatP256PublicKey(imagePoint);
      var n = keys.length;
      var attempt = function (triesLeft) {
        var nonce = randomProofScalar();
        if (nonce === null) return Promise.resolve(null);
        var k = BigInt("0x" + nonce);
        var startE = p256PointMultiply(k, { x: P256_GX, y: P256_GY });
        var startF = p256PointMultiply(k, parseP256Point(hashHexes[s]));
        if (startE === null || startF === null) return Promise.resolve(null);
        var c = new Array(n);
        var z = new Array(n);
        var walk = linkableChallenge(message, formatP256PublicKey(startE),
          formatP256PublicKey(startF)).then(function (first) {
          if (first === null) return null;
          c[(s + 1) % n] = first;
          return true;
        });
        var chainStep = function (j) {
          walk = walk.then(function (ok) {
            if (!ok) return null;
            var i = (s + j) % n;
            var invented = randomProofScalar();
            if (invented === null) return null;
            z[i] = invented;
            var pair = linkablePointPair(c[i], invented, keys[i], hashHexes[i], image);
            if (pair === null) return null;
            return linkableChallenge(message, pair.e, pair.f).then(function (next) {
              if (next === null) return null;
              c[(i + 1) % n] = next;
              return true;
            });
          });
        };
        for (var j = 1; j < n; j++) chainStep(j);
        return walk.then(function (ok) {
          if (!ok) return triesLeft > 1 ? attempt(triesLeft - 1) : null;
          var zs = (k - BigInt("0x" + c[s]) * x) % P256_N;
          if (zs < P256_ZERO) zs += P256_N;
          z[s] = p256IntToHex(zs);
          var line = formatLinkableRingSignature(image, c[0], z);
          if (line === null) return triesLeft > 1 ? attempt(triesLeft - 1) : null;
          return line;
        });
      };
      return attempt(8);
    });
  });
}

/* Verifying: walk the doubled chain from the seed,
   recomputing each member's pair from their answer,
   their key, their hash point and the signature's
   own key image, and check the walk comes home to
   the seed exactly. True only when the loop closes
   on both points at once; false — never null — for
   well-formed pieces whose loop does not close,
   including a key image swapped in from another
   signature; null for any malformed piece. The walk
   establishes that one ring member's private key was
   used and that its image is the one in the line —
   and still cannot say which member. */
function verifyLinkableRingSignature(ringText, message, signatureText) {
  var keys = parseRingPublicKeys(ringText);
  var parsed = parseLinkableRingSignature(signatureText);
  if (keys === null || parsed === null || !validSchnorrMessage(message)) {
    return Promise.resolve(null);
  }
  if (parsed.responses.length !== keys.length) return Promise.resolve(null);
  return linkableHashPoints(keys).then(function (hashHexes) {
    if (hashHexes === null) return null;
    var walk = Promise.resolve(parsed.seed);
    var step = function (i) {
      walk = walk.then(function (current) {
        if (current === null || current === false) return current;
        var pair = linkablePointPair(current, parsed.responses[i], keys[i],
          hashHexes[i], parsed.image);
        if (pair === null) return false;
        return linkableChallenge(message, pair.e, pair.f);
      });
    };
    for (var i = 0; i < keys.length; i++) step(i);
    return walk.then(function (finalChallenge) {
      if (finalChallenge === null || finalChallenge === false) return finalChallenge;
      return finalChallenge === parsed.seed;
    });
  });
}

/* ---------- 36. Signed without seeing — blind signatures ----------

   Tools 33 to 35 all assume the signer knows what
   they are signing: the message is right there in the
   hash. Some signatures must work the other way. A
   token, a voucher, an anonymous credential is worth
   having precisely because the authority who issued
   it cannot recognise it when it comes back — if the
   issuer could, issuance and redemption would link,
   and the holder's privacy would be gone. David
   Chaum's answer is the blind signature: the signer
   signs, genuinely, with their real key — and never
   sees the message, the final commitment, or the real
   challenge. This tool runs the Schnorr form of it on
   the hub's P-256 curve, in four moves that mirror
   tool 32's exchange with the requester standing
   between the signer and the message.

   Move 1 is the signer's alone and needs no key at
   all: a fresh nonce k and its commitment R = k×G,
   exactly tool 32's first move, with the nonce kept
   in a signer-only state line (p4a-blindsigner-v1)
   that pairs it with its own commitment, as tool 32's
   state does. Move 2 is the blinding, and it is the
   requester's alone: they draw two secret scalars
   α and β, shift the commitment to
   R′ = R + α×G + β×Y — a point the signer never
   sees — hash the REAL challenge e′ out of R′ and
   the message with tool 33's own challenge, and send
   the signer only the blinded challenge e = e′ + β.
   To the signer, e is one more number in [1, n−1];
   it carries no trace of the message, of R′, or of
   e′ that they could check or later recognise.
   Move 3 is tool 32's answer, unchanged:
   s = k + e·x mod n, the one place a private key is
   used — used over a number the signer cannot read.
   Move 4 is the unblinding, the requester's alone
   again: s′ = s + α mod n, and the published line is
   an ordinary tool 33 signature (p4a-schnorr-v1)
   over R′, which tool 33's verifier — and nothing in
   this tool — checks: s′×G = R′ + e′×Y, because
   s′×G = R + α×G + (e′ + β)×Y and the β×Y folded
   into R′ at move 2 is exactly the β the blinded
   challenge added. The signer DID sign this message;
   the algebra says so and tool 33's check confirms
   it; they simply never saw it, and the line itself
   carries neither α nor β, so nothing in it points
   back to the signing session that produced it.

   The dangers are stated as plainly as the promise,
   because blindness cuts both ways. The signer is
   endorsing sight unseen: a blind-signing key must
   only ever sign for a service whose blinded
   challenges are worth honouring whoever presents
   them — tokens, vouchers, ballots — never for
   statements, because a blinded challenge can hide
   ANY message, including one the signer would refuse
   in the open. The nonce rule sharpens: one nonce
   behind two blinded answers leaks the private
   scalar exactly as in tools 32 and 33, and a signer
   who answers many sessions in parallel faces the
   ROS attack on blind Schnorr (Wagner's algorithm
   against concurrent sessions) — real deployments
   answer one session at a time, bind each commitment
   to a single session, or use constructions built to
   resist it; this teaching page does none of that
   coordination for you, and says so. The requester's
   blinding factors are load-bearing secrets of a
   smaller kind: leak α and β beside the published
   line and anyone can walk back to the session's
   blinded challenge — the unlinkability is only as
   good as their secrecy, and the request state line
   that carries them is never published. The verdict
   split is the house one: a move that cannot be
   performed is null, never a half-built line; there
   is no "false" here because nothing in this tool
   renders a verdict — the verdict is tool 33's, over
   the finished line. Honestly labelled: this is a
   real blind signature computed and checked locally,
   but it is not the signature format any chain or
   wallet checks, not one of Midnight's Compact
   circuit proofs, and not an audited wallet and not
   side-channel resistant. Never paste a real wallet
   key or a production private key into any web page,
   including this one — practise with throwaway keys
   from tools 17 and 18. */
var BLINDSIGN_SIGNER_FORMAT = "p4a-blindsigner-v1";
var BLINDSIGN_REQUEST_FORMAT = "p4a-blindreq-v1";

/* The signer-only state line: the format tag, the
   nonce, and the commitment it belongs to — the same
   pairing discipline as tool 32's state, under this
   tool's own tag, so a state can never be quietly
   paired with a different commitment, or offered to
   another tool, at answer time. */
function formatBlindSignerState(nonceHex, commitmentHex) {
  var nonce = parseProofScalar(nonceHex);
  var point = parseP256Point(commitmentHex);
  if (nonce === null || point === null) return null;
  return BLINDSIGN_SIGNER_FORMAT + ":" + nonce + ":" + formatP256PublicKey(point);
}

function parseBlindSignerState(text) {
  if (typeof text !== "string") return null;
  var parts = text.trim().split(":");
  if (parts.length !== 3 || parts[0] !== BLINDSIGN_SIGNER_FORMAT) return null;
  var nonce = parseProofScalar(parts[1]);
  var point = parseP256Point(parts[2]);
  if (nonce === null || point === null) return null;
  return { nonce: nonce, commitment: formatP256PublicKey(point) };
}

/* Move 1, the signer's start: draw a fresh nonce,
   commit to it, hand back the public commitment and
   the secret state line. No private key is read here
   — a commitment binds a nonce, not a key, and the
   key is asked once, at answer time, and never stored
   anywhere. Synchronous, like tool 32's commitment
   arithmetic: no randomness, no start — null, never
   a predictable commitment. */
function makeBlindSignerCommitment() {
  var nonce = randomProofScalar();
  if (nonce === null) return null;
  var commitment = proofCommitmentForNonce(nonce);
  var state = formatBlindSignerState(nonce, commitment);
  if (commitment === null || state === null) return null;
  return { commitment: commitment, state: state };
}

/* Move 2's arithmetic, deterministic once the two
   blinding factors exist: shift the signer's
   commitment by α×G and β×Y to the final commitment
   the signer never sees, hash the real challenge out
   of it and the message with tool 33's own challenge,
   and blind that challenge by β. Any sum landing on
   the point at infinity, a zero factor, or a blinded
   challenge of exactly zero is null — the requester
   simply draws fresh factors, an event with
   probability about 2^-256 for the honest sums. */
function blindChallengeFor(commitmentHex, publicKeyHex, message, alphaHex, betaHex) {
  var commitPoint = parseP256Point(commitmentHex);
  var pubPoint = parseP256Point(publicKeyHex);
  var alpha = parseProofScalar(alphaHex);
  var beta = parseProofScalar(betaHex);
  if (commitPoint === null || pubPoint === null || alpha === null ||
      beta === null || !validSchnorrMessage(message)) {
    return Promise.resolve(null);
  }
  var shifted = p256PointAdd(commitPoint,
    p256PointMultiply(BigInt("0x" + alpha), { x: P256_GX, y: P256_GY }));
  if (shifted !== null) {
    shifted = p256PointAdd(shifted,
      p256PointMultiply(BigInt("0x" + beta), pubPoint));
  }
  if (shifted === null) return Promise.resolve(null);
  var finalCommitment = formatP256PublicKey(shifted);
  return schnorrChallenge(finalCommitment, message).then(function (challenge) {
    if (challenge === null) return null;
    var blinded = (BigInt("0x" + challenge) + BigInt("0x" + beta)) % P256_N;
    if (blinded === P256_ZERO) return null;
    return { finalCommitment: finalCommitment, challenge: challenge,
             blindedChallenge: p256IntToHex(blinded) };
  });
}

/* The requester-only state line: the format tag, the
   two blinding factors, and the final commitment
   they produce — everything move 4 needs, and
   nothing move 3 ever sees. This line is a secret of
   the requester's: published beside the finished
   signature, α and β would walk anyone back to the
   signing session. */
function formatBlindRequestState(alphaHex, betaHex, finalCommitmentHex) {
  var alpha = parseProofScalar(alphaHex);
  var beta = parseProofScalar(betaHex);
  var point = parseP256Point(finalCommitmentHex);
  if (alpha === null || beta === null || point === null) return null;
  return BLINDSIGN_REQUEST_FORMAT + ":" + alpha + ":" + beta + ":" +
    formatP256PublicKey(point);
}

function parseBlindRequestState(text) {
  if (typeof text !== "string") return null;
  var parts = text.trim().split(":");
  if (parts.length !== 4 || parts[0] !== BLINDSIGN_REQUEST_FORMAT) return null;
  var alpha = parseProofScalar(parts[1]);
  var beta = parseProofScalar(parts[2]);
  var point = parseP256Point(parts[3]);
  if (alpha === null || beta === null || point === null) return null;
  return { alpha: alpha, beta: beta, finalCommitment: formatP256PublicKey(point) };
}

/* Move 2, the requester's whole job: draw the two
   blinding factors, run the shift, and hand back the
   blinded challenge — the only thing the signer is
   ever shown — and the requester-only state line.
   The message, the real challenge and the final
   commitment stay on this side of the exchange. */
function blindSignatureRequest(commitmentHex, publicKeyHex, message) {
  if (parseP256Point(commitmentHex) === null ||
      parseP256Point(publicKeyHex) === null ||
      !validSchnorrMessage(message)) {
    return Promise.resolve(null);
  }
  var attempt = function (triesLeft) {
    var alpha = randomProofScalar();
    var beta = randomProofScalar();
    if (alpha === null || beta === null) return Promise.resolve(null);
    return blindChallengeFor(commitmentHex, publicKeyHex, message, alpha, beta)
      .then(function (blinded) {
        if (blinded === null) {
          return triesLeft > 1 ? attempt(triesLeft - 1) : null;
        }
        var state = formatBlindRequestState(alpha, beta, blinded.finalCommitment);
        if (state === null) {
          return triesLeft > 1 ? attempt(triesLeft - 1) : null;
        }
        return { blindedChallenge: blinded.blindedChallenge, state: state };
      });
  };
  return attempt(8);
}

/* Move 3, the signer's answer: tool 32's arithmetic,
   unchanged, over a challenge the signer cannot read.
   The state supplies the nonce — and is checked
   against its own commitment first, recomputed from
   the nonce, so a state paired with a commitment it
   did not come from answers nothing. A blinded
   challenge of zero is refused by the scalar gate
   itself: answering it would hand over the nonce. */
function blindSign(privateKeyHex, signerStateText, blindedChallengeHex) {
  var state = parseBlindSignerState(signerStateText);
  var challenge = parseProofScalar(blindedChallengeHex);
  if (state === null || challenge === null) return Promise.resolve(null);
  if (proofCommitmentForNonce(state.nonce) !== state.commitment) {
    return Promise.resolve(null);
  }
  return agreementPrivateParts(privateKeyHex).then(function (parts) {
    if (!parts) return null;
    return proofResponseForScalar(parts.scalarHex, state.nonce, challenge);
  });
}

/* Move 4, the requester's finish: lift the blinded
   answer by α and publish the line — an ordinary
   p4a-schnorr-v1 signature over the final commitment,
   checkable by tool 33's verifier and by nothing in
   this tool. The line carries neither factor: the
   session that produced it is not recoverable from
   it. A malformed state or answer is null, never a
   half-built line. */
function unblindSignature(requestStateText, blindedResponseHex) {
  var state = parseBlindRequestState(requestStateText);
  var response = parseProofResponse(blindedResponseHex);
  if (state === null || response === null) return null;
  var lifted = (BigInt("0x" + response) + BigInt("0x" + state.alpha)) % P256_N;
  return formatSchnorrSignature(state.finalCommitment, p256IntToHex(lifted));
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
                     parseSealed, sealMessage, unsealMessage,
                     SIGN_FORMAT, SIGN_MAX_MESSAGE_CHARS,
                     SIGN_PUBLIC_KEY_BYTES, SIGN_PRIVATE_KEY_BYTES, SIGN_SIGNATURE_BYTES,
                     parseSignature, generateSigningKeyPair, signMessage, verifySignature,
                     AGREE_PUBLIC_KEY_BYTES, AGREE_PRIVATE_KEY_BYTES, AGREE_SHARED_SECRET_BYTES,
                     AGREE_FINGERPRINT_PREFIX, generateAgreementKeyPair,
                     deriveSharedSecret, parseSharedSecret, sharedSecretFingerprint,
                     DERIVE_KEY_BYTES, DERIVE_SALT_BYTES,
                     DERIVE_SECRET_MIN_BYTES, DERIVE_SECRET_MAX_BYTES,
                     DERIVE_PURPOSE_CATALOG, getDerivePurpose,
                     parseDeriveSecret, parseDeriveSalt, parseDerivedKey,
                     deriveSessionKey, checkDerivedKey,
                     KEYSEAL_FORMAT, KEYSEAL_KEY_BYTES, KEYSEAL_IV_BYTES,
                     KEYSEAL_MAX_MESSAGE_CHARS, parseKeySealed,
                     sealWithSessionKey, openWithSessionKey,
                     AUTHSEAL_FORMAT, AUTHSEAL_ENVELOPE_FORMAT,
                     AUTHSEAL_MAX_MESSAGE_CHARS, parseAuthSealed,
                     parseSignedEnvelope, signAndSealMessage,
                     openAuthenticatedMessage,
                     RATCHET_STATE_FORMAT, RATCHET_MSG_INFO,
                     RATCHET_NEXT_INFO, RATCHET_MAX_INDEX,
                     parseChainState, formatChainState,
                     startChainState, ratchetStep,
                     sealRatchetMessage, openRatchetMessage,
                     HEAL_INFO, healChainState,
                     PADDEDSEAL_FORMAT, PAD_MAGIC, PAD_HEADER_BYTES,
                     PAD_BUCKETS, PAD_MAX_MESSAGE_BYTES,
                     paddedBucketFor, buildPaddedPayload,
                     extractPaddedMessage, parsePaddedSealed,
                     sealPaddedMessage, openPaddedMessage,
                     OOOSEAL_FORMAT, SKIPPED_FORMAT,
                     SKIPPED_MAX_KEYS,
                     parseNumberedSealed, formatSkippedStore,
                     parseSkippedStore, emptySkippedStore,
                     sealNumberedMessage, openNumberedMessage,
                     BOX_FORMAT, BOX_KEY_INFO, BOX_MAX_MESSAGE_CHARS,
                     parseBoxSealed, deriveBoxKey,
                     sealBoxMessage, openBoxMessage,
                     AUTHBOX_FORMAT, AUTHBOX_KEY_INFO, AUTHBOX_MAX_MESSAGE_CHARS,
                     parseAuthBoxSealed, deriveAuthBoxKey,
                     sealAuthenticatedBoxMessage, openAuthenticatedBoxMessage,
                     SAFETY_PREFIX, SAFETY_GROUPS, SAFETY_GROUP_DIGITS,
                     parseSafetyPublicKey, formatSafetyNumber, parseSafetyNumber,
                     safetyNumberForKeys, checkSafetyNumber,
                     ONETIME_PREFIX, ONETIME_DESTINATION_BYTES,
                     parseOneTimeDestination, oneTimeDestinationForSecret,
                     makeOneTimeDestination, scanOneTimeDestination,
                     checkOneTimeDestination,
                     SPENDKEY_PREFIX, SPENDKEY_SPKI_PREFIX_HEX,
                     parseP256Point, formatP256PublicKey,
                     spendTweakFromHash, parseSpendTweak, oneTimeSpendTweak,
                     oneTimePublicKeyForTweak, oneTimePrivateKeyForTweak,
                     makeOneTimeSpendKey, claimOneTimeSpendKey,
                     matchOneTimeSpendKey,
                     VIEWKEY_SCAN_PREFIX, VIEWKEY_SPEND_PREFIX,
                     watchedDestinationForSecret, watchedSpendTweak,
                     makeWatchedPayment, scanWatchedPayment,
                     checkWatchedPayment, claimWatchedSpendKey,
                     ZKPROOF_STATE_FORMAT,
                     parseProofScalar, parseProofResponse,
                     proofCommitmentForNonce, formatProofState,
                     parseProofState, makeProofCommitment,
                     generateProofChallenge, proofResponseForScalar,
                     respondToProofChallenge, verifyProof,
                     SCHNORR_FORMAT, SCHNORR_CHALLENGE_PREFIX,
                     SCHNORR_MAX_MESSAGE_CHARS,
                     validSchnorrMessage, schnorrChallenge,
                     formatSchnorrSignature, parseSchnorrSignature,
                     signSchnorrMessage, verifySchnorrSignature,
                     RING_FORMAT, RING_CHALLENGE_PREFIX,
                     RING_MIN_KEYS, RING_MAX_KEYS,
                     parseRingPublicKeys, ringChallenge, ringPointFor,
                     formatRingSignature, parseRingSignature,
                     signRingMessage, verifyRingSignature,
                     LINKRING_FORMAT, LINKRING_CHALLENGE_PREFIX,
                     LINKRING_HASH_PREFIX,
                     LINKRING_MIN_KEYS, LINKRING_MAX_KEYS,
                     p256Pow, hashToPointP256, linkableChallenge,
                     linkablePointPair, linkableKeyImage,
                     formatLinkableRingSignature, parseLinkableRingSignature,
                     linkableRingSignaturesLinked,
                     signLinkableRingMessage, verifyLinkableRingSignature,
                     BLINDSIGN_SIGNER_FORMAT, BLINDSIGN_REQUEST_FORMAT,
                     formatBlindSignerState, parseBlindSignerState,
                     makeBlindSignerCommitment, blindChallengeFor,
                     formatBlindRequestState, parseBlindRequestState,
                     blindSignatureRequest, blindSign, unblindSignature };
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

    /* --- sign it — prove it came from you (ECDSA P-256) --- */
    document.getElementById("sign-keys").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var pubOut = document.getElementById("sign-pub-out");
      var privOut = document.getElementById("sign-priv-out");
      var status = document.getElementById("sign-keys-result");
      status.textContent = "Making keys locally…";
      generateSigningKeyPair().then(function (pair) {
        if (!pair) {
          pubOut.value = "";
          privOut.value = "";
          status.textContent = "This browser could not make keys locally. Nothing was sent anywhere — try a current browser.";
          return;
        }
        pubOut.value = pair.publicKey;
        privOut.value = pair.privateKey;
        document.getElementById("sign-priv-in").value = pair.privateKey;
        document.getElementById("verify-pub").value = pair.publicKey;
        status.textContent = "Keys made locally — nothing was stored or sent, and reloading this page " +
          "loses them. The public key is safe to publish: it is how people recognise your signatures. " +
          "The private key IS the identity: anyone holding it can sign as you, so guard it like a seed " +
          "phrase and never share it. Your private key was copied into the signing box below so you can " +
          "sign right away; the checking box got your public key.";
      });
    });
    document.getElementById("sign-do").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var out = document.getElementById("sign-out");
      var status = document.getElementById("sign-result");
      status.textContent = "Signing locally…";
      signMessage(document.getElementById("sign-priv-in").value,
        document.getElementById("sign-message").value).then(function (sig) {
        if (!sig) {
          out.value = "";
          status.textContent = "Enter a message (up to " + SIGN_MAX_MESSAGE_CHARS + " characters) and " +
            "paste a whole private key made by the key box above. A public key cannot sign — that is the point.";
          return;
        }
        out.value = sig;
        status.textContent = "Signed locally — your private key never left this page. Share the message, " +
          "your public key and this signature together: anyone can then check the words are exactly yours " +
          "and unchanged. The signature does not hide the message and does not prove when you signed it.";
      });
    });
    document.getElementById("sign-verify").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var status = document.getElementById("verify-result");
      status.textContent = "Checking locally…";
      verifySignature(document.getElementById("verify-pub").value,
        document.getElementById("verify-message").value,
        document.getElementById("verify-sig").value).then(function (ok) {
        if (ok === null) {
          status.textContent = "That cannot be checked: paste a whole public key, the exact message, " +
            "and a whole p4a-sig-v1 signature line. Malformed input is different from a failed check.";
          return;
        }
        status.textContent = ok
          ? "✓ Signature checks out — this exact message was signed by whoever holds the private key " +
            "matching that public key, and not one character has changed since. It proves the key, not a " +
            "legal name: trust the key because you got it from the person directly, not from this page."
          : "✗ Signature does NOT check out — the message was changed after signing, or this signature " +
            "belongs to a different message or a different key. Do not trust it as this signer's words.";
      });
    });

    /* --- agree on a secret nobody saw (ECDH P-256) --- */
    document.getElementById("agree-keys").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var pubOut = document.getElementById("agree-pub-out");
      var privOut = document.getElementById("agree-priv-out");
      var status = document.getElementById("agree-keys-result");
      status.textContent = "Making your agreement keys locally…";
      generateAgreementKeyPair().then(function (pair) {
        if (!pair) {
          pubOut.value = "";
          privOut.value = "";
          status.textContent = "This browser could not make keys locally. Nothing was sent anywhere — try a current browser.";
          return;
        }
        pubOut.value = pair.publicKey;
        privOut.value = pair.privateKey;
        document.getElementById("agree-priv-in").value = pair.privateKey;
        document.getElementById("agree-check-pub").value = pair.publicKey;
        status.textContent = "Your keys are made locally — nothing was stored or sent. Publish the public " +
          "key: it is the only thing you exchange. Guard the private key like a seed phrase: whoever " +
          "holds it can complete agreements as you. Your private key was copied into the agreement box " +
          "below, and your public key into the other-side check box at the bottom.";
      });
    });
    document.getElementById("agree-peer").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var pubOut = document.getElementById("agree-peer-pub-out");
      var privOut = document.getElementById("agree-peer-priv-out");
      var status = document.getElementById("agree-peer-result");
      status.textContent = "Making the other person's keys locally…";
      generateAgreementKeyPair().then(function (pair) {
        if (!pair) {
          pubOut.value = "";
          privOut.value = "";
          status.textContent = "This browser could not make keys locally. Nothing was sent anywhere — try a current browser.";
          return;
        }
        pubOut.value = pair.publicKey;
        privOut.value = pair.privateKey;
        document.getElementById("agree-peer-pub").value = pair.publicKey;
        document.getElementById("agree-check-priv").value = pair.privateKey;
        status.textContent = "In real life the other person makes these on their own device and only " +
          "the public key ever travels — this box exists so you can practise both sides on one page. " +
          "Their public key was copied into your agreement box, and their private key into the " +
          "other-side check box (on their device, that is where it would stay).";
      });
    });
    document.getElementById("agree-do").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var out = document.getElementById("agree-out");
      var fpOut = document.getElementById("agree-fingerprint-out");
      var status = document.getElementById("agree-result");
      status.textContent = "Agreeing locally…";
      deriveSharedSecret(document.getElementById("agree-priv-in").value,
        document.getElementById("agree-peer-pub").value).then(function (secret) {
        if (!secret) {
          out.value = "";
          fpOut.value = "";
          status.textContent = "That cannot agree: paste your whole private key and the other person's " +
            "whole public key, both made by the key boxes above. A public key cannot stand in for a " +
            "private key — that is the point.";
          return;
        }
        out.value = secret;
        return sharedSecretFingerprint(secret).then(function (fp) {
          fpOut.value = fp || "";
          status.textContent = "Agreed locally — and the secret itself was never exchanged: it was " +
            "computed on this device from your private key and their public key alone. It is shown here " +
            "only for practice, so you can compare it with the other side below; a real app never " +
            "displays it and never uses it raw — it runs the secret through a key-derivation function " +
            "first. The fingerprint is the part that is safe to compare out loud.";
        });
      });
    });
    document.getElementById("agree-check").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var out = document.getElementById("agree-check-out");
      var status = document.getElementById("agree-check-result");
      status.textContent = "Agreeing from the other side locally…";
      deriveSharedSecret(document.getElementById("agree-check-priv").value,
        document.getElementById("agree-check-pub").value).then(function (secret) {
        if (!secret) {
          out.value = "";
          status.textContent = "That cannot agree: paste the other person's whole private key and " +
            "your whole public key, both made by the key boxes above.";
          return;
        }
        out.value = secret;
        var mine = document.getElementById("agree-out").value.trim().toLowerCase();
        status.textContent = (mine && mine === secret)
          ? "✓ Same secret, computed independently from the other side — and it was never sent anywhere. " +
            "Two devices that have only exchanged public keys now share a secret nobody else can work " +
            "out from those public keys. That is the handshake under private messaging."
          : "The other side's secret is in the box — run your agreement above and compare: the two " +
            "boxes must match exactly. If they do not, one of the four keys is from a different pair.";
      });
    });

    /* --- stretch one secret into proper keys (HKDF) --- */
    document.getElementById("derive-do").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var out = document.getElementById("derive-out");
      var status = document.getElementById("derive-result");
      var purposeId = document.getElementById("derive-purpose").value;
      status.textContent = "Deriving locally…";
      deriveSessionKey(document.getElementById("derive-secret").value, purposeId,
        document.getElementById("derive-salt").value).then(function (key) {
        if (!key) {
          out.value = "";
          status.textContent = "That cannot derive: paste a whole shared secret as hex " +
            "(" + DERIVE_SECRET_MIN_BYTES + "–" + DERIVE_SECRET_MAX_BYTES + " bytes — tool 18's " +
            "output is 32), pick a purpose, and give either no salt or a whole " +
            DERIVE_SALT_BYTES + "-byte hex salt, the kind tool 11 generates.";
          return;
        }
        out.value = key;
        var purpose = getDerivePurpose(purposeId);
        status.textContent = "Derived locally — your secret never left this page, and the key " +
          "cannot be run backwards into it. " + (purpose ? purpose.note + " " : "") +
          "The other side derives the matching key from the same secret, the same purpose " +
          "and the same salt; change any one of the three and the key is unrelated.";
      });
    });
    document.getElementById("derive-check").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var status = document.getElementById("derive-check-result");
      status.textContent = "Checking locally…";
      checkDerivedKey(document.getElementById("derive-check-secret").value,
        document.getElementById("derive-check-purpose").value,
        document.getElementById("derive-check-salt").value,
        document.getElementById("derive-check-key").value).then(function (ok) {
        if (ok === null) {
          status.textContent = "That cannot be checked: paste the whole secret, the same " +
            "purpose and salt used to derive, and a whole 32-byte derived key as hex. " +
            "Malformed input is different from a failed check.";
          return;
        }
        status.textContent = ok
          ? "✓ Match — this key is exactly what that secret, purpose and salt derive. " +
            "Anyone holding the same three inputs derives the same key, and nobody else can."
          : "✗ No match — well-formed inputs, but they derive a different key. Check the " +
            "purpose and salt first: either one being different gives an unrelated key, " +
            "which is the separation working as designed, not an error to override.";
      });
    });

    /* --- use the key: lock a message with a derived key --- */
    document.getElementById("keyseal-make").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var out = document.getElementById("keyseal-out");
      var status = document.getElementById("keyseal-result");
      status.textContent = "Locking locally…";
      sealWithSessionKey(document.getElementById("keyseal-message").value,
        document.getElementById("keyseal-key").value).then(function (sealed) {
        if (!sealed) {
          out.value = "";
          status.textContent = "That cannot lock: write a message and paste a whole " +
            "32-byte derived key as hex — the kind tool 19 derives (use its messaging " +
            "purpose for messages). A password is not a key here.";
          return;
        }
        out.value = sealed;
        status.textContent = "Locked locally with that exact key — no password was " +
          "involved and nothing left this page. Only the same derived key opens it: " +
          "the other side derives it from the same secret, purpose and salt (tools " +
          "18–19). Send the locked text anywhere; send the key nowhere — whoever " +
          "holds it reads everything locked with it.";
      });
    });
    document.getElementById("keyseal-open").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var out = document.getElementById("keyopen-out");
      var status = document.getElementById("keyopen-result");
      status.textContent = "Opening locally…";
      openWithSessionKey(document.getElementById("keyopen-sealed").value,
        document.getElementById("keyopen-key").value).then(function (msg) {
        if (msg === null) {
          out.value = "";
          status.textContent = "That does not open: either the key is not a whole " +
            "32-byte derived key, or it is not the key this was locked with, or the " +
            "locked text was changed or cut short. AES-GCM fails outright rather " +
            "than guess — a wrong key and a tampered message look the same from here.";
          return;
        }
        out.value = msg;
        status.textContent = "✓ Opened locally — that is exactly the message that was " +
          "locked with this key, unchanged: the GCM tag checked out, which no other " +
          "key and no altered byte can produce.";
      });
    });

    /* --- know it's really from them: sign it, then seal it --- */
    document.getElementById("authseal-make").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var out = document.getElementById("authseal-out");
      var status = document.getElementById("authseal-result");
      status.textContent = "Signing, then sealing, locally…";
      signAndSealMessage(document.getElementById("authseal-priv").value,
        document.getElementById("authseal-message").value,
        document.getElementById("authseal-key").value).then(function (sealed) {
        if (!sealed) {
          out.value = "";
          status.textContent = "That cannot seal: write a message, paste your whole " +
            "signing private key from tool 17's key maker, and a whole 32-byte derived " +
            "key from tool 19. A signing key is not a session key, and neither box " +
            "accepts the other's contents.";
          return;
        }
        out.value = sealed;
        status.textContent = "Signed with your signing key, then sealed with the " +
          "session key — locally, and nothing left this page. Send the sealed text " +
          "anywhere. The receiver opens it with the same session key and checks the " +
          "signature inside against your PUBLIC signing key — which is the part you " +
          "can share openly, as long as they get it from really you.";
      });
    });
    document.getElementById("authseal-open").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var out = document.getElementById("authopen-out");
      var status = document.getElementById("authopen-result");
      status.textContent = "Opening, then checking the signature, locally…";
      openAuthenticatedMessage(document.getElementById("authopen-sealed").value,
        document.getElementById("authopen-key").value,
        document.getElementById("authopen-pub").value).then(function (res) {
        if (res === null) {
          out.value = "";
          status.textContent = "That does not open: either a box is malformed (an " +
            "authsealed line, a whole 32-byte derived key, a whole public signing " +
            "key), or the session key is not the one it was sealed with, or the " +
            "sealed text was changed or cut short — or what is inside is not a " +
            "signed envelope at all, like a plain tool-20 seal.";
          return;
        }
        out.value = res.message;
        status.textContent = res.verified
          ? "✓ Opened — and the signature inside checks out against that public " +
            "key. This message is exactly what the holder of the matching private " +
            "signing key signed: private AND from them, as far as the keys go. " +
            "That is only as strong as your certainty that the public key is " +
            "really theirs."
          : "⚠ Opened — it decrypted fine — but the signature inside does NOT " +
            "check out against that public key. The words are in the box so you " +
            "can read them, but read them as unauthenticated: someone with the " +
            "session key sealed this, and it was not signed by the key you " +
            "checked. Private is not the same as from them.";
      });
    });

    /* --- one key per message: the ratchet --- */
    document.getElementById("ratchet-start").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var out = document.getElementById("ratchet-start-out");
      var status = document.getElementById("ratchet-start-result");
      var state = startChainState(document.getElementById("ratchet-start-in").value);
      if (state === null) {
        out.value = "";
        status.textContent = "That cannot start a chain: paste a whole 32-byte " +
          "derived key from tool 19. The session key becomes the chain key at " +
          "position 0 — used for exactly one message, then never again.";
        return;
      }
      out.value = state;
      status.textContent = "Chain started at position 0. Both sides start from " +
        "the same session key, so both hold this same starting state. Keep your " +
        "copy for sending; replies need their own chain, started from a " +
        "different tool-19 purpose or salt. After your first message this state " +
        "is spent — replace it with the next state the seal box gives you, and " +
        "let the old one go.";
    });
    document.getElementById("ratchet-seal").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var out = document.getElementById("ratchet-seal-out");
      var nextOut = document.getElementById("ratchet-seal-next");
      var status = document.getElementById("ratchet-seal-result");
      status.textContent = "Stepping the chain and sealing locally…";
      sealRatchetMessage(document.getElementById("ratchet-seal-state").value,
        document.getElementById("ratchet-seal-message").value).then(function (res) {
        if (res === null) {
          out.value = "";
          nextOut.value = "";
          status.textContent = "That cannot seal: paste your current chain " +
            "state (a whole p4a-chain-v1 line that has not hit the chain's " +
            "labelled cap) and write a message. A blank message, a spent or " +
            "malformed state, or a chain at its cap seals nothing.";
          return;
        }
        out.value = res.sealed;
        nextOut.value = res.state;
        status.textContent = "Sealed with this position's own key — and the " +
          "chain has already moved on. Replace your saved state with the NEXT " +
          "state below. The state you pasted is spent: once you overwrite it, " +
          "this message's key cannot be recomputed from anything you still " +
          "hold. That is the ratchet working, not an inconvenience.";
      });
    });
    document.getElementById("ratchet-open").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var out = document.getElementById("ratchet-open-out");
      var nextOut = document.getElementById("ratchet-open-next");
      var status = document.getElementById("ratchet-open-result");
      status.textContent = "Stepping the chain and opening locally…";
      openRatchetMessage(document.getElementById("ratchet-open-state").value,
        document.getElementById("ratchet-open-in").value).then(function (res) {
        if (res === null) {
          out.value = "";
          nextOut.value = "";
          status.textContent = "That does not open at this position — and your " +
            "state has NOT advanced, nothing was consumed. The usual causes: " +
            "this is a later message and an earlier one has not arrived yet " +
            "(this simple chain opens strictly in order — keep the sealed text " +
            "and retry when the missing message lands), it is a replay of a " +
            "message you already opened, it belongs to the other direction's " +
            "chain, or the sealed text was changed or cut short.";
          return;
        }
        out.value = res.message;
        nextOut.value = res.state;
        status.textContent = "✓ Opened with this position's key — and the chain " +
          "has moved on. Replace your saved state with the NEXT state below: " +
          "the one you pasted can never open this message again, which is " +
          "exactly what protects it if your state leaks later.";
      });
    });

    /* --- heal the chain: a fresh agreement restarts the ratchet --- */
    document.getElementById("heal-keys").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var pubOut = document.getElementById("heal-pub-out");
      var privOut = document.getElementById("heal-priv-out");
      var status = document.getElementById("heal-keys-result");
      status.textContent = "Making your fresh agreement pair locally…";
      generateAgreementKeyPair().then(function (pair) {
        if (!pair) {
          pubOut.value = "";
          privOut.value = "";
          status.textContent = "This browser could not make keys locally. Nothing was sent anywhere — try a current browser.";
          return;
        }
        pubOut.value = pair.publicKey;
        privOut.value = pair.privateKey;
        document.getElementById("heal-priv-in").value = pair.privateKey;
        status.textContent = "Your fresh pair is made locally — nothing was stored or sent. Send the public " +
          "key to the other holder of this chain (public keys travel openly; check it is really theirs " +
          "the tool-18 way) and keep the private key to yourself: it is half of what makes the heal " +
          "unfollowable. Your private key was copied into the heal box below.";
      });
    });
    document.getElementById("chain-heal").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var out = document.getElementById("heal-out");
      var status = document.getElementById("heal-result");
      status.textContent = "Healing the chain locally…";
      healChainState(document.getElementById("heal-state").value,
        document.getElementById("heal-priv-in").value,
        document.getElementById("heal-peer-pub").value).then(function (healed) {
        if (healed === null) {
          out.value = "";
          status.textContent = "That cannot heal: paste your current chain state (a whole p4a-chain-v1 " +
            "line), your fresh private agreement key, and the other side's fresh public key. A malformed " +
            "state, a swapped key or a signing key heals nothing — and nothing was changed.";
          return;
        }
        out.value = healed;
        status.textContent = "Healed — a new chain at position 0. Replace your saved state with this line " +
          "and let the old state go: anyone holding only the old state cannot follow you here, because " +
          "following takes a fresh private key they never had. The other side must heal from exactly " +
          "the same pre-heal state, with their own fresh pair, or their chain lands somewhere else and " +
          "seals will simply fail until you both heal from the same state.";
      });
    });

    /* --- hide the length: pad it to one size before sealing --- */
    document.getElementById("padseal-make").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var out = document.getElementById("padseal-out");
      var status = document.getElementById("padseal-result");
      var message = document.getElementById("padseal-message").value;
      status.textContent = "Padding and locking locally…";
      sealPaddedMessage(message, document.getElementById("padseal-key").value).then(function (sealed) {
        if (sealed === null) {
          out.value = "";
          status.textContent = "That cannot be padded and locked: write a message (up to " +
            PAD_MAX_MESSAGE_BYTES + " bytes once encoded — the largest labelled bucket), and paste the " +
            "derived key exactly as tool 19 made it (64 hex characters, 32 bytes). Nothing was locked.";
          return;
        }
        out.value = sealed;
        var bytes = secretToBytes(message).length;
        status.textContent = "✓ Padded and locked locally. Your message is " + bytes +
          " byte" + (bytes === 1 ? "" : "s") + ", padded up to the " +
          paddedBucketFor(bytes) + "-byte bucket before locking — so this locked line is exactly " +
          "as long as any other locked line in that bucket, whatever the message inside it says. " +
          "Copy the whole line; the key is not in it.";
      });
    });
    document.getElementById("padseal-open").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var out = document.getElementById("padopen-out");
      var status = document.getElementById("padopen-result");
      status.textContent = "Opening locally…";
      openPaddedMessage(document.getElementById("padopen-sealed").value,
        document.getElementById("padopen-key").value).then(function (message) {
        if (message === null) {
          out.value = "";
          status.textContent = "That does not open: the usual causes are the wrong derived key, a " +
            "locked line that was changed or cut short (the padding is inside the lock, so changing any " +
            "of it fails outright), or a plain tool-20 line — those open in tool 20, not here, and this " +
            "tool's lines open only here.";
          return;
        }
        out.value = message;
        status.textContent = "✓ Opened locally — exactly the message that was padded and locked, " +
          "with the random filler stripped away and never shown. The locked line told a watcher only " +
          "which size bucket it was in; this page is the first place its true length exists again.";
      });
    });

    /* --- out of order, still private: skipped message keys --- */
    document.getElementById("ooo-start").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var stateOut = document.getElementById("ooo-start-state-out");
      var storeOut = document.getElementById("ooo-start-store-out");
      var status = document.getElementById("ooo-start-result");
      var state = startChainState(document.getElementById("ooo-start-in").value);
      if (state === null) {
        stateOut.value = "";
        storeOut.value = "";
        status.textContent = "That cannot start a receiving side: paste the derived key exactly as " +
          "tool 19 made it (64 hex characters, 32 bytes). Nothing was started.";
        return;
      }
      stateOut.value = state;
      storeOut.value = emptySkippedStore();
      status.textContent = "✓ Receiving side started locally: a chain state at position 0 and an " +
        "empty skipped-key store. Keep the two together — they are a pair. The sender seals with the " +
        "middle form from the same starting state; you open with the last form.";
    });
    document.getElementById("ooo-seal").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var out = document.getElementById("ooo-seal-out");
      var nextOut = document.getElementById("ooo-seal-next");
      var status = document.getElementById("ooo-seal-result");
      status.textContent = "Stepping the chain and locking locally…";
      sealNumberedMessage(document.getElementById("ooo-seal-state").value,
        document.getElementById("ooo-seal-message").value).then(function (res) {
        if (res === null) {
          out.value = "";
          nextOut.value = "";
          status.textContent = "That cannot be locked: paste your current chain state (a whole " +
            "p4a-chain-v1 line) and write a message (up to " + KEYSEAL_MAX_MESSAGE_CHARS +
            " characters). Nothing was locked and your state was not advanced.";
          return;
        }
        out.value = res.sealed;
        nextOut.value = res.state;
        status.textContent = "✓ Locked locally, with its position written on the outside of the " +
          "line — that number is how the receiver finds the right key, and it is the only thing the " +
          "line gives away beyond its length. Replace your chain state with the NEXT one and let " +
          "the old one go.";
      });
    });
    document.getElementById("ooo-open").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var out = document.getElementById("ooo-open-out");
      var nextOut = document.getElementById("ooo-open-next");
      var storeOut = document.getElementById("ooo-open-store-out");
      var status = document.getElementById("ooo-open-result");
      status.textContent = "Opening locally…";
      openNumberedMessage(document.getElementById("ooo-open-state").value,
        document.getElementById("ooo-open-store").value,
        document.getElementById("ooo-open-in").value).then(function (res) {
        if (res === null) {
          out.value = "";
          nextOut.value = "";
          storeOut.value = "";
          status.textContent = "That does not open, and nothing was consumed: the usual causes are " +
            "a state and store that do not belong together, a message numbered further ahead than " +
            "the labelled store cap lets the chain jump, a replay of a message whose stored key was already used and " +
            "erased, or a locked line that was changed. Your saved state and store are unchanged — " +
            "retry when the missing messages arrive.";
          return;
        }
        out.value = res.message;
        nextOut.value = res.state;
        storeOut.value = res.store;
        status.textContent = "✓ Opened locally. Replace your saved state and store with the two " +
          "new lines below: any positions this message jumped over now have their keys banked in " +
          "the store, and a stored key is erased the moment its message opens, so each late " +
          "message opens exactly once.";
      });
    });

    /* --- for their key only: the sealed box --- */
    document.getElementById("box-seal").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var out = document.getElementById("box-seal-out");
      var status = document.getElementById("box-seal-result");
      status.textContent = "Closing the box locally…";
      sealBoxMessage(document.getElementById("box-seal-pub").value,
        document.getElementById("box-seal-message").value).then(function (sealed) {
        if (sealed === null) {
          out.value = "";
          status.textContent = "That cannot be closed: paste the recipient's public key exactly " +
            "as tool 18 made it (182 hex characters, 91 bytes — a private key pasted here is " +
            "refused, it is never the thing a sender needs) and write a message (up to " +
            BOX_MAX_MESSAGE_CHARS + " characters). Nothing was closed.";
          return;
        }
        out.value = sealed;
        status.textContent = "✓ Closed locally. The long hex after the format label is a fresh " +
          "one-message public key made for this box alone — it is not a secret, and it is the " +
          "only part of the key agreement anyone ever sees. Send the whole line however you " +
          "like; only the matching private key opens it.";
      });
    });
    document.getElementById("box-open").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var out = document.getElementById("box-open-out");
      var status = document.getElementById("box-open-result");
      status.textContent = "Opening locally…";
      openBoxMessage(document.getElementById("box-open-priv").value,
        document.getElementById("box-open-in").value).then(function (message) {
        if (message === null) {
          out.value = "";
          status.textContent = "That does not open: the usual causes are the wrong private key " +
            "(a box opens only for the key matching the public key it was closed to), a locked " +
            "line that was changed or cut short, or a line from another tool — those open in " +
            "their own tools, not here. Nothing about which part failed is revealed, by design.";
          return;
        }
        out.value = message;
        status.textContent = "✓ Opened locally — exactly the message that was closed into the " +
          "box. Remember what the box never proved: who closed it. Anyone holding the " +
          "recipient's public key can close one in any name.";
      });
    });

    /* --- a box that names its sender: sign, then close it in the box --- */
    document.getElementById("authbox-seal").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var out = document.getElementById("authbox-seal-out");
      var status = document.getElementById("authbox-seal-result");
      status.textContent = "Signing and closing the box locally…";
      sealAuthenticatedBoxMessage(document.getElementById("authbox-seal-pub").value,
        document.getElementById("authbox-seal-priv").value,
        document.getElementById("authbox-seal-message").value).then(function (sealed) {
        if (sealed === null) {
          out.value = "";
          status.textContent = "That cannot be closed: paste the recipient's public key exactly " +
            "as tool 18 made it (182 hex characters, 91 bytes — their private key is never the " +
            "thing a sender needs), your own signing private key exactly as tool 17 made it " +
            "(276 hex characters, 138 bytes), and write a message (up to " +
            AUTHBOX_MAX_MESSAGE_CHARS + " characters, so the message and its signature fit " +
            "inside the seal). Nothing was closed.";
          return;
        }
        out.value = sealed;
        status.textContent = "✓ Signed and closed locally. Your signature is inside the box, " +
          "where only the recipient will ever see it — the line itself shows nothing but a " +
          "fresh one-message public key, an IV and ciphertext. Send the whole line however " +
          "you like; only the matching private key opens it, and only your public signing " +
          "key makes the name check out.";
      });
    });
    document.getElementById("authbox-open").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var out = document.getElementById("authbox-open-out");
      var status = document.getElementById("authbox-open-result");
      status.textContent = "Opening locally…";
      openAuthenticatedBoxMessage(document.getElementById("authbox-open-priv").value,
        document.getElementById("authbox-open-in").value,
        document.getElementById("authbox-open-pub").value).then(function (res) {
        if (res === null) {
          out.value = "";
          status.textContent = "That does not open: the usual causes are the wrong private key " +
            "(a box opens only for the key matching the public key it was closed to), a " +
            "sender public key that is not a tool-17 signing key at all, a locked line that " +
            "was changed, cut short or relabelled from another tool, or a plain box from " +
            "tool 26 — those open in their own tool, not here. Nothing about which part " +
            "failed is revealed, by design.";
          return;
        }
        out.value = res.message;
        if (res.verified) {
          status.textContent = "✓ Opened locally, and the signature inside checks out against " +
            "the sender public key you pasted: this message was signed by whoever holds that " +
            "key. That proves the key, not a legal name — it means what you believe about " +
            "whose key that is, and nothing more.";
        } else {
          status.textContent = "⚠ Opened locally, but the signature inside does NOT check out " +
            "against the sender public key you pasted. The message above is exactly what was " +
            "in the box — read it, but not as theirs: whoever closed this box does not hold " +
            "the signing key for the name you expected.";
        }
      });
    });

    /* --- is that really their key? the safety number --- */
    document.getElementById("safety-make").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var out = document.getElementById("safety-out");
      var status = document.getElementById("safety-result");
      status.textContent = "Working out the safety number locally…";
      safetyNumberForKeys(document.getElementById("safety-a").value,
        document.getElementById("safety-b").value).then(function (num) {
        if (num === null) {
          out.value = "";
          status.textContent = "That makes no number: paste two public keys exactly as " +
            "tools 17 or 18 made them (182 hex characters, 91 bytes each). A private key " +
            "(276 hex characters) is never an input here — the number is built from public " +
            "keys alone, which is exactly why it is safe to share. Nothing was computed " +
            "from the wrong thing.";
          return;
        }
        out.value = num;
        status.textContent = "✓ Worked out locally, from the two public keys alone — " +
          "nothing secret went into it, so the number itself is not a secret. Now compare " +
          "it over a channel you already trust: read it aloud, group by group, and have " +
          "them read theirs back. If even one group differs, stop — one of the keys is " +
          "not the key its owner published, and every later check would pass against " +
          "the wrong key.";
      });
    });
    document.getElementById("safety-check").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var status = document.getElementById("safety-check-result");
      status.textContent = "Checking the number locally…";
      checkSafetyNumber(document.getElementById("safety-check-a").value,
        document.getElementById("safety-check-b").value,
        document.getElementById("safety-check-expected").value).then(function (ok) {
        if (ok === null) {
          status.textContent = "That cannot be checked: paste two public keys exactly " +
            "as tools 17 or 18 made them (182 hex characters, 91 bytes each) and a whole " +
            "safety number — twelve groups of five digits, sixty digits in all. A " +
            "half-typed number gets no verdict at all, rather than a wrong one.";
          return;
        }
        if (ok) {
          status.textContent = "✓ Match: the number these two keys produce is exactly " +
            "the number you were given. That binds these keys to whoever read the number " +
            "to you over the channel you trust — it proves the keys, not a legal name.";
        } else {
          status.textContent = "⚠ No match: these two keys do NOT produce that number. " +
            "Do not proceed as if they were theirs — one of the keys is not the key its " +
            "owner published, or the number was read from a different pair. Re-check the " +
            "keys on a channel you already trust before sending anything private.";
        }
      });
    });

    /* --- a fresh destination for every payment — one-time destinations --- */
    document.getElementById("onetime-make").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var ephOut = document.getElementById("onetime-eph-out");
      var destOut = document.getElementById("onetime-dest-out");
      var status = document.getElementById("onetime-result");
      status.textContent = "Making a fresh one-time destination locally…";
      makeOneTimeDestination(document.getElementById("onetime-pub").value).then(function (made) {
        if (made === null) {
          ephOut.value = "";
          destOut.value = "";
          status.textContent = "That makes no destination: paste the recipient's public " +
            "key exactly as tool 18 made it (182 hex characters, 91 bytes). A private key " +
            "(276 hex characters) is never the recipient input here — destinations are " +
            "made TO a public key, that is its job. Nothing was computed from the wrong thing.";
          return;
        }
        ephOut.value = made.ephemeralPublicKey;
        destOut.value = made.destination;
        status.textContent = "✓ Made locally. Send the destination as the payment's " +
          "address, and the one-payment public key alongside it — the key is not a " +
          "secret, it is how the recipient recognises the payment as theirs. Make a " +
          "fresh one for every payment: reuse is exactly what this tool exists to avoid.";
      });
    });
    document.getElementById("onetime-scan").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var out = document.getElementById("onetime-scan-out");
      var status = document.getElementById("onetime-scan-result");
      status.textContent = "Scanning locally…";
      scanOneTimeDestination(document.getElementById("onetime-scan-priv").value,
        document.getElementById("onetime-scan-eph").value).then(function (dest) {
        if (dest === null) {
          out.value = "";
          status.textContent = "That scans nothing: paste your private key exactly as " +
            "tool 18 made it (276 hex characters, 138 bytes) and the one-payment public " +
            "key that travelled with the payment (182 hex characters, 91 bytes). " +
            "Nothing was computed from the wrong thing.";
          return;
        }
        out.value = dest;
        status.textContent = "✓ Scanned locally. If this destination is the one the " +
          "payment used, the payment is yours — your key is the only one that lands " +
          "here from that one-payment key. A different destination means that payment " +
          "was made to a different key, or with a different one-payment key.";
      });
    });
    document.getElementById("onetime-check").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var status = document.getElementById("onetime-check-result");
      status.textContent = "Checking the destination locally…";
      checkOneTimeDestination(document.getElementById("onetime-check-priv").value,
        document.getElementById("onetime-check-eph").value,
        document.getElementById("onetime-check-dest").value).then(function (ok) {
        if (ok === null) {
          status.textContent = "That cannot be checked: paste your private key exactly " +
            "as tool 18 made it (276 hex characters, 138 bytes), the one-payment public " +
            "key (182 hex characters, 91 bytes) and a whole destination — 64 hex " +
            "characters. A half-typed destination gets no verdict at all, rather than " +
            "a wrong one.";
          return;
        }
        if (ok) {
          status.textContent = "✓ Yours: the destination your key computes from that " +
            "one-payment key is exactly this destination. Nobody watching could have " +
            "connected it to your published key — only your private key lands here.";
        } else {
          status.textContent = "⚠ Not yours: your key and that one-payment key land on " +
            "a different destination. This payment was made to a different recipient " +
            "key, or paired with a different one-payment key — it is not a payment " +
            "this key can claim.";
        }
      });
    });

    /* --- the key that can spend it — one-time spend keys --- */
    document.getElementById("spendkey-make").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var ephOut = document.getElementById("spendkey-eph-out");
      var pubOut = document.getElementById("spendkey-onetime-out");
      var status = document.getElementById("spendkey-result");
      status.textContent = "Deriving a one-time public key on the curve locally…";
      makeOneTimeSpendKey(document.getElementById("spendkey-pub").value).then(function (made) {
        if (made === null) {
          ephOut.value = "";
          pubOut.value = "";
          status.textContent = "That derives no key: paste the recipient's public " +
            "key exactly as tool 18 made it (182 hex characters, 91 bytes), and a " +
            "real point on the curve. A private key (276 hex characters) is never " +
            "the recipient input here — one-time keys are made TO a public key. " +
            "Nothing was computed from the wrong thing.";
          return;
        }
        ephOut.value = made.ephemeralPublicKey;
        pubOut.value = made.oneTimePublicKey;
        status.textContent = "✓ Derived locally, on the curve. The payment goes to " +
          "the one-time public key; send the one-payment public key alongside it — " +
          "it is not a secret, it is how the recipient derives the matching private " +
          "key. A fresh pair for every payment: reuse is what this tool exists to avoid.";
      });
    });
    document.getElementById("spendkey-claim").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var out = document.getElementById("spendkey-claim-out");
      var status = document.getElementById("spendkey-claim-result");
      status.textContent = "Deriving your one-time private key locally…";
      claimOneTimeSpendKey(document.getElementById("spendkey-claim-priv").value,
        document.getElementById("spendkey-claim-eph").value).then(function (priv) {
        if (priv === null) {
          out.value = "";
          status.textContent = "That derives no key: paste your private key exactly " +
            "as tool 18 made it (276 hex characters, 138 bytes) and the one-payment " +
            "public key that travelled with the payment (182 hex characters, " +
            "91 bytes). Nothing was computed from the wrong thing.";
          return;
        }
        out.value = priv;
        status.textContent = "✓ Derived locally. This is the private half of the " +
          "one-time public key the payment used — the key that can spend it. It is " +
          "a secret in exactly the way your ordinary private key is: never share " +
          "it, never paste it anywhere else, and treat this practise key as the " +
          "lesson, not as a wallet.";
      });
    });
    document.getElementById("spendkey-check").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var status = document.getElementById("spendkey-check-result");
      status.textContent = "Checking the pair locally…";
      matchOneTimeSpendKey(document.getElementById("spendkey-check-priv").value,
        document.getElementById("spendkey-check-pub").value).then(function (ok) {
        if (ok === null) {
          status.textContent = "That cannot be checked: paste a whole one-time " +
            "private key exactly as the claim form made it (276 hex characters, " +
            "138 bytes) and a whole one-time public key (182 hex characters, " +
            "91 bytes, a real point on the curve). A half-typed key gets no " +
            "verdict at all, rather than a wrong one.";
          return;
        }
        if (ok) {
          status.textContent = "✓ A matching pair: this private key's own point is " +
            "exactly that public key. Whoever holds it holds the spend key for " +
            "that one payment — and no other.";
        } else {
          status.textContent = "⚠ Not a pair: this private key belongs to a " +
            "different public key. It spends a different payment — or none — and " +
            "no amount of re-checking makes it fit this one.";
        }
      });
    });

    /* --- view keys: watch, never spend --- */
    document.getElementById("viewkey-make").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var ephOut = document.getElementById("viewkey-eph-out");
      var destOut = document.getElementById("viewkey-dest-out");
      var pubOut = document.getElementById("viewkey-onetime-out");
      var status = document.getElementById("viewkey-result");
      ephOut.value = ""; destOut.value = ""; pubOut.value = "";
      status.textContent = "Making a watched payment locally…";
      makeWatchedPayment(document.getElementById("viewkey-view-pub").value,
        document.getElementById("viewkey-spend-pub").value).then(function (made) {
        if (!made) {
          status.textContent = "That needs two whole public keys, each exactly " +
            "as tool 18 makes them (182 hex characters, 91 bytes, a real point " +
            "on the curve) — one view key, one spend key. A private key pasted " +
            "as a public key is refused, not used.";
          return;
        }
        ephOut.value = made.ephemeralPublicKey;
        destOut.value = made.destination;
        pubOut.value = made.oneTimePublicKey;
        status.textContent = "Done locally. The one-payment public key travels " +
          "with the payment in plain view. Anyone holding the view private key " +
          "can recognise this destination and name this one-time public key — " +
          "and that is all they can do. The spend key was never touched.";
      });
    });

    document.getElementById("viewkey-scan").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var destOut = document.getElementById("viewkey-scan-dest-out");
      var pubOut = document.getElementById("viewkey-scan-onetime-out");
      var status = document.getElementById("viewkey-scan-result");
      destOut.value = ""; pubOut.value = "";
      status.textContent = "Watching locally…";
      scanWatchedPayment(document.getElementById("viewkey-scan-priv").value,
        document.getElementById("viewkey-scan-spend-pub").value,
        document.getElementById("viewkey-scan-eph").value).then(function (parts) {
        if (!parts) {
          status.textContent = "That cannot be watched: paste your whole view " +
            "private key (276 hex characters, 138 bytes), the recipient's whole " +
            "spend public key (182 hex characters, 91 bytes, a real point on " +
            "the curve) and the whole one-payment public key that travelled " +
            "with the payment.";
          return;
        }
        destOut.value = parts.destination;
        pubOut.value = parts.oneTimePublicKey;
        status.textContent = "Watched locally — with the view key alone. If " +
          "that destination is the payment's destination, the payment is " +
          "theirs, and the one-time public key above is the key it went to. " +
          "Nothing here can spend it: no spend key was asked for or used.";
      });
    });

    document.getElementById("viewkey-check").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var status = document.getElementById("viewkey-check-result");
      status.textContent = "Checking the destination locally…";
      checkWatchedPayment(document.getElementById("viewkey-check-priv").value,
        document.getElementById("viewkey-check-spend-pub").value,
        document.getElementById("viewkey-check-eph").value,
        document.getElementById("viewkey-check-dest").value).then(function (ok) {
        if (ok === null) {
          status.textContent = "That cannot be checked: the destination must " +
            "be a whole destination (64 hex characters), and the keys must be " +
            "whole keys exactly as the other forms use them. A half-typed " +
            "destination gets no verdict at all, rather than a wrong one.";
          return;
        }
        if (ok) {
          status.textContent = "✓ Theirs: this view key recognises exactly " +
            "that destination from that one-payment key. Watching worked — " +
            "and watching is all the view key can do.";
        } else {
          status.textContent = "⚠ Not theirs: this view key computes a " +
            "different destination from that one-payment key. The payment " +
            "went to a different published pair — or to nobody here.";
        }
      });
    });

    document.getElementById("viewkey-claim").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var out = document.getElementById("viewkey-claim-out");
      var status = document.getElementById("viewkey-claim-result");
      out.value = "";
      status.textContent = "Claiming the spend key locally…";
      claimWatchedSpendKey(document.getElementById("viewkey-claim-view-priv").value,
        document.getElementById("viewkey-claim-spend-priv").value,
        document.getElementById("viewkey-claim-eph").value).then(function (priv) {
        if (!priv) {
          status.textContent = "That cannot be claimed: paste both whole " +
            "private keys — the view key AND the spend key, each 276 hex " +
            "characters, 138 bytes — and the whole one-payment public key " +
            "that travelled with the payment. One key on its own is refused: " +
            "that refusal is this tool's whole point.";
          return;
        }
        out.value = priv;
        status.textContent = "Done locally — and it took both keys: the view " +
          "key found the tweak, the spend key used it. That private key " +
          "spends this one payment and no other. Paste it into tool 30's " +
          "pair checker, against the one-time public key from the forms " +
          "above, and watch it match.";
      });
    });

    /* --- prove you know the key (Schnorr proof of knowledge) --- */
    document.getElementById("zkproof-commit").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var commitOut = document.getElementById("zkproof-commitment-out");
      var stateOut = document.getElementById("zkproof-state-out");
      var status = document.getElementById("zkproof-commit-result");
      commitOut.value = "";
      stateOut.value = "";
      status.textContent = "Making the commitment locally…";
      makeProofCommitment(document.getElementById("zkproof-priv").value).then(function (made) {
        if (!made) {
          status.textContent = "That cannot start a proof: paste a whole " +
            "private key — exactly 276 hex characters, 138 bytes, from tool " +
            "17 or tool 18. A public key proves nothing here; the whole " +
            "point is holding the private half.";
          return;
        }
        commitOut.value = made.commitment;
        stateOut.value = made.state;
        status.textContent = "Committed. Send the commitment — and only " +
          "the commitment — to whoever is checking you, and keep the " +
          "prover state secret: it holds the one-time nonce. The state " +
          "answers exactly one challenge; after answering, throw it away " +
          "and start again for the next proof.";
      });
    });

    document.getElementById("zkproof-challenge").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var out = document.getElementById("zkproof-challenge-out");
      var status = document.getElementById("zkproof-challenge-result");
      var challenge = generateProofChallenge();
      if (challenge === null) {
        out.value = "";
        status.textContent = "No challenge could be drawn — this browser " +
          "offered no randomness, and a predictable challenge would prove " +
          "nothing.";
        return;
      }
      out.value = challenge;
      status.textContent = "Drawn fresh, after the commitment was fixed — " +
        "that order is what makes the answer a proof. Send this challenge " +
        "to the prover exactly as drawn; never reuse one, and never draw " +
        "it before the commitment exists.";
    });

    document.getElementById("zkproof-respond").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var out = document.getElementById("zkproof-response-out");
      var status = document.getElementById("zkproof-respond-result");
      out.value = "";
      status.textContent = "Answering the challenge locally…";
      respondToProofChallenge(document.getElementById("zkproof-respond-priv").value,
        document.getElementById("zkproof-respond-state").value,
        document.getElementById("zkproof-respond-challenge").value).then(function (response) {
        if (!response) {
          status.textContent = "That cannot be answered: paste the whole " +
            "private key, the whole prover state from step 1, and the " +
            "verifier's challenge exactly as drawn (64 hex characters, " +
            "never zero). A mistyped piece gets no answer at all, rather " +
            "than a wrong one.";
          return;
        }
        out.value = response;
        status.textContent = "Answered. The response is safe to send — " +
          "one answer reveals neither the nonce nor the key. But this " +
          "state has now answered its one challenge: never answer a " +
          "second challenge with it. Two answers from one commitment " +
          "would let anyone work out the private key itself.";
      });
    });

    document.getElementById("zkproof-verify").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var status = document.getElementById("zkproof-verify-result");
      var ok = verifyProof(document.getElementById("zkproof-verify-pub").value,
        document.getElementById("zkproof-verify-commitment").value,
        document.getElementById("zkproof-verify-challenge").value,
        document.getElementById("zkproof-verify-response").value);
      if (ok === null) {
        status.textContent = "That cannot be checked: the public key and " +
          "the commitment must be whole keys (exactly 91 bytes each), the " +
          "challenge a whole 64-hex number that is not zero, and the " +
          "response a whole 64-hex number. A half-typed piece gets no " +
          "verdict at all, rather than a wrong one.";
        return;
      }
      status.textContent = ok
        ? "✓ Proved: the equation balances — whoever answered holds the " +
          "private key behind that public key, and answered this " +
          "commitment against this challenge. Nothing about the key " +
          "itself was revealed, and this answer proves nothing against " +
          "any other challenge."
        : "⚠ Not proved: the pieces are well-formed, but the equation " +
          "does not balance. The answer was not built from the private " +
          "key behind that public key and the nonce behind that " +
          "commitment — or it answers a different challenge.";
    });

    document.getElementById("schnorr-sign").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var out = document.getElementById("schnorr-sig-out");
      var status = document.getElementById("schnorr-sign-result");
      out.value = "";
      status.textContent = "Signing locally…";
      signSchnorrMessage(document.getElementById("schnorr-priv").value,
        document.getElementById("schnorr-message").value).then(function (sig) {
        if (!sig) {
          status.textContent = "That cannot be signed: paste a whole " +
            "private key — exactly 276 hex characters, 138 bytes, from tool " +
            "17 or tool 18 — and a message that is not blank and is at " +
            "most 2,000 characters. A public key signs nothing; the whole " +
            "point is holding the private half.";
          return;
        }
        out.value = sig;
        status.textContent = "Signed. The line carries the commitment " +
          "and the answer — never the key, never the nonce. Anyone with " +
          "your public key and the exact message can check it, forever, " +
          "with nobody in the room: that is what makes it a signature " +
          "rather than tool 32's one-time proof. Sign the same message " +
          "again and you get a different line — a fresh nonce every " +
          "time, because one nonce behind two signatures would hand " +
          "anyone your private key.";
      });
    });

    document.getElementById("schnorr-verify").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var status = document.getElementById("schnorr-verify-result");
      status.textContent = "Checking locally…";
      verifySchnorrSignature(document.getElementById("schnorr-verify-pub").value,
        document.getElementById("schnorr-verify-message").value,
        document.getElementById("schnorr-verify-sig").value).then(function (ok) {
        if (ok === null) {
          status.textContent = "That cannot be checked: the public key " +
            "must be a whole key (exactly 91 bytes), the message must be " +
            "the exact signed text (not blank, at most 2,000 characters), " +
            "and the signature one whole p4a-schnorr-v1 line. A half-typed " +
            "piece gets no verdict at all, rather than a wrong one.";
          return;
        }
        status.textContent = ok
          ? "✓ Signed: the equation balances — whoever produced that " +
            "line held the private key behind this public key and signed " +
            "this exact message. Change one character of the message and " +
            "it fails."
          : "⚠ Not signed: the pieces are well-formed, but the equation " +
            "does not balance. The line was not produced from the " +
            "private key behind that public key over this message — or " +
            "the message has been changed since it was signed.";
      });
    });

    /* --- one of us signed it (ring signatures) --- */
    document.getElementById("ring-sign").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var out = document.getElementById("ring-sig-out");
      var status = document.getElementById("ring-sign-result");
      out.value = "";
      status.textContent = "Signing locally…";
      signRingMessage(document.getElementById("ring-priv").value,
        document.getElementById("ring-keys").value,
        document.getElementById("ring-message").value).then(function (sig) {
        if (!sig) {
          status.textContent = "That cannot be signed: the ring must be " +
            "2 to 6 whole public keys (exactly 91 bytes each, one per " +
            "line, no duplicates), your private key must be the private " +
            "half of one of them — a key that is not in the ring cannot " +
            "sign for it — and the message must not be blank and must be " +
            "at most 2,000 characters.";
          return;
        }
        out.value = sig;
        status.textContent = "Signed — as one of the ring. The line " +
          "carries a seed challenge and one answer per member, in ring " +
          "order; nothing in it says which member you are, and the " +
          "other members were never asked and never involved: their " +
          "answers were invented forwards from random numbers, and " +
          "only yours was built from a private key. Anyone with the " +
          "ring — the same keys in the same order — and the exact " +
          "message can check that one of you signed, and can learn " +
          "nothing more from the line.";
      });
    });

    document.getElementById("ring-verify").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var status = document.getElementById("ring-verify-result");
      status.textContent = "Checking locally…";
      verifyRingSignature(document.getElementById("ring-verify-keys").value,
        document.getElementById("ring-verify-message").value,
        document.getElementById("ring-verify-sig").value).then(function (ok) {
        if (ok === null) {
          status.textContent = "That cannot be checked: the ring must " +
            "be 2 to 6 whole public keys (exactly 91 bytes each, one " +
            "per line, no duplicates), the message must be the exact " +
            "signed text (not blank, at most 2,000 characters), the " +
            "signature one whole p4a-ring-v1 line, and the number of " +
            "answers in it must match the number of keys in the ring. " +
            "A half-typed piece gets no verdict at all, rather than a " +
            "wrong one.";
          return;
        }
        status.textContent = ok
          ? "✓ One of them signed: the chain of challenges closes back " +
            "on its own seed — exactly one private key from this ring " +
            "produced that line over this exact message. The check " +
            "cannot say which member, and neither can anyone else: " +
            "that silence is the point of the construction."
          : "⚠ Not proved: the pieces are well-formed, but the chain " +
            "does not close. No single member of this ring, in this " +
            "order, signed this exact message with that line — or the " +
            "message, the ring, or the line has been changed since " +
            "signing.";
      });
    });

    /* --- signed twice? it shows (linkable ring signatures) --- */
    document.getElementById("lring-sign").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var out = document.getElementById("lring-sig-out");
      var status = document.getElementById("lring-sign-result");
      out.value = "";
      status.textContent = "Signing locally…";
      signLinkableRingMessage(document.getElementById("lring-priv").value,
        document.getElementById("lring-keys").value,
        document.getElementById("lring-message").value).then(function (sig) {
        if (!sig) {
          status.textContent = "That cannot be signed: the ring must be " +
            "2 to 6 whole public keys (exactly 91 bytes each, one per " +
            "line, no duplicates), your private key must be the private " +
            "half of one of them — a key that is not in the ring cannot " +
            "sign for it — and the message must not be blank and must be " +
            "at most 2,000 characters.";
          return;
        }
        out.value = sig;
        status.textContent = "Signed — as one of the ring, with a key " +
          "image. The line carries the image, a seed challenge and one " +
          "answer per member, in ring order; nothing in it says which " +
          "member you are. But the image is fixed by your key alone: " +
          "sign anything else, in any ring, and the same image appears " +
          "again — anyone holding both lines can tell the same key " +
          "signed twice, and still cannot tell which key it was.";
      });
    });

    document.getElementById("lring-verify").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var status = document.getElementById("lring-verify-result");
      status.textContent = "Checking locally…";
      verifyLinkableRingSignature(document.getElementById("lring-verify-keys").value,
        document.getElementById("lring-verify-message").value,
        document.getElementById("lring-verify-sig").value).then(function (ok) {
        if (ok === null) {
          status.textContent = "That cannot be checked: the ring must " +
            "be 2 to 6 whole public keys (exactly 91 bytes each, one " +
            "per line, no duplicates), the message must be the exact " +
            "signed text (not blank, at most 2,000 characters), the " +
            "signature one whole p4a-lring-v1 line, and the number of " +
            "answers in it must match the number of keys in the ring. " +
            "A half-typed piece gets no verdict at all, rather than a " +
            "wrong one.";
          return;
        }
        status.textContent = ok
          ? "✓ One of them signed: the doubled chain of challenges " +
            "closes back on its own seed, on both link points at once — " +
            "exactly one private key from this ring produced that line " +
            "over this exact message, and the key image in the line is " +
            "that key's image. The check still cannot say which member."
          : "⚠ Not proved: the pieces are well-formed, but the chain " +
            "does not close. No single member of this ring, in this " +
            "order, signed this exact message with that line and that " +
            "key image — or the message, the ring, or the line has " +
            "been changed since signing.";
      });
    });

    document.getElementById("lring-link").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var status = document.getElementById("lring-link-result");
      status.textContent = "Comparing locally…";
      var linked = linkableRingSignaturesLinked(
        document.getElementById("lring-link-a").value,
        document.getElementById("lring-link-b").value);
      if (linked === null) {
        status.textContent = "That cannot be compared: both pieces " +
          "must be whole p4a-lring-v1 signature lines. A half-typed " +
          "line gets no verdict at all, rather than a wrong one.";
        return;
      }
      status.textContent = linked
        ? "✓ Linked: both lines carry the same key image, so the same " +
          "ring member's key signed both — in whatever rings, over " +
          "whatever messages. That is all the image can ever say: " +
          "same key twice, never which key."
        : "Not linked: the two lines carry different key images, so " +
          "they were signed by different keys. (Either line could still " +
          "be unverified or forged — linking compares images, it does " +
          "not check a signature; run each line through the check " +
          "above for that.)";
    });

    /* --- signed without seeing (blind signatures) --- */
    document.getElementById("blind-commit").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var commitOut = document.getElementById("blind-commitment-out");
      var stateOut = document.getElementById("blind-state-out");
      var status = document.getElementById("blind-commit-result");
      commitOut.value = "";
      stateOut.value = "";
      var made = makeBlindSignerCommitment();
      if (!made) {
        status.textContent = "That cannot be started: this browser " +
          "offered no randomness to draw the signer's nonce from, so " +
          "no commitment exists. Nothing was committed to.";
        return;
      }
      commitOut.value = made.commitment;
      stateOut.value = made.state;
      status.textContent = "Committed. Publish the commitment line " +
        "where the requester can reach it, and keep the state line " +
        "secret and beside it: the state holds the nonce, the one " +
        "secret this move makes. One commitment, one session, one " +
        "answer — answering twice from it hands over the private " +
        "key, exactly as in tools 32 and 33.";
    });

    document.getElementById("blind-request").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var challengeOut = document.getElementById("blind-req-challenge-out");
      var stateOut = document.getElementById("blind-req-state-out");
      var status = document.getElementById("blind-req-result");
      challengeOut.value = "";
      stateOut.value = "";
      status.textContent = "Blinding locally…";
      blindSignatureRequest(document.getElementById("blind-req-commitment").value,
        document.getElementById("blind-req-pub").value,
        document.getElementById("blind-req-message").value).then(function (req) {
        if (!req) {
          status.textContent = "That cannot be blinded: the signer's " +
            "public key and their commitment must both be whole keys " +
            "(exactly 91 bytes each), and the message must not be " +
            "blank and must be at most 2,000 characters.";
          return;
        }
        challengeOut.value = req.blindedChallenge;
        stateOut.value = req.state;
        status.textContent = "Blinded. Send the signer ONLY the " +
          "blinded challenge — never the message, never the state " +
          "line. The state holds the two blinding factors and the " +
          "final commitment; it is yours alone, and move 4 needs it. " +
          "From the blinded challenge alone the signer can learn " +
          "nothing about what they are about to sign.";
      });
    });

    document.getElementById("blind-sign").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var out = document.getElementById("blind-sign-out");
      var status = document.getElementById("blind-sign-result");
      out.value = "";
      status.textContent = "Signing blindly, locally…";
      blindSign(document.getElementById("blind-sign-priv").value,
        document.getElementById("blind-sign-state").value,
        document.getElementById("blind-sign-challenge").value).then(function (resp) {
        if (!resp) {
          status.textContent = "That cannot be answered: the private " +
            "key must be a whole key (exactly 138 bytes), the signer " +
            "state one whole p4a-blindsigner-v1 line whose commitment " +
            "matches its own nonce, and the blinded challenge a whole " +
            "64-hex number that is not zero — a zero challenge would " +
            "be answered with the nonce itself, so it is refused.";
          return;
        }
        out.value = resp;
        status.textContent = "Answered — blindly. That number is " +
          "your nonce plus the blinded challenge times your private " +
          "scalar: a real answer from your real key, over a challenge " +
          "you cannot read, for a message you have never seen. Send " +
          "it back to the requester; on its own it verifies as " +
          "nothing, and it becomes a signature only in their hands.";
      });
    });

    document.getElementById("blind-unblind").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var out = document.getElementById("blind-unblind-out");
      var status = document.getElementById("blind-unblind-result");
      out.value = "";
      var line = unblindSignature(document.getElementById("blind-unblind-state").value,
        document.getElementById("blind-unblind-response").value);
      if (!line) {
        status.textContent = "That cannot be unblinded: the request " +
          "state must be one whole p4a-blindreq-v1 line and the " +
          "signer's answer one whole 64-hex number under the curve " +
          "order. A half-typed piece produces no line at all, rather " +
          "than a wrong one.";
        return;
      }
      out.value = line;
      status.textContent = "Unblinded — and finished. That line is " +
        "an ordinary tool 33 signature: check it in tool 33's verify " +
        "form, against the signer's public key and your exact " +
        "message, and it balances. The signer produced it without " +
        "ever seeing either, and nothing in the line points back to " +
        "the session that made it.";
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
