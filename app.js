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

/* ---------- 37. It takes a quorum — threshold signatures ----------

   Every signature so far has had exactly one key
   behind it: one holder, one point of failure, one
   person who can be coerced, robbed or simply
   unavailable. Groups that hold something together —
   a treasury, a release key, a community fund — want
   the opposite shape: no single key can sign, and no
   single loss can silence the group. The threshold
   signature is that shape. One group key is split at
   setup, and any quorum of the holders — here any 2
   or any 3 of up to 5 — can together produce ONE
   ordinary signature under the group public key,
   while fewer than the quorum can produce nothing
   that verifies.

   The split is tool 15's Shamir idea moved into the
   scalar field of the curve itself, mod n. The
   dealer's polynomial is f(t) = x + a₁t (+ a₂t² for a
   quorum of 3), where x is the group private scalar
   and the a's are fresh random scalars; holder i is
   handed the single number f(i) in a share line
   (p4a-threshshare-v1) that carries the quorum size
   and their index and nothing else. The group public
   key is the ordinary Y = x×G — the coefficients and
   the shares never appear in it, and no verifier ever
   learns the split existed.

   Signing is tools 32 and 33 run by a committee.
   Each participating holder commits to a fresh nonce
   exactly as in tool 32, keeping it in a signer state
   line (p4a-threshsigner-v1) that also carries their
   index. The commitments are gathered into one set —
   one "index:commitment" line per participant — and
   summed into a single aggregate commitment R. The
   challenge is tool 33's own: e = H(R, message) under
   privacy4all-schnorr-v1. Holder j then answers not
   with their raw share but weighted by their Lagrange
   coefficient for the participating set S,
   λ_j = Π_{l∈S, l≠j} l/(l−j) mod n, computed with a
   Fermat inverse under the order: s_j = k_j + e·λ_j·f(j).
   Adding the partial answers gives s with
   s×G = R + e×Y, because Σ λ_j·f(j) is exactly f(0) = x
   — Lagrange interpolation evaluated at zero, never
   reconstructing x anywhere. The combined line is an
   ordinary p4a-schnorr-v1 signature, and tool 33's
   verifier — nothing in this tool — is the judge.

   The honest limits are structural, not fine print.
   A DEALER runs the split: whoever deals sees the
   whole group key at setup, so this is a trusted-
   dealer teaching construction — real threshold
   protocols such as FROST generate the key jointly,
   by distributed key generation, so the whole key
   never exists in one place, and they add nonce
   commitments and binding factors against the
   concurrent-session attacks a page like this does
   no coordination against. Fewer than the quorum is
   not "weaker signing", it is nothing: the partial
   answers of a sub-quorum set interpolate to a scalar
   that is not x, and tool 33's verifier calls the
   result false. One nonce behind two partial answers
   leaks the holder's weighted share exactly as in
   tools 32 and 33 — λ_j·f(j) falls out, and f(j) with
   it, since λ_j is public arithmetic — so one
   commitment, one answer, ever. A share line is a
   secret of the same rank as a private key: any
   quorum of them, pooled, is the group. And the
   frame is the house one: a real threshold signature
   computed and checked locally, but not the signature
   format any chain or wallet checks, not a Compact
   circuit proof, and not an audited wallet and not
   side-channel resistant. Never paste a real wallet
   key or a production private key into any web page,
   including this one — practise with throwaway keys
   from tools 17 and 18. */
var THRESH_SHARE_FORMAT = "p4a-threshshare-v1";
var THRESH_SIGNER_FORMAT = "p4a-threshsigner-v1";
var THRESH_MIN_THRESHOLD = 2;
var THRESH_MAX_THRESHOLD = 3;
var THRESH_MIN_COUNT = 2;
var THRESH_MAX_COUNT = 5;

/* An index is a whole number in [1, THRESH_MAX_COUNT]:
   holder numbers on share lines, state lines and
   commitment sets. Zero is refused — index 0 is the
   point the polynomial is evaluated at to recover x
   itself, so a "holder 0" would be handed the group
   key, not a share of it. */
function parseThresholdIndexText(text) {
  if (typeof text !== "string") return null;
  var t = text.trim();
  if (!/^[1-9][0-9]*$/.test(t)) return null;
  var v = Number(t);
  if (v < 1 || v > THRESH_MAX_COUNT) return null;
  return v;
}

function validThresholdIndexValue(v) {
  return typeof v === "number" && isFinite(v) && Math.floor(v) === v &&
    v >= 1 && v <= THRESH_MAX_COUNT;
}

function validThresholdValue(v) {
  return typeof v === "number" && isFinite(v) && Math.floor(v) === v &&
    v >= THRESH_MIN_THRESHOLD && v <= THRESH_MAX_THRESHOLD;
}

/* The dealer polynomial evaluated at one holder's
   index: f(i) = x + a₁·i + a₂·i² mod n, deterministic
   once the scalar and the coefficients exist, so
   tests can pin it against hand arithmetic. One
   coefficient makes a quorum of 2, two make 3; a
   share that lands on exactly zero is null — a zero
   share would answer challenges with the nonce
   alone, and the dealer simply draws fresh
   coefficients, an event of probability about 2^-256. */
function thresholdShareScalar(scalarHex, coefficientHexes, index) {
  var scalar = parseProofScalar(scalarHex);
  if (scalar === null || !Array.isArray(coefficientHexes) ||
      coefficientHexes.length < 1 ||
      coefficientHexes.length > THRESH_MAX_THRESHOLD - 1 ||
      !validThresholdIndexValue(index)) {
    return null;
  }
  var total = BigInt("0x" + scalar);
  var power = BigInt(index);
  var iBig = BigInt(index);
  for (var i = 0; i < coefficientHexes.length; i++) {
    var coeff = parseProofScalar(coefficientHexes[i]);
    if (coeff === null) return null;
    total = (total + BigInt("0x" + coeff) * power) % P256_N;
    power = power * iBig;
  }
  if (total === P256_ZERO) return null;
  return p256IntToHex(total);
}

/* A share line: the format tag, the quorum size, the
   holder's index, and the share scalar — everything
   the holder needs at signing time, and a secret of
   the same rank as a private key. */
function formatThresholdShare(threshold, index, shareHex) {
  var share = parseProofScalar(shareHex);
  if (!validThresholdValue(threshold) || !validThresholdIndexValue(index) ||
      share === null) {
    return null;
  }
  return THRESH_SHARE_FORMAT + ":" + threshold + ":" + index + ":" + share;
}

function parseThresholdShare(text) {
  if (typeof text !== "string") return null;
  var parts = text.trim().split(":");
  if (parts.length !== 4 || parts[0] !== THRESH_SHARE_FORMAT) return null;
  if (!/^[2-3]$/.test(parts[1])) return null;
  var index = parseThresholdIndexText(parts[2]);
  var share = parseProofScalar(parts[3]);
  if (index === null || share === null) return null;
  return { threshold: Number(parts[1]), index: index, share: share };
}

/* The split itself: read the group private key's own
   scalar back through the platform, draw the dealer
   coefficients, evaluate the polynomial once per
   holder, and hand back the group public key and one
   share line per holder. The dealer's coefficients
   are never returned — once the shares exist, nobody
   needs them, and keeping them would keep a second
   road back to the whole key. */
function splitThresholdKey(privateKeyHex, threshold, count) {
  if (!validThresholdValue(threshold) ||
      typeof count !== "number" || !isFinite(count) ||
      Math.floor(count) !== count ||
      count < threshold || count > THRESH_MAX_COUNT) {
    return Promise.resolve(null);
  }
  return agreementPrivateParts(privateKeyHex).then(function (parts) {
    if (!parts) return null;
    var coeffs = [];
    for (var c = 0; c < threshold - 1; c++) {
      var coeff = randomProofScalar();
      if (coeff === null) return null;
      coeffs.push(coeff);
    }
    var shares = [];
    for (var i = 1; i <= count; i++) {
      var shareScalar = thresholdShareScalar(parts.scalarHex, coeffs, i);
      if (shareScalar === null) return null;
      var line = formatThresholdShare(threshold, i, shareScalar);
      if (line === null) return null;
      shares.push(line);
    }
    var publicKey = proofCommitmentForNonce(parts.scalarHex);
    if (publicKey === null) return null;
    return { publicKey: publicKey, shares: shares };
  });
}

/* Modular inverse under the curve ORDER (also prime)
   by Fermat's little theorem — p256Invert works mod
   p, the field prime; Lagrange division lives mod n.
   Same five-line spirit. Zero has no inverse: null. */
function thresholdScalarInvert(value) {
  var base = value % P256_N;
  if (base < P256_ZERO) base += P256_N;
  if (base === P256_ZERO) return null;
  var exp = P256_N - BigInt(2);
  var result = BigInt(1);
  var b = base;
  while (exp > P256_ZERO) {
    if ((exp & BigInt(1)) === BigInt(1)) result = result * b % P256_N;
    b = b * b % P256_N;
    exp = exp >> BigInt(1);
  }
  return result;
}

/* One holder's Lagrange coefficient for a
   participating set S, evaluated at zero:
   λ_j = Π_{l∈S, l≠j} l/(l−j) mod n. The set must be
   two to five distinct valid indices including j —
   a set of one is not a quorum of anything, and its
   coefficient would quietly be 1, the raw share,
   which is exactly the confusion this gate exists to
   prevent. Deterministic, so tests pin it against
   hand arithmetic and against the reconstruction
   identity Σ λ_j·f(j) = x. */
function thresholdLagrangeCoefficient(index, indices) {
  if (!validThresholdIndexValue(index) || !Array.isArray(indices) ||
      indices.length < 2 || indices.length > THRESH_MAX_COUNT) {
    return null;
  }
  var seen = {};
  var found = false;
  for (var i = 0; i < indices.length; i++) {
    if (!validThresholdIndexValue(indices[i]) || seen[indices[i]]) return null;
    seen[indices[i]] = true;
    if (indices[i] === index) found = true;
  }
  if (!found) return null;
  var acc = BigInt(1);
  for (var j = 0; j < indices.length; j++) {
    var l = indices[j];
    if (l === index) continue;
    var inv = thresholdScalarInvert(BigInt(l - index));
    if (inv === null) return null;
    acc = acc * BigInt(l) % P256_N * inv % P256_N;
  }
  if (acc === P256_ZERO) return null;
  return p256IntToHex(acc);
}

/* One line of a commitment set: a holder's index and
   the commitment they published, "index:commitment".
   The set — all participants' lines together — is
   what every partial answer and the final combination
   are computed against, so it parses strictly: two to
   five lines, distinct indices, whole on-curve
   commitments, and a summed aggregate that is not the
   point at infinity. */
function formatThresholdCommitmentLine(index, commitmentHex) {
  var point = parseP256Point(commitmentHex);
  if (!validThresholdIndexValue(index) || point === null) return null;
  return index + ":" + formatP256PublicKey(point);
}

function parseThresholdCommitmentSet(text) {
  if (typeof text !== "string") return null;
  var lines = text.split(/\r?\n/);
  var commitments = {};
  var indices = [];
  var aggregate = null;
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i].trim();
    if (line === "") continue;
    var parts = line.split(":");
    if (parts.length !== 2) return null;
    var index = parseThresholdIndexText(parts[0]);
    var point = parseP256Point(parts[1]);
    if (index === null || point === null || commitments[index]) return null;
    commitments[index] = formatP256PublicKey(point);
    indices.push(index);
    aggregate = aggregate === null ? point : p256PointAdd(aggregate, point);
    if (aggregate === null) return null;
  }
  if (indices.length < 2 || indices.length > THRESH_MAX_COUNT) return null;
  indices.sort(function (a, b) { return a - b; });
  return { indices: indices, commitments: commitments,
           aggregate: formatP256PublicKey(aggregate) };
}

/* The signer-only state line: the format tag, the
   holder's index, the nonce, and the commitment it
   belongs to — tool 32's pairing discipline plus the
   index, so a state can never be quietly re-paired
   with a different commitment, a different holder, or
   another tool, at answer time. */
function formatThresholdSignerState(index, nonceHex, commitmentHex) {
  var nonce = parseProofScalar(nonceHex);
  var point = parseP256Point(commitmentHex);
  if (!validThresholdIndexValue(index) || nonce === null || point === null) {
    return null;
  }
  return THRESH_SIGNER_FORMAT + ":" + index + ":" + nonce + ":" +
    formatP256PublicKey(point);
}

function parseThresholdSignerState(text) {
  if (typeof text !== "string") return null;
  var parts = text.trim().split(":");
  if (parts.length !== 4 || parts[0] !== THRESH_SIGNER_FORMAT) return null;
  var index = parseThresholdIndexText(parts[1]);
  var nonce = parseProofScalar(parts[2]);
  var point = parseP256Point(parts[3]);
  if (index === null || nonce === null || point === null) return null;
  return { index: index, nonce: nonce, commitment: formatP256PublicKey(point) };
}

/* A participating holder's first move: draw a fresh
   nonce from the share line's own index, commit to
   it, and hand back the commitment-set line to
   publish and the secret state line to keep. The
   share itself is read only for its index here — the
   scalar is asked again at answer time and never
   stored anywhere. */
function makeThresholdCommitment(shareText) {
  var share = parseThresholdShare(shareText);
  if (share === null) return null;
  var nonce = randomProofScalar();
  if (nonce === null) return null;
  var commitment = proofCommitmentForNonce(nonce);
  var state = formatThresholdSignerState(share.index, nonce, commitment);
  var line = formatThresholdCommitmentLine(share.index, commitment);
  if (commitment === null || state === null || line === null) return null;
  return { index: share.index, commitment: commitment, line: line, state: state };
}

/* The partial answer: s_j = k_j + e·λ_j·f(j) mod n,
   tool 32's response arithmetic with the holder's
   share first weighted by their Lagrange coefficient
   for THIS participating set — the same share answers
   differently inside a different quorum, which is the
   whole mechanism. Every pairing is checked before
   any arithmetic: the state's index is the share's
   index, the state's commitment is its own nonce's
   commitment, that commitment stands in the set under
   that index, and the set is at least the share's
   quorum. A weighted share of exactly zero, or a
   challenge of zero, is null: the answer would carry
   no trace of the share. */
function thresholdPartialResponse(shareText, stateText, message, commitmentSetText) {
  var share = parseThresholdShare(shareText);
  var state = parseThresholdSignerState(stateText);
  var set = parseThresholdCommitmentSet(commitmentSetText);
  if (share === null || state === null || set === null ||
      !validSchnorrMessage(message)) {
    return Promise.resolve(null);
  }
  if (state.index !== share.index) return Promise.resolve(null);
  if (proofCommitmentForNonce(state.nonce) !== state.commitment) {
    return Promise.resolve(null);
  }
  if (set.commitments[share.index] !== state.commitment) {
    return Promise.resolve(null);
  }
  if (set.indices.length < share.threshold) return Promise.resolve(null);
  var lambda = thresholdLagrangeCoefficient(share.index, set.indices);
  if (lambda === null) return Promise.resolve(null);
  var weighted = (BigInt("0x" + lambda) * BigInt("0x" + share.share)) % P256_N;
  if (weighted === P256_ZERO) return Promise.resolve(null);
  return schnorrChallenge(set.aggregate, message).then(function (challenge) {
    if (challenge === null) return null;
    return proofResponseForScalar(p256IntToHex(weighted), state.nonce, challenge);
  });
}

/* The combination, and the tool's only output line:
   the partial answers — one per participating holder,
   in any order, because addition does not care — are
   summed under the order over the set's aggregate
   commitment, and the result is formatted as an
   ordinary p4a-schnorr-v1 signature. Whether it is a
   REAL signature is not this function's verdict to
   give: it is tool 33's, over the group public key
   and the exact message. A sub-quorum set, a missing
   answer, or an extra one is null rather than a
   wrong line — count first, then sum. */
function combineThresholdResponses(commitmentSetText, responsesText) {
  var set = parseThresholdCommitmentSet(commitmentSetText);
  if (set === null || typeof responsesText !== "string") return null;
  var lines = responsesText.split(/\r?\n/);
  var total = P256_ZERO;
  var count = 0;
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i].trim();
    if (line === "") continue;
    var response = parseProofResponse(line);
    if (response === null) return null;
    total = (total + BigInt("0x" + response)) % P256_N;
    count++;
  }
  if (count !== set.indices.length) return null;
  if (total === P256_ZERO) return null;
  return formatSchnorrSignature(set.aggregate, p256IntToHex(total));
}

/* ---------- 38. No dealer ever saw it — distributed key generation ----------

   Tool 37 ends on a named flaw: a dealer splits the
   group key, and the dealer sees the whole key at
   setup. This tool removes the dealer. In a
   distributed key generation (Pedersen's scheme, with
   Feldman's verifiable sharing as the check), EVERY
   holder deals a split of their own random
   contribution, and the group key is the sum of the
   contributions — a number that is never computed,
   by anyone, anywhere in this code: only its public
   key exists, as the sum of the contributions'
   public commitments.

   Holder j draws a fresh scalar x_j and, for a quorum
   of t, fresh coefficients a_j1…a_j(t−1), exactly
   tool 37's polynomial shape. They broadcast ONE
   commitment line (p4a-dkgcommit-v1) carrying the
   Feldman commitments C_jk = a_jk×G — with a_j0 read
   as x_j itself — and they send each holder i,
   privately, one share line (p4a-dkgshare-v1)
   carrying f_j(i), computed by tool 37's own
   thresholdShareScalar. A commitment reveals nothing
   about its scalar; what it does is bind the dealer
   to it, because the recipient can check the share
   against the commitments: f_j(i)×G must equal
   Σ_k i^k·C_jk. A share that fails that check is a
   dealer who dealt inconsistently — false, not a
   rounding error — and finalizing refuses it.

   Finalizing is addition and nothing else: holder i
   sums the shares addressed to them, one from every
   dealer including themselves, and the sum F(i) is
   a point on the SUMMED polynomial
   F(t) = Σ_j f_j(t), whose constant term is
   Σ_j x_j — the group scalar, which exists only as
   that sum of shares, never as a value anyone held.
   The final line is formatted as an ordinary tool 37
   share (p4a-threshshare-v1), so a key generated here
   signs in tool 37 unchanged, and the group public
   key is the sum of the dealers' first commitments,
   Σ_j C_j0 = (Σ_j x_j)×G.

   The honest limits are structural. This page plays
   every holder on one device, so here the whole
   round is visible in one place; in real use each
   holder runs their own device, only commitment
   lines are broadcast, and share lines travel over
   private channels — a share line is a secret of
   the same rank as in tool 37. There is no complaint
   or dispute round: real protocols add one, where a
   dealer whose share fails the Feldman check is
   disqualified by the group and the round restarts
   without them — here verification and finalizing
   simply refuse, and restarting is the group's own
   business off-page. This simplified round also
   makes no claim to FROST's full proofs: a dealer
   who waits to see the others' commitments before
   choosing their own can bias the group key's
   distribution in ways Gennaro and co-authors
   showed for Pedersen's original scheme, which is
   why production protocols add rounds this teaching
   page does not. And the frame is the house one: a
   real distributed key generation computed and
   checked locally, but not the key format any chain
   or wallet checks, not a Compact circuit proof, and
   not an audited wallet and not side-channel
   resistant. Never paste a real wallet key or a
   production private key into any web page, including
   this one — this tool needs no existing key at all:
   every contribution is drawn fresh on the page. */
var DKG_COMMIT_FORMAT = "p4a-dkgcommit-v1";
var DKG_SHARE_FORMAT = "p4a-dkgshare-v1";

/* One dealer's Feldman commitments for a contribution
   polynomial: the public points of the contribution
   scalar itself and of each coefficient, in order —
   [x×G, a₁×G, (a₂×G)]. The count is the quorum: a
   quorum of 2 publishes two points, 3 publishes
   three. Nothing here reveals a scalar; the points
   exist so every dealt share can be checked against
   them at finalizing time. */
function dkgPolynomialCommitments(scalarHex, coefficientHexes) {
  var scalar = parseProofScalar(scalarHex);
  if (scalar === null || !Array.isArray(coefficientHexes) ||
      coefficientHexes.length < 1 ||
      coefficientHexes.length > THRESH_MAX_THRESHOLD - 1) {
    return null;
  }
  var points = [proofCommitmentForNonce(scalar)];
  if (points[0] === null) return null;
  for (var i = 0; i < coefficientHexes.length; i++) {
    var coeff = parseProofScalar(coefficientHexes[i]);
    if (coeff === null) return null;
    var point = proofCommitmentForNonce(coeff);
    if (point === null) return null;
    points.push(point);
  }
  return points;
}

/* A commitment line: the format tag, the quorum, the
   dealer's index, and the Feldman commitment points
   in polynomial order — exactly `threshold` points,
   because the constant point plus one per coefficient
   is the whole polynomial a verifier needs. This is
   the line a dealer BROADCASTS: it is public by
   design and safe to publish anywhere. */
function formatDkgCommitmentLine(threshold, dealerIndex, commitments) {
  if (!validThresholdValue(threshold) ||
      !validThresholdIndexValue(dealerIndex) ||
      !Array.isArray(commitments) || commitments.length !== threshold) {
    return null;
  }
  var points = [];
  for (var i = 0; i < commitments.length; i++) {
    var point = parseP256Point(commitments[i]);
    if (point === null) return null;
    points.push(formatP256PublicKey(point));
  }
  return DKG_COMMIT_FORMAT + ":" + threshold + ":" + dealerIndex + ":" +
    points.join(":");
}

function parseDkgCommitmentLine(text) {
  if (typeof text !== "string") return null;
  var parts = text.trim().split(":");
  if (parts.length < 3 || parts[0] !== DKG_COMMIT_FORMAT) return null;
  if (!/^[2-3]$/.test(parts[1])) return null;
  var threshold = Number(parts[1]);
  if (parts.length !== 3 + threshold) return null;
  var dealer = parseThresholdIndexText(parts[2]);
  if (dealer === null) return null;
  var commitments = [];
  for (var i = 0; i < threshold; i++) {
    var point = parseP256Point(parts[3 + i]);
    if (point === null) return null;
    commitments.push(formatP256PublicKey(point));
  }
  return { threshold: threshold, dealer: dealer, commitments: commitments };
}

/* A dealt share line: the format tag, the quorum, the
   dealer's index, the RECIPIENT's index, and the
   share scalar f_dealer(recipient). Unlike the
   commitment line this is a secret — it travels from
   the dealer to exactly one holder, privately. A
   dealer deals to themselves too: their own share of
   their own polynomial is one of the summands of
   their final share. */
function formatDkgShareLine(threshold, dealerIndex, recipientIndex, shareHex) {
  var share = parseProofScalar(shareHex);
  if (!validThresholdValue(threshold) ||
      !validThresholdIndexValue(dealerIndex) ||
      !validThresholdIndexValue(recipientIndex) || share === null) {
    return null;
  }
  return DKG_SHARE_FORMAT + ":" + threshold + ":" + dealerIndex + ":" +
    recipientIndex + ":" + share;
}

function parseDkgShareLine(text) {
  if (typeof text !== "string") return null;
  var parts = text.trim().split(":");
  if (parts.length !== 5 || parts[0] !== DKG_SHARE_FORMAT) return null;
  if (!/^[2-3]$/.test(parts[1])) return null;
  var dealer = parseThresholdIndexText(parts[2]);
  var recipient = parseThresholdIndexText(parts[3]);
  var share = parseProofScalar(parts[4]);
  if (dealer === null || recipient === null || share === null) return null;
  return { threshold: Number(parts[1]), dealer: dealer,
           recipient: recipient, share: share };
}

/* One holder's whole move as a dealer: draw a fresh
   contribution scalar and its coefficients, publish
   the commitment line, and deal one share line to
   every holder including themselves. The contribution
   scalar itself is never returned — once the shares
   are dealt, nobody needs it, and keeping it would
   keep a road back to a piece of the group key. */
function generateDkgContribution(threshold, count, dealerIndex) {
  if (!validThresholdValue(threshold) ||
      typeof count !== "number" || !isFinite(count) ||
      Math.floor(count) !== count ||
      count < threshold || count > THRESH_MAX_COUNT ||
      !validThresholdIndexValue(dealerIndex) || dealerIndex > count) {
    return null;
  }
  var scalar = randomProofScalar();
  if (scalar === null) return null;
  var coeffs = [];
  for (var c = 0; c < threshold - 1; c++) {
    var coeff = randomProofScalar();
    if (coeff === null) return null;
    coeffs.push(coeff);
  }
  var commitments = dkgPolynomialCommitments(scalar, coeffs);
  var commitmentLine = commitments === null ? null :
    formatDkgCommitmentLine(threshold, dealerIndex, commitments);
  if (commitmentLine === null) return null;
  var shares = [];
  for (var i = 1; i <= count; i++) {
    var shareScalar = thresholdShareScalar(scalar, coeffs, i);
    if (shareScalar === null) return null;
    var line = formatDkgShareLine(threshold, dealerIndex, i, shareScalar);
    if (line === null) return null;
    shares.push(line);
  }
  return { dealer: dealerIndex, commitment: commitmentLine, shares: shares };
}

/* The Feldman check, over parsed lines: a dealt share
   verifies when share×G equals the commitments
   weighted by the recipient's powers,
   Σ_k recipient^k·C_k. True is a share consistent
   with what its dealer broadcast; false is a
   well-formed share that does not match those
   commitments — an inconsistent dealer, not a typo
   this function can forgive; malformed lines, or a
   share and a commitment line from different dealers
   or different quorums, are null. */
function verifyDkgShareParsed(commitment, share) {
  if (!commitment || !share) return null;
  if (commitment.threshold !== share.threshold ||
      commitment.dealer !== share.dealer) {
    return null;
  }
  var lhs = p256PointMultiply(BigInt("0x" + share.share),
    { x: P256_GX, y: P256_GY });
  if (lhs === null) return false;
  var rhs = null;
  var power = BigInt(1);
  var recipient = BigInt(share.recipient);
  for (var k = 0; k < commitment.commitments.length; k++) {
    var point = parseP256Point(commitment.commitments[k]);
    if (point === null) return null;
    var term = power === BigInt(1) ? point : p256PointMultiply(power, point);
    if (term === null) return false;
    rhs = rhs === null ? term : p256PointAdd(rhs, term);
    if (rhs === null) return false;
    power = power * recipient;
  }
  return formatP256PublicKey(lhs) === formatP256PublicKey(rhs);
}

function verifyDkgShare(commitmentLineText, shareLineText) {
  return verifyDkgShareParsed(parseDkgCommitmentLine(commitmentLineText),
    parseDkgShareLine(shareLineText));
}

/* The broadcast set, parsed strictly: two to five
   commitment lines, one common quorum, and the
   dealers exactly 1..count, each once — a round with
   a dealer missing is not a round this page will
   finalize, because the summed polynomial would
   silently be a different group key than the set of
   holders agreed to. The group public key falls out
   of the parse: the sum of every dealer's constant
   commitment, which is (Σ x_j)×G — computed as
   points, never as a scalar. */
function parseDkgCommitmentSet(text) {
  if (typeof text !== "string") return null;
  var lines = text.split(/\r?\n/);
  var byDealer = {};
  var threshold = null;
  var count = 0;
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i].trim();
    if (line === "") continue;
    var parsed = parseDkgCommitmentLine(line);
    if (parsed === null || byDealer[parsed.dealer]) return null;
    if (threshold === null) threshold = parsed.threshold;
    if (parsed.threshold !== threshold) return null;
    byDealer[parsed.dealer] = parsed;
    count++;
  }
  if (count < THRESH_MIN_COUNT || count > THRESH_MAX_COUNT ||
      threshold === null || count < threshold) {
    return null;
  }
  var groupPoint = null;
  for (var d = 1; d <= count; d++) {
    if (!byDealer[d]) return null;
    var constant = parseP256Point(byDealer[d].commitments[0]);
    if (constant === null) return null;
    groupPoint = groupPoint === null ? constant :
      p256PointAdd(groupPoint, constant);
    if (groupPoint === null) return null;
  }
  return { threshold: threshold, count: count, byDealer: byDealer,
           publicKey: formatP256PublicKey(groupPoint) };
}

/* Finalizing, for one holder: the broadcast commitment
   set plus every share line addressed to that holder —
   exactly one per dealer, each passing its Feldman
   check against that dealer's own commitments, all
   addressed to the same recipient. The final share is
   the plain sum of the dealt shares under the order;
   a sum of exactly zero is refused rather than handed
   out as a share that would answer challenges with
   nothing. The output share line is tool 37's own
   format, deliberately: a key generated with no
   dealer signs in tool 37 unchanged. Any share that
   fails its check, is missing, is duplicated, or is
   addressed to someone else makes the whole finalize
   null — a group does not finalize on a partial or
   inconsistent round. */
function finalizeDkgShares(commitmentSetText, shareLinesText) {
  var set = parseDkgCommitmentSet(commitmentSetText);
  if (set === null || typeof shareLinesText !== "string") return null;
  var lines = shareLinesText.split(/\r?\n/);
  var seen = {};
  var recipient = null;
  var total = P256_ZERO;
  var found = 0;
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i].trim();
    if (line === "") continue;
    var share = parseDkgShareLine(line);
    if (share === null || share.threshold !== set.threshold ||
        !set.byDealer[share.dealer] || seen[share.dealer]) {
      return null;
    }
    if (recipient === null) recipient = share.recipient;
    if (share.recipient !== recipient) return null;
    if (verifyDkgShareParsed(set.byDealer[share.dealer], share) !== true) {
      return null;
    }
    seen[share.dealer] = true;
    total = (total + BigInt("0x" + share.share)) % P256_N;
    found++;
  }
  if (found !== set.count || recipient === null) return null;
  if (total === P256_ZERO) return null;
  var shareLine = formatThresholdShare(set.threshold, recipient,
    p256IntToHex(total));
  if (shareLine === null) return null;
  return { publicKey: set.publicKey, recipient: recipient,
           shareLine: shareLine };
}

/* ---------- 39. A signature that waits for a secret — adaptor signatures ----------

   Every signature on this page is finished the moment
   it is made: tool 33's line either verifies or it
   does not, and nothing that happens afterwards can
   change that. Some agreements need the opposite
   shape — a signature that is complete except for one
   missing number, so that revealing that number
   finishes the signature, and finishing the signature
   reveals the number. That is an adaptor signature,
   run here locally on tool 33's own Schnorr scheme.
   The missing number is an ordinary proof scalar t,
   the adaptor secret; what the world sees of it is
   only its point T = t×G, the adaptor point, which
   reveals nothing about t. The signer makes a
   pre-signature: draw a nonce k, commit to it as
   usual at R = k×G, then shift the commitment by the
   adaptor point, R̂ = R + T, and draw tool 33's
   challenge over the SHIFTED commitment and the
   message. The answer s′ = k + e·x is tool 32's
   arithmetic unchanged — but it answers for R, while
   the challenge was drawn over R̂, so the line
   (R̂, s′) is not a signature: tool 33's verifier
   checks it and says false, because s′×G = R + e×Y,
   one adaptor point short of the R̂ + e×Y a finished
   signature needs. Anyone holding T can check the
   pre-signature is genuine — s′×G must equal
   (R̂ − T) + e×Y — so both sides can confirm, before
   anything is revealed, that exactly one number is
   missing and it is the number whose point is T.
   Adapting is adding that number: s = s′ + t, and
   the line (R̂, s) is an ordinary p4a-schnorr-v1
   signature that tool 33's verifier accepts, because
   s×G = s′×G + T = R̂ + e×Y exactly. Extraction is
   the same addition read backwards: anyone holding
   both the pre-signature and the adapted signature
   computes t = s − s′ and recovers the adaptor secret
   itself — that symmetry is the mechanism, not a
   side effect. Agree a secret's point with a stranger,
   take their pre-signature locked to it, and the
   moment either side publishes an adapted signature
   the other side can extract the secret and adapt
   their own — which is why real systems build atomic
   swaps and payment locks out of exactly this shape:
   two signatures on two chains, one secret, both
   complete or neither does.

   The honest limits are plain. The pre-signature is
   worthless until adapted — it verifies as nothing,
   spends nothing, and proves only that its maker knew
   the signing key and aimed it at this adaptor point.
   The adaptor point has to really be the point of the
   secret the agreement is about: a swapped point
   locks the signature to a stranger's secret, and
   adapting with any other number produces a line tool
   33's verifier rejects — check the point the way
   tool 28 checks a key, over a channel you already
   trust, before relying on a pre-signature.
   Publication is the reveal: an adapted signature
   shown to anyone who holds the pre-signature hands
   them the secret, so there is no adapting "privately"
   to one verifier — adapt to one holder of the
   pre-signature and you have adapted for all of them.
   And the nonce discipline of tools 32 and 33 is
   inherited whole: one nonce behind two pre-signatures
   with different challenges leaks the signing key the
   same way. Honestly labelled: this is a real adaptor
   signature computed and checked locally, but it is
   not the signature format any chain or wallet checks;
   it is the maths in the open, not one of Midnight's
   Compact circuit proofs; and like tool 30 the curve
   code is a teaching implementation — affine
   arithmetic written to be read and checked line by
   line, not an audited wallet and not side-channel
   resistant. Never paste a real wallet key or a
   production private key into any web page, including
   this one — practise with throwaway keys from tools
   17 and 18. */
var ADAPTOR_FORMAT = "p4a-adaptor-v1";

/* A point's reflection through the x-axis: the same x,
   the negated y. Subtracting a point is adding its
   reflection, and the pre-signature check below is the
   one place on this page that needs it. A point with
   y = 0 would be its own reflection; P-256 has no such
   point (its order is odd), so no input that parses
   can produce one. */
function p256PointNegate(point) {
  if (point === null) return null;
  return { x: point.x, y: p256Mod(P256_P - point.y) };
}

/* The adaptor point for one secret: T = t×G, computed
   by tool 32's own commitment arithmetic, because a
   nonce commitment and an adaptor point are the same
   object — a scalar's public shadow. A secret that is
   not a whole scalar in [1, n−1] is null. */
function adaptorPointForSecret(secretHex) {
  return proofCommitmentForNonce(secretHex);
}

/* A fresh adaptor secret and its point, drawn the way
   every secret on this page is drawn. The secret is a
   number of private-key rank: whoever holds it can
   finish any signature locked to its point, and
   whoever sees an adapted signature beside its
   pre-signature can take it — it is shown once, here,
   and stored nowhere. */
function generateAdaptorSecret() {
  var secret = randomProofScalar();
  if (secret === null) return null;
  var point = adaptorPointForSecret(secret);
  if (point === null) return null;
  return { secret: secret, point: point };
}

/* The pre-signature line: the format tag, the ADAPTED
   commitment R̂ (a whole 91-byte public key) and the
   pre-response s′ (a whole 64-hex scalar, zero allowed
   by the parser for the same 2^-256 reason as tool
   33's). The unshifted R never appears: it is
   recoverable from R̂ and the adaptor point, and
   publishing it separately would only invite pairing
   the line with the wrong point. */
function formatAdaptorSignature(commitmentHex, responseHex) {
  var point = parseP256Point(commitmentHex);
  var response = parseProofResponse(responseHex);
  if (point === null || response === null) return null;
  return ADAPTOR_FORMAT + ":" + formatP256PublicKey(point) + ":" + response;
}

function parseAdaptorSignature(text) {
  if (typeof text !== "string") return null;
  var parts = text.trim().split(":");
  if (parts.length !== 3 || parts[0] !== ADAPTOR_FORMAT) return null;
  var point = parseP256Point(parts[1]);
  var response = parseProofResponse(parts[2]);
  if (point === null || response === null) return null;
  return { commitment: formatP256PublicKey(point), response: response };
}

/* Making a pre-signature: validate the signer's key by
   reading its own parts back through the platform (as
   in tool 32, a public key offered as a private key
   never imports), draw a fresh nonce, shift its
   commitment by the adaptor point, draw tool 33's
   challenge over the shifted commitment, and answer
   with tool 32's arithmetic. A shifted commitment that
   lands on the point at infinity — the nonce point
   exactly cancelling the adaptor point, a 2^-256
   event — or a zero challenge or answer simply draws
   a fresh nonce and tries again, exactly as tool 33's
   signer does. */
function createAdaptorSignature(privateKeyHex, message, adaptorPointHex) {
  var adaptorPoint = parseP256Point(adaptorPointHex);
  if (adaptorPoint === null || !validSchnorrMessage(message)) {
    return Promise.resolve(null);
  }
  return agreementPrivateParts(privateKeyHex).then(function (parts) {
    if (!parts) return null;
    var attempt = function (triesLeft) {
      var nonce = randomProofScalar();
      if (nonce === null) return Promise.resolve(null);
      var commitment = proofCommitmentForNonce(nonce);
      if (commitment === null) return Promise.resolve(null);
      var shifted = p256PointAdd(parseP256Point(commitment), adaptorPoint);
      var shiftedHex = formatP256PublicKey(shifted);
      if (shiftedHex === null) {
        return triesLeft > 1 ? attempt(triesLeft - 1) : Promise.resolve(null);
      }
      return schnorrChallenge(shiftedHex, message).then(function (challenge) {
        if (challenge === null) {
          return triesLeft > 1 ? attempt(triesLeft - 1) : null;
        }
        var response = proofResponseForScalar(parts.scalarHex, nonce, challenge);
        if (response === null) {
          return triesLeft > 1 ? attempt(triesLeft - 1) : null;
        }
        return formatAdaptorSignature(shiftedHex, response);
      });
    };
    return attempt(8);
  });
}

/* Checking a pre-signature: recompute the challenge
   from the message and the line's own adapted
   commitment, unshift the commitment with the adaptor
   point it claims to be locked to, and check tool 32's
   equation against what remains, s′×G = (R̂ − T) + e×Y.
   True only when it balances; false — never null —
   for well-formed pieces that do not balance (a
   pre-response nudged by one, a different message, a
   stranger's key, the wrong adaptor point — including
   the point of the very secret that would adapt it,
   offered one step too early); null for any malformed
   piece, so "not a genuine pre-signature" and "cannot
   be checked" never blur. */
function verifyAdaptorSignature(publicKeyHex, message, adaptorPointHex, adaptorText) {
  var parsed = parseAdaptorSignature(adaptorText);
  var pubPoint = parseP256Point(publicKeyHex);
  var adaptorPoint = parseP256Point(adaptorPointHex);
  if (parsed === null || pubPoint === null || adaptorPoint === null ||
      !validSchnorrMessage(message)) {
    return Promise.resolve(null);
  }
  return schnorrChallenge(parsed.commitment, message).then(function (challenge) {
    if (challenge === null) return null;
    var lhs = p256PointMultiply(BigInt("0x" + parsed.response), { x: P256_GX, y: P256_GY });
    if (lhs === null) return false;
    var unshifted = p256PointAdd(parseP256Point(parsed.commitment),
      p256PointNegate(adaptorPoint));
    var rhs = p256PointAdd(unshifted,
      p256PointMultiply(BigInt("0x" + challenge), pubPoint));
    if (rhs === null) return false;
    return lhs.x === rhs.x && lhs.y === rhs.y;
  });
}

/* Adapting: add the adaptor secret to the pre-response
   under the order, and the line that comes out is tool
   33's own format, deliberately — a finished adaptor
   signature is an ordinary signature, checkable in
   tool 33 by anyone, with nothing in it saying it ever
   waited for anything. A secret that is not a whole
   scalar, or a line that does not parse, is null; a
   WRONG secret still adapts to a well-formed line —
   one tool 33's verifier will reject — because this
   function cannot know which secret the point was
   made from, and says so rather than pretend. */
function adaptAdaptorSignature(adaptorText, secretHex) {
  var parsed = parseAdaptorSignature(adaptorText);
  var secret = parseProofScalar(secretHex);
  if (parsed === null || secret === null) return null;
  var adapted = (BigInt("0x" + parsed.response) + BigInt("0x" + secret)) % P256_N;
  return formatSchnorrSignature(parsed.commitment, p256IntToHex(adapted));
}

/* Extraction: the adapted response minus the
   pre-response, under the order — the adaptor secret
   itself. The two lines must carry the same adapted
   commitment: a finished signature from any other
   pre-signature differs by more than the secret, and
   subtracting across them would hand back a plausible
   number that is nothing. Identical responses mean
   the "adapted" line is the pre-signature restated —
   a difference of zero is refused as null, never
   handed out as a secret. */
function extractAdaptorSecret(adaptorText, adaptedText) {
  var pre = parseAdaptorSignature(adaptorText);
  var fin = parseSchnorrSignature(adaptedText);
  if (pre === null || fin === null) return null;
  if (pre.commitment !== fin.commitment) return null;
  var secret = (BigInt("0x" + fin.response) - BigInt("0x" + pre.response)) % P256_N;
  if (secret < P256_ZERO) secret += P256_N;
  if (secret === P256_ZERO) return null;
  return p256IntToHex(secret);
}

/* ---------- 40. Many keys, one signature — aggregate signatures ----------

   Tools 37 and 38 split ONE key across a quorum: any
   t of n holders can sign, and the group key has a
   life of its own before anyone signs. This tool is
   the opposite shape, the MuSig idea: every signer
   keeps their own ordinary key, ALL of them must sign,
   and what the world sees is one ordinary-looking key
   and one ordinary signature. The aggregate key is
   not the plain sum of the signers' keys — that sum
   falls to the rogue-key attack, where the last
   signer to join picks their "key" as a target point
   minus everyone else's keys, so the plain sum is a
   key they alone control. Instead each key is first
   weighted by a coefficient hashed from the WHOLE
   list and that key together,
   a_i = H(list, Y_i) mod n, and the aggregate key is
   Ỹ = Σ a_i·Y_i. A coefficient is a commitment to the
   final list: change any key and every coefficient
   changes, so a crafted key is weighted by a number
   its maker could not predict when they crafted it,
   and the cancellation stops working.

   Signing mirrors tool 37's committee with the
   weights in place of Lagrange coefficients and no
   quorum shortcut: each signer commits a fresh nonce
   (the commitments gather into one set whose points
   sum to the aggregate commitment R), the challenge
   is tool 33's own over R and the message, each
   partial answer is tool 32's response over the
   signer's weighted scalar a_i·x_i, and the partials
   sum into one ordinary p4a-schnorr-v1 line that tool
   33's verifier — nothing in this tool — judges
   against the aggregate key. One missing signer is
   not a weaker signature; it is no signature, and a
   partial sum offered as the whole thing fails tool
   33's check.

   The honest limits are plain. Everyone must sign:
   that is the point of this shape and also its cost —
   one absent signer blocks the group, where tool 37's
   quorum would not. This page plays every signer on
   one device with the nonce commitments exchanged as
   text; production MuSig (MuSig2, as standardised for
   Bitcoin in BIP-327) adds nonce-commitment rounds
   and partial-signature checks this teaching page
   omits — a signer who reuses one nonce across two
   sessions, or answers two challenges over one nonce,
   leaks their weighted scalar here exactly as in
   tools 32 and 33, and the coefficient does not save
   them. The key list's ORDER is part of the agreement:
   the same keys in a different order are a different
   list, different coefficients, a different aggregate
   key — agree the list the way tool 28 checks a key,
   over a channel you already trust. This is a real
   aggregate signature computed and checked locally,
   but it is not the signature format any chain or
   wallet checks — published MuSig works over
   secp256k1 with its own encodings, and this page
   stays on the hub's P-256 teaching curve; it is the
   maths in the open, not one of Midnight's Compact
   circuit proofs; and like tool 30 the curve code is
   a teaching implementation, not an audited wallet
   and not side-channel resistant. Never paste a real
   wallet key or a production private key into any web
   page, including this one — practise with throwaway
   keys from tools 17 and 18. */
var MUSIG_KEYAGG_PREFIX = "privacy4all-musig-keyagg-v1";
var MUSIG_SIGNER_FORMAT = "p4a-musigsigner-v1";
var MUSIG_MIN_SIGNERS = 2;
var MUSIG_MAX_SIGNERS = 5;

/* The key list, parsed strictly: two to five whole
   public keys, one per line, each canonicalised, no
   key twice — a duplicated key would carry two
   positions and two coefficients for one secret,
   which is a different agreement than the list
   pretends to be. The ORDER is kept exactly as
   given: position i in this list is signer i in
   every later step. */
function parseMusigKeyList(text) {
  if (typeof text !== "string") return null;
  var lines = text.split(/\r?\n/);
  var keys = [];
  var seen = {};
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i].trim();
    if (line === "") continue;
    var point = parseP256Point(line);
    if (point === null) return null;
    var canonical = formatP256PublicKey(point);
    if (seen[canonical]) return null;
    seen[canonical] = true;
    keys.push(canonical);
  }
  if (keys.length < MUSIG_MIN_SIGNERS || keys.length > MUSIG_MAX_SIGNERS) {
    return null;
  }
  return { keys: keys, count: keys.length };
}

/* One signer's coefficient: SHA-256 over the label,
   the whole canonical list, and that signer's own
   key, reduced under the order. A reduction to zero
   is null — a zero coefficient would silently drop
   the signer from the aggregate key while their name
   stayed on the list. */
function musigKeyCoefficient(keyListText, position) {
  var list = parseMusigKeyList(keyListText);
  if (list === null || !validThresholdIndexValue(position) ||
      position > list.count) {
    return Promise.resolve(null);
  }
  return sha256Hex(MUSIG_KEYAGG_PREFIX + "\n" + list.keys.join("\n") +
    "\n" + list.keys[position - 1]).then(function (digest) {
      if (digest === null) return null;
      var value = BigInt("0x" + digest) % P256_N;
      if (value === P256_ZERO) return null;
      return p256IntToHex(value);
    });
}

/* The aggregate key: Σ a_i·Y_i over the list, as one
   ordinary 91-byte public key — the key tool 33's
   verifier will judge the finished signature
   against. A sum landing on the point at infinity is
   null: it would be a key nobody and everybody
   holds, and the list that produced it is not an
   agreement, it is an accident. */
function aggregateMusigKey(keyListText) {
  var list = parseMusigKeyList(keyListText);
  if (list === null) return Promise.resolve(null);
  var coefficients = [];
  var chain = Promise.resolve(null);
  list.keys.forEach(function (_, i) {
    chain = chain.then(function () {
      return musigKeyCoefficient(keyListText, i + 1).then(function (c) {
        coefficients.push(c);
      });
    });
  });
  return chain.then(function () {
    var total = null;
    for (var i = 0; i < list.keys.length; i++) {
      if (coefficients[i] === null) return null;
      var weighted = p256PointMultiply(BigInt("0x" + coefficients[i]),
        parseP256Point(list.keys[i]));
      if (weighted === null) return null;
      total = total === null ? weighted : p256PointAdd(total, weighted);
      if (total === null) return null;
    }
    return formatP256PublicKey(total);
  });
}

/* The signer-only state line: tool 37's pairing
   discipline under this tool's own tag — the signer's
   POSITION in the agreed list, their nonce, and the
   commitment it belongs to, so a state can never be
   quietly re-paired with a different commitment, a
   different position, or another tool, at answer
   time. */
function formatMusigSignerState(position, nonceHex, commitmentHex) {
  var nonce = parseProofScalar(nonceHex);
  var point = parseP256Point(commitmentHex);
  if (!validThresholdIndexValue(position) || nonce === null || point === null) {
    return null;
  }
  return MUSIG_SIGNER_FORMAT + ":" + position + ":" + nonce + ":" +
    formatP256PublicKey(point);
}

function parseMusigSignerState(text) {
  if (typeof text !== "string") return null;
  var parts = text.trim().split(":");
  if (parts.length !== 4 || parts[0] !== MUSIG_SIGNER_FORMAT) return null;
  var position = parseThresholdIndexText(parts[1]);
  var nonce = parseProofScalar(parts[2]);
  var point = parseP256Point(parts[3]);
  if (position === null || nonce === null || point === null) return null;
  return { index: position, nonce: nonce, commitment: formatP256PublicKey(point) };
}

/* A signer's first move: draw a fresh nonce for their
   position in the list, commit to it, and hand back
   the commitment-set line to publish and the secret
   state line to keep. No key is read here — the
   position is a claim the answer step will check
   against the actual key. */
function makeMusigCommitment(position) {
  if (!validThresholdIndexValue(position)) return null;
  var nonce = randomProofScalar();
  if (nonce === null) return null;
  var commitment = proofCommitmentForNonce(nonce);
  var state = formatMusigSignerState(position, nonce, commitment);
  var line = formatThresholdCommitmentLine(position, commitment);
  if (commitment === null || state === null || line === null) return null;
  return { index: position, commitment: commitment, line: line, state: state };
}

/* The partial answer: s_i = k_i + e·a_i·x_i mod n,
   tool 32's response arithmetic with the signer's
   scalar first weighted by their coefficient for
   THIS list. Every pairing is checked before any
   arithmetic: the list holds the signer's own public
   key at the state's position (a private key offered
   for the wrong position, or a list that names a
   stranger there, is null), the state's commitment
   is its own nonce's commitment and stands in the
   set under that position, and the set is COMPLETE —
   one commitment per position, 1 through the list's
   count, no gaps, no extras — because in this shape
   everyone signs or nobody does. A weighted scalar
   of exactly zero, or a challenge of zero, is null:
   the answer would carry no trace of the signer. */
function musigPartialResponse(privateKeyHex, stateText, keyListText, message, commitmentSetText) {
  var list = parseMusigKeyList(keyListText);
  var state = parseMusigSignerState(stateText);
  var set = parseThresholdCommitmentSet(commitmentSetText);
  if (list === null || state === null || set === null ||
      !validSchnorrMessage(message)) {
    return Promise.resolve(null);
  }
  if (state.index > list.count) return Promise.resolve(null);
  if (set.indices.length !== list.count) return Promise.resolve(null);
  for (var i = 0; i < list.count; i++) {
    if (set.indices[i] !== i + 1) return Promise.resolve(null);
  }
  if (proofCommitmentForNonce(state.nonce) !== state.commitment) {
    return Promise.resolve(null);
  }
  if (set.commitments[state.index] !== state.commitment) {
    return Promise.resolve(null);
  }
  return musigKeyCoefficient(keyListText, state.index).then(function (coefficient) {
    if (coefficient === null) return null;
    return agreementPrivateParts(privateKeyHex).then(function (parts) {
      if (!parts) return null;
      var signerPoint = parseP256Point(SPENDKEY_SPKI_PREFIX_HEX + parts.pointHex);
      if (signerPoint === null) return null;
      if (formatP256PublicKey(signerPoint) !== list.keys[state.index - 1]) {
        return null;
      }
      var weighted = (BigInt("0x" + coefficient) * BigInt("0x" + parts.scalarHex)) % P256_N;
      if (weighted === P256_ZERO) return null;
      return schnorrChallenge(set.aggregate, message).then(function (challenge) {
        if (challenge === null) return null;
        return proofResponseForScalar(p256IntToHex(weighted), state.nonce, challenge);
      });
    });
  });
}

/* The combination: the partial answers — one per
   signer, in any order, because addition does not
   care — summed under the order over the set's
   aggregate commitment, formatted as an ordinary
   p4a-schnorr-v1 signature. The summation is tool
   37's own, deliberately: addition is addition, and
   what differs here is everything upstream of it.
   Whether the result is a REAL signature is tool
   33's verdict, over the aggregate key and the exact
   message — a missing partial sums to a line tool 33
   rejects, and the count check here refuses to even
   format a set that does not match its commitments. */
function combineMusigResponses(commitmentSetText, responsesText) {
  return combineThresholdResponses(commitmentSetText, responsesText);
}

/* ---------- 41. Check them all at once — batch verification ----------

   Every verifier on this page checks one signature at
   a time: tool 33 recomputes one challenge and balances
   one equation, s×G = R + e×Y. A verifier holding a
   pile of signatures — a block of statements, a bundle
   of signed messages — does that work once per line,
   and most of the cost is the curve arithmetic. Batch
   verification checks the whole pile with ONE equation
   instead. Each entry keeps its own challenge, drawn by
   tool 33's hash from its own commitment and message,
   and the batch asks whether the weighted sum balances:

     (Σ a_i·s_i)×G  =  Σ a_i×R_i  +  Σ (a_i·e_i)×Y_i

   If every signature is honest, every individual
   equation holds, so the sum holds too — that direction
   is just addition. The interesting direction is the
   converse, and it is exactly why the weights a_i are
   there. With plain weights (every a_i = 1) the converse
   FAILS in a way anyone can build: nudge one response up
   by any amount d and another down by the same d, and
   the two errors cancel in the sum — the batch passes
   over two signatures that are each, on their own,
   false. So each weight here is hashed, under the label
   privacy4all-batch-v1, from the WHOLE batch — every
   canonical key, signature line and message, in order —
   and the entry's position: a_i is a commitment to the
   final pile, fixed only once every entry is fixed, so
   a forger crafting a cancelling pair cannot know the
   weights their errors will be multiplied by, and
   errors weighted differently do not cancel except
   with probability about 2^-256. The tests pin the
   attack both ways: the forged pair fools a plain sum
   and fails this weighted one.

   The verdict keeps the house split, sharpened by what
   a batch can and cannot say. True means the weighted
   equation balances — every entry in the pile checks
   out, up to that negligible forgery probability. False
   means the equation does not balance: at least one
   entry is wrong, and the batch verdict alone cannot
   say which — that is the honest price of one equation,
   and it is why this tool's second move exists: when a
   batch fails, findInvalidBatchEntries falls back to
   tool 33's check per entry and names the positions
   that fail on their own. Null means the pile itself
   cannot be judged — a malformed key, line or message
   anywhere in it — because "one entry was garbled" and
   "one entry was forged" must never blur into one
   answer. Entries are two to six, each written as a
   public key line, a signature line, then the message
   (as many lines as it needs), with a blank line
   between entries; the same key may sign in several
   entries — a batch is a pile of statements, not a
   list of people.

   The honest limits are plain. A batch verdict is a
   statement about the pile exactly as pasted: reorder
   the entries and the weights change (the verdict for
   an honest pile does not — every honest equation
   holds under any weights — but a transcript agreed
   with anyone else must be pasted in the agreed
   order). Batching saves the verifier work; it does
   not make any signature stronger, fresher or more
   transferable than tool 33 already said it was, and
   a true batch adds nothing tool 33 checking each line
   would not say — it says it in one equation instead
   of six. This is real batch verification computed and
   checked locally, but over this hub's own
   p4a-schnorr-v1 teaching lines, not the signature
   format any chain or wallet checks; production
   batch verifiers (BIP-340's among them) draw their
   weights from a verifier-side random source rather
   than a transcript hash, and work over secp256k1
   with their own encodings; and like tool 30 the
   curve code is a teaching implementation — affine
   arithmetic written to be read, not an audited
   verifier and not side-channel resistant. This tool
   takes public keys and published signatures only —
   never paste a real wallet key or a production
   private key into any web page, including this one;
   practise with throwaway keys from tools 17 and 18. */
var BATCH_COEFF_PREFIX = "privacy4all-batch-v1";
var BATCH_MIN_ENTRIES = 2;
var BATCH_MAX_ENTRIES = 6;

/* One batch entry, parsed strictly: a whole public
   key on the first line, a whole p4a-schnorr-v1 line
   on the second, and the message — everything after
   the signature line, newlines kept, because the
   challenge was drawn over exactly that text. Both
   pieces are canonicalised, so the transcript the
   weights are hashed from names the pieces and not
   one spelling of them. */
function parseBatchEntryBlock(block) {
  var lines = block.split("\n");
  if (lines.length < 3) return null;
  var point = parseP256Point(lines[0].trim());
  var sig = parseSchnorrSignature(lines[1].trim());
  var message = lines.slice(2).join("\n");
  if (point === null || sig === null || !validSchnorrMessage(message)) {
    return null;
  }
  return {
    publicKey: formatP256PublicKey(point),
    signature: formatSchnorrSignature(sig.commitment, sig.response),
    commitment: sig.commitment,
    response: sig.response,
    message: message
  };
}

/* The whole pile: entries separated by blank lines,
   two to six of them, order kept exactly as pasted —
   position in this pile is each entry's position in
   every later step. One malformed entry makes the
   pile null, never a shorter pile that quietly judges
   fewer signatures than were pasted. */
function parseBatchEntries(text) {
  if (typeof text !== "string") return null;
  var blocks = text.replace(/\r\n/g, "\n").split(/\n[ \t]*\n/);
  var entries = [];
  for (var i = 0; i < blocks.length; i++) {
    var block = blocks[i].trim();
    if (block === "") continue;
    var entry = parseBatchEntryBlock(block);
    if (entry === null) return null;
    entries.push(entry);
  }
  if (entries.length < BATCH_MIN_ENTRIES ||
      entries.length > BATCH_MAX_ENTRIES) {
    return null;
  }
  return { entries: entries, count: entries.length };
}

/* The transcript the weights commit to: each entry's
   canonical key, canonical signature line and exact
   message, entries in pile order. Change any entry —
   a key, a line, one character of a message — and
   every weight in the batch changes. */
function batchTranscript(entries) {
  return entries.map(function (e) {
    return e.publicKey + "\n" + e.signature + "\n" + e.message;
  }).join("\n\n");
}

/* One entry's weight: SHA-256 over the label, the
   whole transcript and that entry's position, reduced
   under the order. A reduction to zero is null — a
   zero weight would silently drop the entry from the
   equation while its name stayed on the pile. */
function batchCoefficient(entriesText, position) {
  var parsed = parseBatchEntries(entriesText);
  if (parsed === null || typeof position !== "number" ||
      !isFinite(position) || Math.floor(position) !== position ||
      position < 1 || position > parsed.count) {
    return Promise.resolve(null);
  }
  return sha256Hex(BATCH_COEFF_PREFIX + "\n" +
    batchTranscript(parsed.entries) + "\n" + position)
    .then(function (digest) {
      if (digest === null) return null;
      var value = BigInt("0x" + digest) % P256_N;
      if (value === P256_ZERO) return null;
      return p256IntToHex(value);
    });
}

/* The batch check itself: draw each entry's own
   challenge with tool 33's hash, weight every term,
   and balance the one equation. True only when it
   balances; false — never null — when the pile is
   well-formed and the equation does not balance (at
   least one entry wrong, and this verdict does not
   say which); null when any piece is malformed or a
   weight or challenge cannot be drawn. */
function verifyBatchSignatures(entriesText) {
  var parsed = parseBatchEntries(entriesText);
  if (parsed === null) return Promise.resolve(null);
  var entries = parsed.entries;
  var weights = [];
  var challenges = [];
  var chain = Promise.resolve(null);
  entries.forEach(function (entry, i) {
    chain = chain.then(function () {
      return batchCoefficient(entriesText, i + 1).then(function (w) {
        weights.push(w);
        return schnorrChallenge(entry.commitment, entry.message)
          .then(function (e) { challenges.push(e); });
      });
    });
  });
  return chain.then(function () {
    var totalResponse = P256_ZERO;
    var rhs = null;
    for (var i = 0; i < entries.length; i++) {
      if (weights[i] === null || challenges[i] === null) return null;
      var a = BigInt("0x" + weights[i]);
      totalResponse = (totalResponse +
        a * BigInt("0x" + entries[i].response)) % P256_N;
      var commitPoint = parseP256Point(entries[i].commitment);
      var pubPoint = parseP256Point(entries[i].publicKey);
      var termCommit = p256PointMultiply(a, commitPoint);
      var termKey = p256PointMultiply(
        (a * BigInt("0x" + challenges[i])) % P256_N, pubPoint);
      if (termCommit === null || termKey === null) return false;
      rhs = rhs === null ? termCommit : p256PointAdd(rhs, termCommit);
      if (rhs === null) return false;
      rhs = p256PointAdd(rhs, termKey);
      if (rhs === null) return false;
    }
    var lhs = p256PointMultiply(totalResponse, { x: P256_GX, y: P256_GY });
    if (lhs === null) return false;
    return lhs.x === rhs.x && lhs.y === rhs.y;
  });
}

/* The fallback a failed batch needs: check each entry
   on its own with tool 33's verifier and name the
   positions — 1-based, in pile order — that fail alone.
   An empty list means every entry passes individually
   (so a false batch over the same pile is the
   negligible-probability case, not a hidden forgery);
   null means the pile, or one verdict in it, cannot be
   judged at all. */
function findInvalidBatchEntries(entriesText) {
  var parsed = parseBatchEntries(entriesText);
  if (parsed === null) return Promise.resolve(null);
  var invalid = [];
  var chain = Promise.resolve(null);
  parsed.entries.forEach(function (entry, i) {
    chain = chain.then(function () {
      return verifySchnorrSignature(entry.publicKey, entry.message,
        entry.signature).then(function (verdict) {
          if (verdict === null) { invalid = null; return; }
          if (invalid !== null && verdict === false) invalid.push(i + 1);
        });
    });
  });
  return chain.then(function () { return invalid; });
}

/* ---------- 42. Hide the amount, keep the maths — Pedersen commitments ----------

   Every commitment on this page before this one was a
   hash (tool 8): commit to a secret, reveal it later,
   and the hash says whether the reveal matches. That
   shape can prove you did not change a VALUE, but it
   can do no arithmetic on it — a hash of 750 and a
   hash of 250 cannot be combined into anything a
   verifier can check against 1000. A shielded ledger
   needs exactly that combination: amounts stay hidden
   from everyone watching, while the ledger still
   proves no value was created or destroyed — inputs
   and outputs must balance without any amount ever
   being shown. A Pedersen commitment is the curve
   version of the same promise, and it is homomorphic:

     C(v, r) = r×G + v×H

   G is the hub's usual base point. H is a second point
   built below by hashing, under the label
   privacy4all-pedersen-h-v1, into the curve —
   try-and-increment until the digest lands on a valid
   point, even root chosen. Nobody knows the discrete
   logarithm between G and H — the number t with
   H = t×G — and that unknown number is load-bearing:
   if anyone knew it, they could re-open a commitment
   as any value they liked (shift the value, correct
   the blinding by the known multiple), and the binding
   half of the promise would be gone. The hiding half
   is the blinding r: a fresh random scalar per
   commitment, so the same value committed twice lands
   on two unrelated points, and a watcher who guesses
   the value still cannot check the guess without r —
   which is exactly tool 8's salt lesson, in curve form.

   The homomorphism is plain addition. Commitments add
   point-by-point, blindings add under the order,
   values add as numbers:

     C(v1, r1) + C(v2, r2) = C(v1 + v2, (r1 + r2) mod n)

   so a verifier who is handed two commitments, the two
   openings, and a claimed total never sees either
   amount proved in the clear beyond the openings the
   prover chooses to give — and in a real shielded
   system the openings are themselves replaced by
   proofs, which is Midnight's Compact territory, not
   this page's. Values here are whole numbers from 0
   to 1,000,000,000,000 — a teaching range, wide enough
   for amounts in a currency's smallest unit, narrow
   enough that a sum of two can never wrap the order
   and quietly mean a different total.

   The verdict keeps the house split. An opening check
   is true when the recomputed commitment matches the
   pasted one, false — never null — when every piece is
   well-formed and the recomputation lands elsewhere,
   and null when a piece cannot even be parsed: a
   malformed commitment, a value outside the range, a
   blinding that is not a whole scalar in [1, n−1].
   A zero blinding is refused for the same reason tool
   32 refuses a zero nonce: with r = 0 the commitment
   is just v×H, a watcher can test guesses of v one by
   one, and the hiding half is gone.

   The honest limits are plain. A commitment hides a
   value; it does not prove the value is in any range —
   a commitment to a negative or absurd amount is
   perfectly well-formed curve arithmetic, and real
   confidential systems pair commitments with range
   proofs for exactly that reason. This page is not
   one of Midnight's Compact circuit proofs, the
   commitment line here is the hub's own 91-byte SPKI
   point spelling, not a format any chain or wallet
   checks, and like tool 30 the curve code is a
   teaching implementation — affine arithmetic written
   to be read, not an audited library and not
   side-channel resistant. The blinding is a private
   number of the same rank as a private key: whoever
   holds a commitment's opening can show its value to
   anyone, so openings are shared the way tool 37 says
   share lines are shared — deliberately, never pasted
   around. Never paste a real wallet key or a
   production private key into any web page, including
   this one. */
var PEDERSEN_H_PREFIX = "privacy4all-pedersen-h-v1";
var PEDERSEN_MAX_VALUE = 1000000000000;

/* A committable value: a whole decimal number in
   [0, PEDERSEN_MAX_VALUE], canonicalised through
   BigInt so leading zeros and surrounding space are
   one spelling of one number. Signs, decimals,
   exponents, hex and anything past the ceiling are
   null — a commitment to a value this page cannot
   state exactly is a commitment it will not make. */
function parsePedersenValue(text) {
  if (typeof text !== "string") return null;
  var trimmed = text.trim();
  if (!/^[0-9]+$/.test(trimmed)) return null;
  var value = BigInt(trimmed);
  if (value > BigInt(PEDERSEN_MAX_VALUE)) return null;
  return value.toString();
}

/* The second generator H: hashed into the curve under
   its own label by try-and-increment — the digest is
   the x coordinate, the first counter whose x carries
   an on-curve point wins, and the even root is chosen,
   the same convention tool 35's hash-to-point uses.
   Deterministic and reproducible by anyone from the
   label alone, which is the whole point: a generator
   whose discrete logarithm nobody knows because
   nobody chose it — it fell out of a hash. */
function pedersenGeneratorPoint() {
  var sqrtExponent = (P256_P + P256_ONE) / BigInt(4);
  var attempt = function (counter) {
    if (counter > 255) return Promise.resolve(null);
    return sha256Hex(PEDERSEN_H_PREFIX + "\n" + counter)
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

/* The point arithmetic once H exists: r×G + v×H, with
   a zero value contributing no H term at all. Callers
   gate the blinding to [1, n−1] first, so the r×G term
   is never the identity here. */
function pedersenPointFor(hPoint, value, blinding) {
  var rPart = p256PointMultiply(blinding, { x: P256_GX, y: P256_GY });
  if (rPart === null) return null;
  if (value === P256_ZERO) return rPart;
  var vPart = p256PointMultiply(value, hPoint);
  if (vPart === null) return null;
  return p256PointAdd(rPart, vPart);
}

/* One commitment, made to order: the value and the
   blinding in, the commitment point — in the hub's
   usual 91-byte SPKI spelling — out. Synchronous
   pieces, one hash for H, so tests can pin the result
   from independent arithmetic. */
function pedersenCommitmentFor(valueText, blindingHex) {
  var value = parsePedersenValue(valueText);
  var blinding = parseProofScalar(blindingHex);
  if (value === null || blinding === null) {
    return Promise.resolve(null);
  }
  return pedersenGeneratorPoint().then(function (hHex) {
    if (hHex === null) return null;
    var hPoint = parseP256Point(hHex);
    if (hPoint === null) return null;
    var point = pedersenPointFor(hPoint, BigInt(value),
      BigInt("0x" + blinding));
    return point === null ? null : formatP256PublicKey(point);
  });
}

/* The maker's move: draw a fresh blinding — a new one
   every time, because a reused blinding across two
   values exposes their difference to anyone holding
   both commitments — and hand back the commitment
   with its opening. The opening (value + blinding) is
   the secret half: publish the commitment, keep the
   opening until the moment you choose to reveal. */
function makePedersenCommitment(valueText) {
  var value = parsePedersenValue(valueText);
  if (value === null) return Promise.resolve(null);
  var blinding = randomProofScalar();
  if (blinding === null) return Promise.resolve(null);
  return pedersenCommitmentFor(value, blinding).then(function (c) {
    if (c === null) return null;
    return { commitment: c, blinding: blinding, value: value };
  });
}

/* The opening check: recompute the commitment from
   the claimed value and blinding and compare points.
   True when they match, false when every piece is
   well-formed and they do not, null when any piece
   cannot be judged. */
function verifyPedersenOpening(commitmentHex, valueText, blindingHex) {
  var point = parseP256Point(commitmentHex);
  if (point === null || parsePedersenValue(valueText) === null ||
      parseProofScalar(blindingHex) === null) {
    return Promise.resolve(null);
  }
  return pedersenCommitmentFor(valueText, blindingHex)
    .then(function (recomputed) {
      if (recomputed === null) return null;
      return recomputed === formatP256PublicKey(point);
    });
}

/* Two commitments added as points — the homomorphism's
   left-hand side, on its own. Null when either point
   is malformed, or when the two cancel to the identity
   (a commitment to nothing, which this page will not
   spell as a point). */
function pedersenCommitmentSum(commitmentA, commitmentB) {
  var a = parseP256Point(commitmentA);
  var b = parseP256Point(commitmentB);
  if (a === null || b === null) return null;
  var sum = p256PointAdd(a, b);
  return sum === null ? null : formatP256PublicKey(sum);
}

/* The balance check: add the two commitments as
   points, add the two values as numbers and the two
   blindings under the order, and ask whether the sum
   opens exactly as the totals say. True when the
   added commitments are a commitment to the total
   under the added blinding; false — never null — when
   every piece is well-formed and they are not; null
   when any piece cannot be judged. A sum check judges
   TOTALS only: swapping the two blindings between the
   sides leaves the total blinding unchanged, so it
   still balances — which opening belongs to which
   commitment is the opening check's question, not
   this one's, and the tests pin the split. */
function checkPedersenSum(commitA, valueA, blindingA,
                           commitB, valueB, blindingB) {
  var aPoint = parseP256Point(commitA);
  var bPoint = parseP256Point(commitB);
  var vA = parsePedersenValue(valueA);
  var vB = parsePedersenValue(valueB);
  var rA = parseProofScalar(blindingA);
  var rB = parseProofScalar(blindingB);
  if (aPoint === null || bPoint === null || vA === null ||
      vB === null || rA === null || rB === null) {
    return Promise.resolve(null);
  }
  return pedersenGeneratorPoint().then(function (hHex) {
    if (hHex === null) return null;
    var hPoint = parseP256Point(hHex);
    if (hPoint === null) return null;
    var sumPoint = p256PointAdd(aPoint, bPoint);
    var totalValue = BigInt(vA) + BigInt(vB);
    var totalBlinding = (BigInt("0x" + rA) + BigInt("0x" + rB)) % P256_N;
    var expected = totalBlinding === P256_ZERO ?
      (totalValue === P256_ZERO ? null :
        p256PointMultiply(totalValue, hPoint)) :
      pedersenPointFor(hPoint, totalValue, totalBlinding);
    if (sumPoint === null || expected === null) {
      return sumPoint === null && expected === null;
    }
    return sumPoint.x === expected.x && sumPoint.y === expected.y;
  });
}

/* ---------- 43. In range, and I can prove it — range proofs ----------

   Tool 42 ends on a named limit: a Pedersen commitment
   hides a value, but it does not prove the value is in
   any range. A commitment built as curve arithmetic
   for a negative amount, or for a million when the
   ledger's rule is a maximum of 255, is perfectly
   well-formed — and a shielded system that accepted
   commitments without a range proof would let value
   be created out of the wrap-around, which is why real
   confidential systems (Midnight's shielded design
   among them) pair every commitment with one. This
   tool is the textbook construction those systems
   optimise: prove, bit by bit, that the hidden value
   is a whole number from 0 to 255, revealing neither
   the value nor its blinding.

   The value is written in binary, v = Σ 2^i·b_i over
   eight bits, and every bit gets a Pedersen commitment
   of its own, D_i = s_i×G + b_i×H, built with tool
   42's own generator H. The bit blindings are chosen
   so the weighted sum lands exactly on the commitment
   being proved: s_0…s_6 are fresh random scalars, and
   s_7 is solved from (r − Σ_{i<7} 2^i·s_i) × (128⁻¹
   mod n), so Σ 2^i·D_i = C as points — a sum the
   verifier recomputes for themselves, which pins the
   bits to THIS commitment and no other. What remains
   is to prove each D_i hides a bit — 0 or 1, nothing
   between — without opening it. That is an OR proof
   in the Cramer–Damgård–Schoenmakers shape, run over
   the two statements a bit commitment can make:

     branch 0: D_i itself is s_i×G         (the bit is 0)
     branch 1: D_i − H is s_i×G            (the bit is 1)

   Exactly one branch's discrete logarithm is known to
   the prover — the true one, whose witness is s_i;
   the other branch's logarithm runs through H, whose
   logarithm nobody knows. The prover answers the true
   branch the way tool 32 answers a challenge, and
   SIMULATES the other branch backwards from a
   self-chosen challenge and response, the same
   backwards move tool 5's simulator makes — except
   here the simulation is half of an honest proof, not
   a fake one. One Fiat–Shamir challenge binds the
   whole proof: c = SHA-256 under the label
   privacy4all-rangeproof-v1 over the commitment, the
   eight bit commitments and all sixteen branch
   commitments, reduced under the order; each bit's
   two branch challenges must sum to that same c,
   which is what stops a prover choosing both branches
   freely — they can pre-build one branch per bit, and
   the hash chooses how the rest must go. A verifier
   needs no secret at all: add the bit commitments
   with their weights and compare against the pasted
   commitment, rebuild every branch commitment from
   its challenge and response (R = s×G − c×X), re-hash,
   and check each bit's pair sums to the hash.

   The verdict keeps the house split. True when the
   weighted sum matches and every pair sums to the
   challenge; false — never null — when every piece is
   well-formed and one of those checks fails: a proof
   transplanted to another commitment, one nudged
   response, two bit records swapped. Null when a
   piece cannot even be parsed: a malformed point, a
   proof line with the wrong number of fields, a
   scalar at or past the order. Making a proof also
   refuses as null what it cannot honestly prove: a
   value outside 0…255 (a commitment to 256 is a fine
   tool-42 commitment and an unprovable statement
   here — that refusal IS the range doing its work),
   and an opening whose value and blinding do not
   recompute the pasted commitment.

   The honest limits are plain. Eight bits is a
   teaching range, chosen so the whole proof fits on
   one page and every step can be followed; production
   range proofs (Bulletproofs, and the proofs a
   Compact circuit makes) cover 64-bit amounts in
   logarithmic space instead of one OR proof per bit,
   and they are circuit or protocol proofs, not this
   page's transcript. The proof line here is the hub's
   own p4a-rangeproof-v1 spelling over P-256 teaching
   arithmetic — not a format any chain or wallet
   checks, not one of Midnight's Compact circuit
   proofs, and the curve code is a teaching
   implementation: affine arithmetic written to be
   read, not an audited library and not side-channel
   resistant. The proof reveals the commitment and
   nothing else — not the value, not the blinding, not
   even which branch was real for any bit — but the
   opening it is made from stays a private number of
   the same rank as a private key, shared the way tool
   42 says openings are shared. Never paste a real
   wallet key or a production private key into any web
   page, including this one. */
var RANGEPROOF_FORMAT = "p4a-rangeproof-v1";
var RANGEPROOF_CHALLENGE_PREFIX = "privacy4all-rangeproof-v1";
var RANGE_BITS = 8;
var RANGE_MAX_VALUE = 255;

/* A value this tool can prove things about: a whole
   decimal number in [0, RANGE_MAX_VALUE], canonicalised
   through BigInt exactly the way tool 42 canonicalises
   its wider range. Anything past 255 is null here even
   though tool 42 would happily commit to it — the
   refusal is the range, stated as code. */
function parseRangeValue(text) {
  if (typeof text !== "string") return null;
  var trimmed = text.trim();
  if (!/^[0-9]+$/.test(trimmed)) return null;
  var value = BigInt(trimmed);
  if (value > BigInt(RANGE_MAX_VALUE)) return null;
  return value.toString();
}

function rangeModN(value) {
  var r = value % P256_N;
  return r < P256_ZERO ? r + P256_N : r;
}

/* (2^7)^-1 and friends under the order, by Fermat:
   the order is prime, so a^(n−2) is the inverse.
   Used once per proof, to solve the last bit's
   blinding from the weighted-sum equation. */
function rangeScalarPow(base, exponent) {
  var result = P256_ONE;
  var b = rangeModN(base);
  var e = exponent;
  while (e > P256_ZERO) {
    if ((e & P256_ONE) === P256_ONE) result = rangeModN(result * b);
    b = rangeModN(b * b);
    e = e >> P256_ONE;
  }
  return result;
}

/* The one challenge for the whole proof: SHA-256 over
   the label, the commitment being proved, the eight
   bit commitments and the sixteen branch commitments,
   every point canonicalised first so the hash names
   points and not spellings. Reduced under the order;
   a reduced digest of zero is null — with c = 0 both
   branch challenges would be chosen freely and the
   proof would bind nothing, the same refusal tool 33
   makes. Inputs are arrays of point hexes of exactly
   the labelled lengths; anything else is null. */
function rangeProofChallenge(commitmentHex, bitCommitments, branchCommitments) {
  var commitment = parseP256Point(commitmentHex);
  if (commitment === null || !Array.isArray(bitCommitments) ||
      !Array.isArray(branchCommitments) ||
      bitCommitments.length !== RANGE_BITS ||
      branchCommitments.length !== RANGE_BITS * 2) {
    return Promise.resolve(null);
  }
  var canonicalBits = [];
  var i;
  for (i = 0; i < bitCommitments.length; i++) {
    var bitPoint = parseP256Point(bitCommitments[i]);
    if (bitPoint === null) return Promise.resolve(null);
    canonicalBits.push(formatP256PublicKey(bitPoint));
  }
  var canonicalBranches = [];
  for (i = 0; i < branchCommitments.length; i++) {
    var branchPoint = parseP256Point(branchCommitments[i]);
    if (branchPoint === null) return Promise.resolve(null);
    canonicalBranches.push(formatP256PublicKey(branchPoint));
  }
  var transcript = RANGEPROOF_CHALLENGE_PREFIX + "\n" +
    formatP256PublicKey(commitment) + "\n" +
    canonicalBits.join("\n") + "\n" + canonicalBranches.join("\n");
  return sha256Hex(transcript).then(function (digest) {
    if (digest === null) return null;
    var value = BigInt("0x" + digest) % P256_N;
    if (value === P256_ZERO) return null;
    return p256IntToHex(value);
  });
}

/* The proof line: the format tag, then per bit the
   bit commitment (a whole 91-byte point) and the two
   branches' challenges and responses (c0, s0, c1, s1),
   challenges and responses gated as responses — zero
   allowed, the order refused — because a branch
   challenge honestly can be the difference that lands
   on zero. Pieces that do not check out are null,
   never a half-built line. */
function formatRangeProof(bitCommitments, branches) {
  if (!Array.isArray(bitCommitments) || !Array.isArray(branches) ||
      bitCommitments.length !== RANGE_BITS ||
      branches.length !== RANGE_BITS) {
    return null;
  }
  var parts = [RANGEPROOF_FORMAT];
  for (var i = 0; i < RANGE_BITS; i++) {
    var point = parseP256Point(bitCommitments[i]);
    var branch = branches[i];
    if (point === null || branch === null ||
        typeof branch !== "object") return null;
    var c0 = parseProofResponse(branch.challenge0);
    var s0 = parseProofResponse(branch.response0);
    var c1 = parseProofResponse(branch.challenge1);
    var s1 = parseProofResponse(branch.response1);
    if (c0 === null || s0 === null || c1 === null || s1 === null) {
      return null;
    }
    parts.push(formatP256PublicKey(point));
    parts.push(c0); parts.push(s0); parts.push(c1); parts.push(s1);
  }
  return parts.join(":");
}

function parseRangeProof(text) {
  if (typeof text !== "string") return null;
  var parts = text.trim().split(":");
  if (parts.length !== 1 + RANGE_BITS * 5 ||
      parts[0] !== RANGEPROOF_FORMAT) return null;
  var bitCommitments = [];
  var branches = [];
  for (var i = 0; i < RANGE_BITS; i++) {
    var base = 1 + i * 5;
    var point = parseP256Point(parts[base]);
    var c0 = parseProofResponse(parts[base + 1]);
    var s0 = parseProofResponse(parts[base + 2]);
    var c1 = parseProofResponse(parts[base + 3]);
    var s1 = parseProofResponse(parts[base + 4]);
    if (point === null || c0 === null || s0 === null ||
        c1 === null || s1 === null) return null;
    bitCommitments.push(formatP256PublicKey(point));
    branches.push({ challenge0: c0, response0: s0,
                    challenge1: c1, response1: s1 });
  }
  return { bitCommitments: bitCommitments, branches: branches };
}

/* One attempt at a proof, with all randomness drawn
   fresh inside the attempt. Any impossible point — a
   bit commitment or branch commitment landing on the
   identity, the solved last blinding coming out zero —
   fails the attempt as null and the caller redraws,
   the same discipline tool 33's signer follows. */
function rangeProofAttempt(hPoint, commitmentHex, value, blindingHex) {
  var numericValue = BigInt(value);
  var bits = [];
  var i;
  for (i = 0; i < RANGE_BITS; i++) {
    bits.push(Number((numericValue >> BigInt(i)) & P256_ONE));
  }
  var blindings = [];
  for (i = 0; i < RANGE_BITS - 1; i++) {
    var drawn = randomProofScalar();
    if (drawn === null) return Promise.resolve(null);
    blindings.push(BigInt("0x" + drawn));
  }
  var weighted = P256_ZERO;
  for (i = 0; i < RANGE_BITS - 1; i++) {
    weighted = rangeModN(weighted + BigInt(2 ** i) * blindings[i]);
  }
  var inverse = rangeScalarPow(BigInt(2 ** (RANGE_BITS - 1)), P256_N - P256_TWO);
  var last = rangeModN((BigInt("0x" + blindingHex) - weighted) * inverse);
  if (last === P256_ZERO) return Promise.resolve(null);
  blindings.push(last);
  var bitPoints = [];
  var bitHexes = [];
  for (i = 0; i < RANGE_BITS; i++) {
    var bitPoint = pedersenPointFor(hPoint, BigInt(bits[i]), blindings[i]);
    if (bitPoint === null) return Promise.resolve(null);
    bitPoints.push(bitPoint);
    bitHexes.push(formatP256PublicKey(bitPoint));
  }
  var negH = { x: hPoint.x, y: P256_P - hPoint.y };
  var branchHexes = [];
  var simulated = [];
  for (i = 0; i < RANGE_BITS; i++) {
    var statements = [bitPoints[i], p256PointAdd(bitPoints[i], negH)];
    if (statements[1] === null) return Promise.resolve(null);
    var simChallenge = randomProofScalar();
    var simResponse = randomProofScalar();
    var nonce = randomProofScalar();
    if (simChallenge === null || simResponse === null || nonce === null) {
      return Promise.resolve(null);
    }
    var simScalar = BigInt("0x" + simChallenge);
    var realPoint = p256PointMultiply(BigInt("0x" + nonce),
      { x: P256_GX, y: P256_GY });
    var simPoint = p256PointAdd(
      p256PointMultiply(BigInt("0x" + simResponse),
        { x: P256_GX, y: P256_GY }),
      p256PointMultiply(rangeModN(-simScalar), statements[1 - bits[i]]));
    if (realPoint === null || simPoint === null) {
      return Promise.resolve(null);
    }
    simulated.push({ challenge: simScalar, response: simResponse,
                     nonce: nonce, statements: statements });
    var ordered = bits[i] === 0 ? [realPoint, simPoint] : [simPoint, realPoint];
    branchHexes.push(formatP256PublicKey(ordered[0]));
    branchHexes.push(formatP256PublicKey(ordered[1]));
  }
  return rangeProofChallenge(commitmentHex, bitHexes, branchHexes)
    .then(function (challenge) {
      if (challenge === null) return null;
      var challengeValue = BigInt("0x" + challenge);
      var branches = [];
      for (var j = 0; j < RANGE_BITS; j++) {
        var realChallenge = rangeModN(challengeValue - simulated[j].challenge);
        var realResponse = rangeModN(BigInt("0x" + simulated[j].nonce) +
          realChallenge * blindings[j]);
        var realPair = { challenge: p256IntToHex(realChallenge),
                         response: p256IntToHex(realResponse) };
        var simPair = { challenge: p256IntToHex(simulated[j].challenge),
                        response: simulated[j].response };
        var first = bits[j] === 0 ? realPair : simPair;
        var second = bits[j] === 0 ? simPair : realPair;
        branches.push({ challenge0: first.challenge,
                        response0: first.response,
                        challenge1: second.challenge,
                        response1: second.response });
      }
      return formatRangeProof(bitHexes, branches);
    });
}

/* The prover's move: given a tool-42 commitment and
   its opening, prove the hidden value lies in
   0…255. The opening is checked first — a value and
   blinding that do not recompute the commitment are
   refused as null, because a proof built on a false
   opening would be a lie with good formatting. The
   value's range is checked by parseRangeValue before
   any of that: outside 0…255 there is nothing here
   to prove, whatever the commitment hides. */
function makeRangeProof(commitmentHex, valueText, blindingHex) {
  var point = parseP256Point(commitmentHex);
  var value = parseRangeValue(valueText);
  var blinding = parseProofScalar(blindingHex);
  if (point === null || value === null || blinding === null) {
    return Promise.resolve(null);
  }
  var canonical = formatP256PublicKey(point);
  return pedersenCommitmentFor(value, blinding).then(function (recomputed) {
    if (recomputed === null || recomputed !== canonical) return null;
    return pedersenGeneratorPoint().then(function (hHex) {
      if (hHex === null) return null;
      var hPoint = parseP256Point(hHex);
      if (hPoint === null) return null;
      var attempt = function (triesLeft) {
        return rangeProofAttempt(hPoint, canonical, value, blinding)
          .then(function (proof) {
            if (proof !== null) return proof;
            return triesLeft > 1 ? attempt(triesLeft - 1) : null;
          });
      };
      return attempt(4);
    });
  });
}

/* The verifier's verdict, needing no secret at all:
   the weighted sum of the bit commitments must be
   the pasted commitment itself, point for point, and
   every bit's two branch challenges must sum to the
   one Fiat–Shamir challenge re-hashed from the branch
   commitments the responses rebuild. True when both
   hold; false — never null — when every piece is
   well-formed and either fails; null when a piece
   cannot even be parsed, or a rebuilt branch lands
   on the identity and cannot be named in the hash. */
function verifyRangeProof(commitmentHex, proofText) {
  var point = parseP256Point(commitmentHex);
  var proof = parseRangeProof(proofText);
  if (point === null || proof === null) return Promise.resolve(null);
  return pedersenGeneratorPoint().then(function (hHex) {
    if (hHex === null) return null;
    var hPoint = parseP256Point(hHex);
    if (hPoint === null) return null;
    var negH = { x: hPoint.x, y: P256_P - hPoint.y };
    var sum = null;
    var i;
    for (i = 0; i < RANGE_BITS; i++) {
      var weighted = p256PointMultiply(BigInt(2 ** i),
        parseP256Point(proof.bitCommitments[i]));
      if (weighted === null) return null;
      sum = p256PointAdd(sum, weighted);
    }
    if (sum === null || sum.x !== point.x || sum.y !== point.y) {
      return false;
    }
    var branchHexes = [];
    for (i = 0; i < RANGE_BITS; i++) {
      var bitPoint = parseP256Point(proof.bitCommitments[i]);
      var statements = [bitPoint, p256PointAdd(bitPoint, negH)];
      if (statements[1] === null) return null;
      var branch = proof.branches[i];
      var responses = [branch.response0, branch.response1];
      var challenges = [branch.challenge0, branch.challenge1];
      for (var j = 0; j < 2; j++) {
        var rebuilt = p256PointAdd(
          p256PointMultiply(BigInt("0x" + responses[j]),
            { x: P256_GX, y: P256_GY }),
          p256PointMultiply(
            rangeModN(-BigInt("0x" + challenges[j])), statements[j]));
        if (rebuilt === null) return null;
        branchHexes.push(formatP256PublicKey(rebuilt));
      }
    }
    return rangeProofChallenge(formatP256PublicKey(point),
      proof.bitCommitments, branchHexes).then(function (challenge) {
      if (challenge === null) return null;
      var challengeValue = BigInt("0x" + challenge);
      for (var k = 0; k < RANGE_BITS; k++) {
        var pairSum = rangeModN(BigInt("0x" + proof.branches[k].challenge0) +
          BigInt("0x" + proof.branches[k].challenge1));
        if (pairSum !== challengeValue) return false;
      }
      return true;
    });
  });
}

/* ---------- 44. Same value, twice hidden — equality proofs ----------

   Tools 42 and 43 ask questions about ONE commitment:
   does it open to this value, is the hidden value in
   range. A shielded ledger asks a two-commitment
   question just as often: the commitment published
   when a note was created and the commitment in
   today's transfer — do they hide the SAME amount?
   If they do, value moved from one hiding place to
   another without changing; if they do not, value was
   created or destroyed somewhere between the two
   points on the ledger. This tool proves the equality
   without opening either commitment.

   The arithmetic is one subtraction. Two commitments
   to the same value under different blindings,

     C1 = r1×G + v×H        C2 = r2×G + v×H,

   differ only in their blinding terms, so their
   difference is a plain multiple of the base point:

     C1 − C2 = (r1 − r2)×G.

   Proving the values equal is therefore proving
   knowledge of the difference d = (r1 − r2) mod n
   behind the difference point D = C1 − C2 — a
   Schnorr proof of knowledge, tool 32's protocol,
   aimed at a point the verifier computes for
   themselves from the two pasted commitments.
   The prover commits to a fresh nonce (R = k×G),
   the challenge is SHA-256 under the label
   privacy4all-eqproof-v1 over the two commitments
   and the nonce commitment, and the response is
   tool 32's own s = k + c·d mod n; the verifier
   checks s×G = R + c×D. If the values had differed
   by any δ ≠ 0, the difference point would carry a
   δ×H term, and answering the challenge would mean
   knowing the discrete logarithm of an H-carrying
   point under G — the very logarithm tool 42's
   generator is built so nobody knows. That unknown
   is the soundness: equality here is proved, not
   merely claimed.

   The witness deserves stating plainly: it is the
   blinding difference and nothing else. The value
   never enters the response — anyone holding both
   blindings can make this proof, and the proof
   itself names neither the value nor either
   blinding. It also binds the pair in order: the
   challenge hashes C1 before C2, and the swapped
   pair is a different statement (its witness is
   −d), so a proof does not transplant from one
   ordering to the other.

   The verdict keeps the house split. True when the
   response balances against the difference point;
   false — never null — when every piece is
   well-formed and it does not: a nudged response, a
   proof transplanted to a pair whose values differ,
   the pair pasted in the wrong order. Null when a
   piece cannot even be parsed, and in one case that
   is the statement's own edge: identical commitments
   have the identity for a difference, which has no
   point spelling on this page — two identical
   commitments are visibly equal already, and there
   is nothing to prove. Making a proof also refuses
   as null what it cannot honestly prove: openings
   that do not recompute their commitments, two
   values that differ (the refusal IS the equality
   failing, stated before any proof is attempted),
   equal blindings (which would make the commitments
   identical), and a zero blinding on either side.

   The honest limits are plain. The nonce discipline
   is inherited whole from tool 32: one nonce behind
   two responses hands back the witness — here the
   blinding difference — and the tests pin exactly
   that recovery, using one nonce for the pair and
   for the pair swapped. Whoever learns the blinding
   difference and holds one blinding holds the other,
   so the difference is a secret of the same rank.
   The proof line is the hub's own p4a-eqproof-v1
   spelling over P-256 teaching arithmetic — not a
   format any chain or wallet checks, not one of
   Midnight's Compact circuit proofs, and the curve
   code is a teaching implementation: affine
   arithmetic written to be read, not an audited
   library and not side-channel resistant. Never
   paste a real wallet key or a production private
   key into any web page, including this one;
   practise with throwaway commitments from tool 42.
   Tool 45 below asks a set question about one
   commitment instead of an equality question about
   two. */
var EQPROOF_FORMAT = "p4a-eqproof-v1";
var EQPROOF_CHALLENGE_PREFIX = "privacy4all-eqproof-v1";

/* The difference point of two commitments, C1 − C2,
   in the hub's 91-byte spelling. When the values
   match it is (r1 − r2)×G; when they do not it
   carries the value gap as an H term. Null when
   either point is malformed, or when the two are
   identical and the difference is the identity,
   which this page does not spell as a point. */
function eqProofDifference(commitmentA, commitmentB) {
  var a = parseP256Point(commitmentA);
  var b = parseP256Point(commitmentB);
  if (a === null || b === null) return null;
  var diff = p256PointAdd(a, p256PointNegate(b));
  return diff === null ? null : formatP256PublicKey(diff);
}

/* The one challenge for a proof: SHA-256 over the
   label, the two commitments in order and the nonce
   commitment, every point canonicalised first so the
   hash names points and not spellings. Reduced under
   the order; a reduced digest of zero is null — with
   c = 0 the response would bind nothing, the same
   refusal tools 32 and 33 make. */
function eqProofChallenge(commitmentA, commitmentB, noncePointHex) {
  var a = parseP256Point(commitmentA);
  var b = parseP256Point(commitmentB);
  var r = parseP256Point(noncePointHex);
  if (a === null || b === null || r === null) {
    return Promise.resolve(null);
  }
  var transcript = EQPROOF_CHALLENGE_PREFIX + "\n" +
    formatP256PublicKey(a) + "\n" + formatP256PublicKey(b) +
    "\n" + formatP256PublicKey(r);
  return sha256Hex(transcript).then(function (digest) {
    if (digest === null) return null;
    var value = BigInt("0x" + digest) % P256_N;
    if (value === P256_ZERO) return null;
    return p256IntToHex(value);
  });
}

/* The proof line: the format tag, the nonce
   commitment (a whole 91-byte point) and the
   response, gated as a response — zero allowed, the
   order refused. Pieces that do not check out are
   null, never a half-built line. */
function formatEqualityProof(noncePointHex, responseHex) {
  var point = parseP256Point(noncePointHex);
  var response = parseProofResponse(responseHex);
  if (point === null || response === null) return null;
  return [EQPROOF_FORMAT, formatP256PublicKey(point), response].join(":");
}

function parseEqualityProof(text) {
  if (typeof text !== "string") return null;
  var parts = text.trim().split(":");
  if (parts.length !== 3 || parts[0] !== EQPROOF_FORMAT) return null;
  var point = parseP256Point(parts[1]);
  var response = parseProofResponse(parts[2]);
  if (point === null || response === null) return null;
  return { nonceCommitment: formatP256PublicKey(point),
           response: response };
}

/* One attempt at a proof, with the nonce drawn fresh
   inside the attempt. A zero challenge or a zero
   response fails the attempt as null and the caller
   redraws, the same discipline tool 33's signer
   follows. */
function equalityProofAttempt(commitmentA, commitmentB, differenceHex) {
  var nonce = randomProofScalar();
  if (nonce === null) return Promise.resolve(null);
  var noncePoint = proofCommitmentForNonce(nonce);
  if (noncePoint === null) return Promise.resolve(null);
  return eqProofChallenge(commitmentA, commitmentB, noncePoint)
    .then(function (challenge) {
      if (challenge === null) return null;
      var response = proofResponseForScalar(differenceHex, nonce, challenge);
      if (response === null) return null;
      return formatEqualityProof(noncePoint, response);
    });
}

/* The prover's move: given two tool-42 commitments
   and both openings, prove the hidden values are the
   same. Both openings are checked first — a value and
   blinding that do not recompute their commitment are
   refused as null — and the values themselves are
   compared before anything is proved: two different
   values get null, because no honest proof of their
   equality exists. Equal blindings are refused the
   same way: they would make the two commitments the
   same point, and identical commitments are visibly
   equal — there is nothing to prove. */
function makeEqualityProof(commitA, valueA, blindingA,
                           commitB, valueB, blindingB) {
  var aPoint = parseP256Point(commitA);
  var bPoint = parseP256Point(commitB);
  var vA = parsePedersenValue(valueA);
  var vB = parsePedersenValue(valueB);
  var rA = parseProofScalar(blindingA);
  var rB = parseProofScalar(blindingB);
  if (aPoint === null || bPoint === null || vA === null ||
      vB === null || rA === null || rB === null) {
    return Promise.resolve(null);
  }
  if (vA !== vB) return Promise.resolve(null);
  var difference = rangeModN(BigInt("0x" + rA) - BigInt("0x" + rB));
  if (difference === P256_ZERO) return Promise.resolve(null);
  var differenceHex = p256IntToHex(difference);
  var canonA = formatP256PublicKey(aPoint);
  var canonB = formatP256PublicKey(bPoint);
  return pedersenCommitmentFor(vA, rA).then(function (recomputedA) {
    if (recomputedA === null || recomputedA !== canonA) return null;
    return pedersenCommitmentFor(vB, rB).then(function (recomputedB) {
      if (recomputedB === null || recomputedB !== canonB) return null;
      var attempt = function (triesLeft) {
        return equalityProofAttempt(canonA, canonB, differenceHex)
          .then(function (proof) {
            if (proof !== null) return proof;
            return triesLeft > 1 ? attempt(triesLeft - 1) : null;
          });
      };
      return attempt(4);
    });
  });
}

/* The verifier's verdict, needing no secret at all:
   subtract the second commitment from the first,
   re-hash the challenge from the two commitments and
   the proof's nonce commitment, and check the
   response balances — s×G against R + c×D. True when
   it balances; false — never null — when every piece
   is well-formed and it does not; null when a piece
   cannot even be parsed, or when the two commitments
   are identical and their difference is the identity
   this page does not spell. An identity on either
   side of the balance counts as the identity point
   it is: both sides landing there together is a
   balance, one side alone is not. */
function verifyEqualityProof(commitA, commitB, proofText) {
  var aPoint = parseP256Point(commitA);
  var bPoint = parseP256Point(commitB);
  var proof = parseEqualityProof(proofText);
  if (aPoint === null || bPoint === null || proof === null) {
    return Promise.resolve(null);
  }
  var diff = p256PointAdd(aPoint, p256PointNegate(bPoint));
  if (diff === null) return Promise.resolve(null);
  return eqProofChallenge(formatP256PublicKey(aPoint),
    formatP256PublicKey(bPoint), proof.nonceCommitment)
    .then(function (challenge) {
      if (challenge === null) return null;
      var lhs = p256PointMultiply(BigInt("0x" + proof.response),
        { x: P256_GX, y: P256_GY });
      var rhs = p256PointAdd(parseP256Point(proof.nonceCommitment),
        p256PointMultiply(BigInt("0x" + challenge), diff));
      if (lhs === null || rhs === null) {
        return lhs === null && rhs === null;
      }
      return lhs.x === rhs.x && lhs.y === rhs.y;
    });
}

/* ---------- 45. One of these, I won't say which — set-membership proofs ----------

   Tools 43 and 44 each answer one shape of question
   about a hidden value: is it in a range, and does
   it equal another hidden value. A third shape is
   just as common in a selective-disclosure world:
   is the hidden value ONE OF a small public list?
   A credential whose tier is one of three published
   tiers, an age bracket one of the brackets a venue
   accepts, a jurisdiction on an allowed list — the
   verifier publishes the list, the prover's value is
   on it, and which entry it is stays hidden. This
   tool proves exactly that membership over tool
   42's Pedersen commitments, and nothing more.

   The arithmetic starts from the commitment,
   C = r×G + v×H. For each candidate value v_i on
   the public list, anyone can compute the shifted
   point D_i = C − v_i×H = r×G + (v − v_i)×H. For
   the one candidate that equals the hidden value,
   the H term vanishes and D_i is a plain multiple
   of the base point, r×G — a statement about which
   the prover knows the discrete logarithm, because
   the witness is their own blinding r. For every
   other candidate the H term survives, and its
   logarithm under G is the number tool 42's
   generator is built so nobody knows. Membership
   is therefore an OR proof in the
   Cramer–Damgård–Schoenmakers shape tool 43 uses
   for its bits, run once per candidate instead of
   once per bit: the true branch is answered the
   way tool 32 answers a challenge, with a fresh
   nonce, and every other branch is SIMULATED
   backwards from a self-chosen challenge and
   response (R_i = s_i×G − c_i×D_i). One
   Fiat–Shamir challenge binds the whole proof —
   SHA-256 under the label privacy4all-setmember-v1
   over the commitment, the canonical candidate
   list and every branch's nonce commitment — and
   the branch challenges must sum to it under the
   order, which is what stops a prover pre-building
   every branch freely: they can pre-build all but
   one, and the hash decides how the last must go.

   The candidate list is a set, not a sequence: the
   entries are canonicalised through tool 42's own
   value parser, duplicates are refused, and the
   list is hashed in sorted order, so a proof does
   not depend on the order anyone typed the list
   in — the same set makes the same statement in
   any order. Two to six candidates: a set of one
   would name the value outright, and past six the
   teaching page's line grows past what a reader
   can follow.

   The verdict keeps the house split. True when
   every branch balances and the challenges sum to
   the rehashed one; false — never null — when
   every piece is well-formed and one of those
   fails: a nudged response, branches swapped
   between candidates, a proof checked against a
   different list, a proof transplanted to a
   commitment whose value is on no list. Null when
   a piece cannot even be parsed, or when a shifted
   point lands on the identity — a pasted point
   equal to some candidate's v_i×H alone, with no
   blinding term at all, which this page does not
   spell and cannot judge as a commitment.
   Making a proof also refuses as null what it
   cannot honestly prove: a value that is not on
   the list (the refusal IS the membership failing,
   stated before any proof is attempted), and an
   opening that does not recompute its commitment.

   The honest limits are plain. The set is public
   and membership is all the proof says — a set of
   two is a coin flip about which entry, so small
   sets leak by their size, and membership in a
   set nobody else belongs to is a name, not a
   hiding place. The witness is the blinding alone:
   anyone holding the opening can make this proof,
   and the proof names neither the value nor the
   blinding. The nonce discipline is inherited
   whole from tool 32: one nonce behind two
   responses hands back the witness it answered
   with. The proof line is the hub's own
   p4a-setmember-v1 spelling over P-256 teaching
   arithmetic — not a format any chain or wallet
   checks, not one of Midnight's Compact circuit
   proofs, and like tool 30 the curve code is a
   teaching implementation: affine arithmetic
   written to be read and checked line by line, not
   an audited library and not side-channel
   resistant. Never paste a real wallet key or a
   production private key into any web page,
   including this one; practise with throwaway
   commitments from tool 42. */
var SETMEMBER_FORMAT = "p4a-setmember-v1";
var SETMEMBER_CHALLENGE_PREFIX = "privacy4all-setmember-v1";
var SETMEMBER_MIN_CANDIDATES = 2;
var SETMEMBER_MAX_CANDIDATES = 6;

/* The public list, parsed as a set: comma-separated
   values, each canonicalised by tool 42's own value
   parser, duplicates refused — a list that names a
   value twice is a smaller set wearing a longer
   list — and sorted ascending as numbers, so the
   statement is the set itself and not the order it
   was typed in. Anything outside two to six
   distinct in-range values is null. The return is
   the canonical array of value strings. */
function parseSetCandidates(text) {
  if (typeof text !== "string") return null;
  var rawParts = text.split(",");
  if (rawParts.length < SETMEMBER_MIN_CANDIDATES ||
      rawParts.length > SETMEMBER_MAX_CANDIDATES) return null;
  var seen = {};
  var values = [];
  for (var i = 0; i < rawParts.length; i++) {
    var value = parsePedersenValue(rawParts[i]);
    if (value === null || seen[value]) return null;
    seen[value] = true;
    values.push(value);
  }
  values.sort(function (a, b) {
    var x = BigInt(a), y = BigInt(b);
    return x < y ? -1 : (x > y ? 1 : 0);
  });
  return values;
}

/* A candidate array as the challenge and the
   statement points need it: an array of two to six
   value strings that canonicalise, with no
   duplicates, returned in the same sorted canonical
   order parseSetCandidates produces. Anything else
   is null, so the helpers below judge one spelling
   of a set and never two. */
function canonicalSetCandidates(candidates) {
  if (!Array.isArray(candidates) ||
      candidates.length < SETMEMBER_MIN_CANDIDATES ||
      candidates.length > SETMEMBER_MAX_CANDIDATES) return null;
  var seen = {};
  var values = [];
  for (var i = 0; i < candidates.length; i++) {
    if (typeof candidates[i] !== "string") return null;
    var value = parsePedersenValue(candidates[i]);
    if (value === null || value !== candidates[i] || seen[value]) {
      return null;
    }
    seen[value] = true;
    values.push(value);
  }
  var sorted = values.slice().sort(function (a, b) {
    var x = BigInt(a), y = BigInt(b);
    return x < y ? -1 : (x > y ? 1 : 0);
  });
  for (var j = 0; j < values.length; j++) {
    if (sorted[j] !== values[j]) return null;
  }
  return values;
}

/* The shifted point for one candidate, D = C − v×H,
   in the hub's 91-byte spelling: for the candidate
   that equals the hidden value it is the blinding's
   own public point; for every other it carries the
   value gap as an H term. A zero candidate shifts
   nothing, so its point is the commitment itself.
   Null when a piece is malformed, or when the
   shifted point is the identity — a commitment
   with no blinding term at all. */
function setMemberStatementPoint(commitmentHex, candidateText, hPoint) {
  var point = parseP256Point(commitmentHex);
  var value = parsePedersenValue(candidateText);
  if (point === null || value === null || hPoint === null) return null;
  var shifted = p256PointAdd(point,
    p256PointNegate(p256PointMultiply(BigInt(value), hPoint)));
  return shifted === null ? null : formatP256PublicKey(shifted);
}

/* All the shifted points for a statement, in the
   canonical candidate order: one hash for H, then
   plain point arithmetic per candidate. Null when
   the commitment or the list cannot be judged, or
   when any shifted point is the identity. */
function setMemberStatementPoints(commitmentHex, candidates) {
  var canonical = canonicalSetCandidates(candidates);
  var point = parseP256Point(commitmentHex);
  if (canonical === null || point === null) {
    return Promise.resolve(null);
  }
  return pedersenGeneratorPoint().then(function (hHex) {
    if (hHex === null) return null;
    var hPoint = parseP256Point(hHex);
    if (hPoint === null) return null;
    var points = [];
    for (var i = 0; i < canonical.length; i++) {
      var shifted = setMemberStatementPoint(
        formatP256PublicKey(point), canonical[i], hPoint);
      if (shifted === null) return null;
      points.push(shifted);
    }
    return points;
  });
}

/* The one challenge for a proof: SHA-256 over the
   label, the commitment, the canonical candidate
   list and every branch's nonce commitment, every
   point canonicalised first so the hash names
   points and not spellings. Reduced under the
   order; a reduced digest of zero is null — with
   c = 0 every branch challenge would be chosen
   freely and the proof would bind nothing, the
   same refusal tools 32 and 33 make. */
function setMemberChallenge(commitmentHex, candidates, noncePoints) {
  var point = parseP256Point(commitmentHex);
  var canonical = canonicalSetCandidates(candidates);
  if (point === null || canonical === null ||
      !Array.isArray(noncePoints) ||
      noncePoints.length !== canonical.length) {
    return Promise.resolve(null);
  }
  var canonicalNonces = [];
  for (var i = 0; i < noncePoints.length; i++) {
    var noncePoint = parseP256Point(noncePoints[i]);
    if (noncePoint === null) return Promise.resolve(null);
    canonicalNonces.push(formatP256PublicKey(noncePoint));
  }
  var transcript = SETMEMBER_CHALLENGE_PREFIX + "\n" +
    formatP256PublicKey(point) + "\n" + canonical.join(",") +
    "\n" + canonicalNonces.join("\n");
  return sha256Hex(transcript).then(function (digest) {
    if (digest === null) return null;
    var value = BigInt("0x" + digest) % P256_N;
    if (value === P256_ZERO) return null;
    return p256IntToHex(value);
  });
}

/* The proof line: the format tag, then per candidate
   — in the canonical order — the branch's nonce
   commitment (a whole 91-byte point) and its
   challenge and response, gated as responses: zero
   allowed, the order refused, because a branch
   challenge honestly can be the difference that
   lands on zero. Pieces that do not check out are
   null, never a half-built line. */
function formatSetMembershipProof(branches) {
  if (!Array.isArray(branches) ||
      branches.length < SETMEMBER_MIN_CANDIDATES ||
      branches.length > SETMEMBER_MAX_CANDIDATES) return null;
  var parts = [SETMEMBER_FORMAT];
  for (var i = 0; i < branches.length; i++) {
    var branch = branches[i];
    if (branch === null || typeof branch !== "object") return null;
    var point = parseP256Point(branch.nonceCommitment);
    var challenge = parseProofResponse(branch.challenge);
    var response = parseProofResponse(branch.response);
    if (point === null || challenge === null || response === null) {
      return null;
    }
    parts.push(formatP256PublicKey(point));
    parts.push(challenge); parts.push(response);
  }
  return parts.join(":");
}

function parseSetMembershipProof(text) {
  if (typeof text !== "string") return null;
  var parts = text.trim().split(":");
  if (parts.length < 1 + SETMEMBER_MIN_CANDIDATES * 3 ||
      parts.length > 1 + SETMEMBER_MAX_CANDIDATES * 3 ||
      (parts.length - 1) % 3 !== 0 ||
      parts[0] !== SETMEMBER_FORMAT) return null;
  var branches = [];
  for (var i = 0; i < (parts.length - 1) / 3; i++) {
    var base = 1 + i * 3;
    var point = parseP256Point(parts[base]);
    var challenge = parseProofResponse(parts[base + 1]);
    var response = parseProofResponse(parts[base + 2]);
    if (point === null || challenge === null || response === null) {
      return null;
    }
    branches.push({ nonceCommitment: formatP256PublicKey(point),
                    challenge: challenge, response: response });
  }
  return { branches: branches };
}

/* One attempt at a proof, with all randomness drawn
   fresh inside the attempt: the false branches are
   simulated backwards, the true branch's nonce is
   committed, the hash chooses the true branch's
   challenge as whatever the simulated ones leave,
   and the true branch answers with the blinding.
   Any impossible point — a simulated branch landing
   on the identity — fails the attempt as null and
   the caller redraws, the same discipline tool 33's
   signer follows. */
function setMembershipProofAttempt(commitmentHex, candidates,
                                   statementPoints, trueIndex,
                                   blindingHex) {
  var count = candidates.length;
  var challenges = [];
  var responses = [];
  var noncePoints = [];
  var i;
  for (i = 0; i < count; i++) {
    challenges.push(null); responses.push(null); noncePoints.push(null);
  }
  var nonceHex = null;
  for (i = 0; i < count; i++) {
    if (i === trueIndex) continue;
    var simChallenge = randomProofScalar();
    var simResponse = randomProofScalar();
    if (simChallenge === null || simResponse === null) {
      return Promise.resolve(null);
    }
    var simPoint = p256PointAdd(
      p256PointMultiply(BigInt("0x" + simResponse),
        { x: P256_GX, y: P256_GY }),
      p256PointMultiply(rangeModN(-BigInt("0x" + simChallenge)),
        parseP256Point(statementPoints[i])));
    if (simPoint === null) return Promise.resolve(null);
    challenges[i] = simChallenge;
    responses[i] = simResponse;
    noncePoints[i] = formatP256PublicKey(simPoint);
  }
  nonceHex = randomProofScalar();
  if (nonceHex === null) return Promise.resolve(null);
  var trueNoncePoint = proofCommitmentForNonce(nonceHex);
  if (trueNoncePoint === null) return Promise.resolve(null);
  noncePoints[trueIndex] = trueNoncePoint;
  return setMemberChallenge(commitmentHex, candidates, noncePoints)
    .then(function (challenge) {
      if (challenge === null) return null;
      var others = P256_ZERO;
      for (var j = 0; j < count; j++) {
        if (j === trueIndex) continue;
        others = rangeModN(others + BigInt("0x" + challenges[j]));
      }
      var trueChallenge = rangeModN(BigInt("0x" + challenge) - others);
      var trueResponse = rangeModN(BigInt("0x" + nonceHex) +
        trueChallenge * BigInt("0x" + blindingHex));
      challenges[trueIndex] = p256IntToHex(trueChallenge);
      responses[trueIndex] = p256IntToHex(trueResponse);
      var branches = [];
      for (var k = 0; k < count; k++) {
        branches.push({ nonceCommitment: noncePoints[k],
                        challenge: challenges[k],
                        response: responses[k] });
      }
      return formatSetMembershipProof(branches);
    });
}

/* The prover's move: given a tool-42 commitment, its
   opening and a public candidate list, prove the
   hidden value is one of the candidates. The opening
   is checked first — a value and blinding that do
   not recompute their commitment are refused as
   null — and membership is checked before anything
   is proved: a value on no list gets null, because
   no honest proof of its membership exists. */
function makeSetMembershipProof(commitmentHex, valueText, blindingHex,
                                candidatesText) {
  var point = parseP256Point(commitmentHex);
  var value = parsePedersenValue(valueText);
  var blinding = parseProofScalar(blindingHex);
  var candidates = parseSetCandidates(candidatesText);
  if (point === null || value === null || blinding === null ||
      candidates === null) {
    return Promise.resolve(null);
  }
  var trueIndex = candidates.indexOf(value);
  if (trueIndex === -1) return Promise.resolve(null);
  var canonical = formatP256PublicKey(point);
  return pedersenCommitmentFor(value, blinding).then(function (recomputed) {
    if (recomputed === null || recomputed !== canonical) return null;
    return setMemberStatementPoints(canonical, candidates)
      .then(function (statementPoints) {
        if (statementPoints === null) return null;
        var attempt = function (triesLeft) {
          return setMembershipProofAttempt(canonical, candidates,
            statementPoints, trueIndex, blinding)
            .then(function (proof) {
              if (proof !== null) return proof;
              return triesLeft > 1 ? attempt(triesLeft - 1) : null;
            });
        };
        return attempt(4);
      });
  });
}

/* The verifier's verdict, needing no secret at all:
   recompute every shifted point from the commitment
   and the pasted list, re-hash the challenge from
   the commitment, the canonical list and the proof's
   nonce commitments, then check that the branch
   challenges sum to it and every branch balances —
   s_i×G against R_i + c_i×D_i. True when both hold;
   false — never null — when every piece is
   well-formed and one fails; null when a piece
   cannot even be parsed, when the proof's branch
   count does not match the list, or when a shifted
   point is the identity this page does not spell.
   An identity on either side of a branch balance
   counts as the identity point it is: both sides
   landing there together is a balance, one side
   alone is not. */
function verifySetMembershipProof(commitmentHex, candidatesText,
                                  proofText) {
  var point = parseP256Point(commitmentHex);
  var candidates = parseSetCandidates(candidatesText);
  var proof = parseSetMembershipProof(proofText);
  if (point === null || candidates === null || proof === null ||
      proof.branches.length !== candidates.length) {
    return Promise.resolve(null);
  }
  var canonical = formatP256PublicKey(point);
  return setMemberStatementPoints(canonical, candidates)
    .then(function (statementPoints) {
      if (statementPoints === null) return null;
      var noncePoints = proof.branches.map(function (branch) {
        return branch.nonceCommitment;
      });
      return setMemberChallenge(canonical, candidates, noncePoints)
        .then(function (challenge) {
          if (challenge === null) return null;
          var sum = P256_ZERO;
          var i;
          for (i = 0; i < proof.branches.length; i++) {
            sum = rangeModN(sum +
              BigInt("0x" + proof.branches[i].challenge));
          }
          if (sum !== BigInt("0x" + challenge)) return false;
          for (i = 0; i < proof.branches.length; i++) {
            var branch = proof.branches[i];
            var lhs = p256PointMultiply(BigInt("0x" + branch.response),
              { x: P256_GX, y: P256_GY });
            var rhs = p256PointAdd(parseP256Point(branch.nonceCommitment),
              p256PointMultiply(BigInt("0x" + branch.challenge),
                parseP256Point(statementPoints[i])));
            if (lhs === null || rhs === null) {
              if (lhs !== null || rhs !== null) return false;
              continue;
            }
            if (lhs.x !== rhs.x || lhs.y !== rhs.y) return false;
          }
          return true;
        });
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
                     blindSignatureRequest, blindSign, unblindSignature,
                     THRESH_SHARE_FORMAT, THRESH_SIGNER_FORMAT,
                     THRESH_MIN_THRESHOLD, THRESH_MAX_THRESHOLD,
                     THRESH_MIN_COUNT, THRESH_MAX_COUNT,
                     thresholdShareScalar, formatThresholdShare,
                     parseThresholdShare, splitThresholdKey,
                     thresholdLagrangeCoefficient,
                     formatThresholdCommitmentLine, parseThresholdCommitmentSet,
                     formatThresholdSignerState, parseThresholdSignerState,
                     makeThresholdCommitment, thresholdPartialResponse,
                     combineThresholdResponses,
                     DKG_COMMIT_FORMAT, DKG_SHARE_FORMAT,
                     dkgPolynomialCommitments,
                     formatDkgCommitmentLine, parseDkgCommitmentLine,
                     formatDkgShareLine, parseDkgShareLine,
                     generateDkgContribution, verifyDkgShare,
                     parseDkgCommitmentSet, finalizeDkgShares,
                     ADAPTOR_FORMAT,
                     adaptorPointForSecret, generateAdaptorSecret,
                     formatAdaptorSignature, parseAdaptorSignature,
                     createAdaptorSignature, verifyAdaptorSignature,
                     adaptAdaptorSignature, extractAdaptorSecret,
                     MUSIG_KEYAGG_PREFIX, MUSIG_SIGNER_FORMAT,
                     parseMusigKeyList, musigKeyCoefficient, aggregateMusigKey,
                     formatMusigSignerState, parseMusigSignerState,
                     makeMusigCommitment, musigPartialResponse,
                     combineMusigResponses,
                     BATCH_COEFF_PREFIX, BATCH_MIN_ENTRIES, BATCH_MAX_ENTRIES,
                     parseBatchEntries, batchCoefficient,
                     verifyBatchSignatures, findInvalidBatchEntries,
                     PEDERSEN_H_PREFIX, PEDERSEN_MAX_VALUE,
                     parsePedersenValue, pedersenGeneratorPoint,
                     pedersenCommitmentFor, makePedersenCommitment,
                     verifyPedersenOpening, pedersenCommitmentSum,
                     checkPedersenSum,
                     RANGEPROOF_FORMAT, RANGEPROOF_CHALLENGE_PREFIX,
                     RANGE_BITS, RANGE_MAX_VALUE,
                     parseRangeValue, rangeProofChallenge,
                     formatRangeProof, parseRangeProof,
                     makeRangeProof, verifyRangeProof,
                     EQPROOF_FORMAT, EQPROOF_CHALLENGE_PREFIX,
                     eqProofDifference, eqProofChallenge,
                     formatEqualityProof, parseEqualityProof,
                     makeEqualityProof, verifyEqualityProof,
                     SETMEMBER_FORMAT, SETMEMBER_CHALLENGE_PREFIX,
                     SETMEMBER_MIN_CANDIDATES, SETMEMBER_MAX_CANDIDATES,
                     parseSetCandidates, canonicalSetCandidates,
                     setMemberStatementPoint, setMemberStatementPoints,
                     setMemberChallenge, formatSetMembershipProof,
                     parseSetMembershipProof, makeSetMembershipProof,
                     verifySetMembershipProof };
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

    /* --- it takes a quorum (threshold signatures) --- */
    document.getElementById("thresh-split").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var pubOut = document.getElementById("thresh-split-pub-out");
      var sharesOut = document.getElementById("thresh-split-shares-out");
      var status = document.getElementById("thresh-split-result");
      pubOut.value = "";
      sharesOut.value = "";
      status.textContent = "Splitting the group key, locally…";
      splitThresholdKey(document.getElementById("thresh-split-priv").value,
        Number(document.getElementById("thresh-split-threshold").value),
        Number(document.getElementById("thresh-split-count").value)).then(function (split) {
        if (!split) {
          status.textContent = "That cannot be split: the group " +
            "private key must be a whole key (exactly 138 bytes), " +
            "the quorum must be 2 or 3, and the holder count must " +
            "be at least the quorum and at most 5.";
          return;
        }
        pubOut.value = split.publicKey;
        sharesOut.value = split.shares.join("\n");
        status.textContent = "Split. Publish the group public key " +
          "anywhere — it is an ordinary public key, and nothing in " +
          "it shows a split ever happened. Give each holder exactly " +
          "ONE share line, over a private channel: a share is a " +
          "secret of the same rank as a private key, and any quorum " +
          "of shares pooled together is the group key. As the dealer " +
          "you saw the whole key at this moment — that is this " +
          "teaching construction's stated limit; real threshold " +
          "protocols generate the key jointly so nobody ever does.";
      });
    });

    document.getElementById("thresh-commit").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var lineOut = document.getElementById("thresh-commitment-out");
      var stateOut = document.getElementById("thresh-state-out");
      var status = document.getElementById("thresh-commit-result");
      lineOut.value = "";
      stateOut.value = "";
      var made = makeThresholdCommitment(document.getElementById("thresh-commit-share").value);
      if (!made) {
        status.textContent = "That cannot be started: the share " +
          "must be one whole p4a-threshshare-v1 line, and this " +
          "browser must offer randomness to draw the nonce from.";
        return;
      }
      lineOut.value = made.line;
      stateOut.value = made.state;
      status.textContent = "Committed, holder " + made.index + ". " +
        "Publish the commitment line where whoever gathers the set " +
        "can reach it, and keep the state line secret and beside " +
        "it: the state holds your nonce. One commitment, one " +
        "answer — answering twice from it hands over your share, " +
        "exactly as in tools 32 and 33.";
    });

    document.getElementById("thresh-part").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var out = document.getElementById("thresh-part-out");
      var status = document.getElementById("thresh-part-result");
      out.value = "";
      status.textContent = "Answering as one holder of the quorum, locally…";
      thresholdPartialResponse(document.getElementById("thresh-part-share").value,
        document.getElementById("thresh-part-state").value,
        document.getElementById("thresh-part-message").value,
        document.getElementById("thresh-part-set").value).then(function (resp) {
        if (!resp) {
          status.textContent = "That cannot be answered: the share " +
            "and the signer state must be one whole line each, of " +
            "the same holder; the state's commitment must stand in " +
            "the commitment set under that holder's index; the set " +
            "must hold at least the share's quorum of distinct " +
            "commitment lines; and the message must not be blank " +
            "and must be at most 2,000 characters.";
          return;
        }
        out.value = resp;
        status.textContent = "Answered — partially. That number is " +
          "your nonce plus the challenge times your share weighted " +
          "by your Lagrange coefficient for exactly this set of " +
          "holders: inside a different quorum the same share would " +
          "answer differently. Send it to whoever combines; on its " +
          "own it verifies as nothing.";
      });
    });

    document.getElementById("thresh-combine").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var out = document.getElementById("thresh-combine-out");
      var status = document.getElementById("thresh-combine-result");
      out.value = "";
      var line = combineThresholdResponses(document.getElementById("thresh-combine-set").value,
        document.getElementById("thresh-combine-responses").value);
      if (!line) {
        status.textContent = "That cannot be combined: the " +
          "commitment set must be whole — distinct holder lines, " +
          "at least the quorum of them — and there must be exactly " +
          "one whole 64-hex partial answer per line in the set, " +
          "no more and no fewer.";
        return;
      }
      out.value = line;
      status.textContent = "Combined. That line is an ordinary " +
        "tool 33 signature: check it in tool 33's verify form, " +
        "against the GROUP public key and the exact message, and " +
        "it balances — signed by a quorum, under one key, with no " +
        "trace in the line of who held shares or how many it took.";
    });

    /* --- no dealer ever saw it (distributed key generation) --- */
    document.getElementById("dkg-contribute").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var commitOut = document.getElementById("dkg-commitment-out");
      var sharesOut = document.getElementById("dkg-shares-out");
      var status = document.getElementById("dkg-contribute-result");
      commitOut.value = "";
      sharesOut.value = "";
      var made = generateDkgContribution(
        Number(document.getElementById("dkg-threshold").value),
        Number(document.getElementById("dkg-count").value),
        Number(document.getElementById("dkg-dealer").value));
      if (!made) {
        status.textContent = "That contribution cannot be made: " +
          "the quorum must be 2 or 3, the holder count must be at " +
          "least the quorum and at most 5, your holder number must " +
          "be one of the holders, and this browser must offer " +
          "randomness to draw the contribution from.";
        return;
      }
      commitOut.value = made.commitment;
      sharesOut.value = made.shares.join("\n");
      status.textContent = "Contribution made, holder " + made.dealer +
        ". Broadcast the commitment line where every holder can " +
        "reach it — it is public, and it binds you to the shares " +
        "you dealt without revealing any of them. Send each share " +
        "line to exactly its own holder, privately: the line's " +
        "fourth field is the holder it belongs to, and a share is " +
        "a secret. Your contribution scalar itself was never shown " +
        "and is not stored — once every holder finalizes, no copy " +
        "of it exists anywhere, which is the point.";
    });

    document.getElementById("dkg-verify").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var status = document.getElementById("dkg-verify-result");
      var verdict = verifyDkgShare(document.getElementById("dkg-verify-commitment").value,
        document.getElementById("dkg-verify-share").value);
      if (verdict === null) {
        status.textContent = "That cannot be checked: the " +
          "commitment line and the share line must each be one " +
          "whole line, from the same dealer and for the same " +
          "quorum — a share is only ever checked against its own " +
          "dealer's commitments.";
        return;
      }
      status.textContent = verdict ?
        "Consistent. That share is exactly the share its dealer " +
          "committed to dealing you: share × G equals the dealer's " +
          "broadcast commitments weighted by your holder powers. " +
          "The dealer dealt honestly — at least to you." :
        "INCONSISTENT. That well-formed share does not match its " +
          "dealer's broadcast commitments: the dealer dealt a " +
          "different polynomial than the one they committed to. " +
          "Do not finalize with it — in a real protocol this is " +
          "the evidence a dispute round disqualifies a dealer on.";
    });

    document.getElementById("dkg-finalize").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var pubOut = document.getElementById("dkg-finalize-pub-out");
      var shareOut = document.getElementById("dkg-finalize-share-out");
      var status = document.getElementById("dkg-finalize-result");
      pubOut.value = "";
      shareOut.value = "";
      var done = finalizeDkgShares(document.getElementById("dkg-finalize-commitments").value,
        document.getElementById("dkg-finalize-shares").value);
      if (!done) {
        status.textContent = "That cannot be finalized: the " +
          "commitment set must hold one whole line per dealer — " +
          "holders 1 through the holder count, each once, one " +
          "quorum — and the share lines must be exactly one per " +
          "dealer, all addressed to you, and every one must pass " +
          "its Feldman check against its dealer's commitments. A " +
          "group does not finalize on a partial or inconsistent " +
          "round.";
        return;
      }
      pubOut.value = done.publicKey;
      shareOut.value = done.shareLine;
      status.textContent = "Finalized, holder " + done.recipient +
        ". Your share line is an ordinary tool 37 share: guard it " +
        "exactly like one, and sign with it in tool 37 against " +
        "the group public key above. The group key itself was " +
        "never computed by anyone — not by you, not by any " +
        "dealer: what exists is its public key, and one share " +
        "per holder.";
    });

    /* --- a signature that waits for a secret (adaptor signatures) --- */
    document.getElementById("adaptor-make").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var secretOut = document.getElementById("adaptor-secret-out");
      var pointOut = document.getElementById("adaptor-point-out");
      var status = document.getElementById("adaptor-make-result");
      secretOut.value = "";
      pointOut.value = "";
      var made = generateAdaptorSecret();
      if (!made) {
        status.textContent = "That secret cannot be drawn: this " +
          "browser must offer randomness to draw it from.";
        return;
      }
      secretOut.value = made.secret;
      pointOut.value = made.point;
      status.textContent = "Secret drawn. Publish the adaptor " +
        "point anywhere — it reveals nothing about the secret — " +
        "and guard the secret itself exactly like a private key: " +
        "whoever holds it can finish any signature locked to the " +
        "point, and it is stored nowhere on this page.";
    });

    document.getElementById("adaptor-create").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var out = document.getElementById("adaptor-out");
      var status = document.getElementById("adaptor-create-result");
      out.value = "";
      status.textContent = "Making the pre-signature, locally…";
      createAdaptorSignature(document.getElementById("adaptor-priv").value,
        document.getElementById("adaptor-message").value,
        document.getElementById("adaptor-point-in").value).then(function (line) {
        if (!line) {
          status.textContent = "That pre-signature cannot be made: " +
            "the signing key must be one whole 138-byte tool 17 or " +
            "tool 18 private key, the adaptor point one whole " +
            "91-byte public key, and the message between 1 and " +
            "2,000 characters.";
          return;
        }
        out.value = line;
        status.textContent = "Pre-signature made. On its own it " +
          "verifies as nothing — check it in the verify form below " +
          "against your public key, the exact message and the " +
          "adaptor point, and it balances only as a pre-signature: " +
          "exactly one number short of a signature, and that " +
          "number is the adaptor secret.";
      });
    });

    document.getElementById("adaptor-verify").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var status = document.getElementById("adaptor-verify-result");
      status.textContent = "Checking the pre-signature, locally…";
      verifyAdaptorSignature(document.getElementById("adaptor-verify-pub").value,
        document.getElementById("adaptor-verify-message").value,
        document.getElementById("adaptor-verify-point").value,
        document.getElementById("adaptor-verify-in").value).then(function (verdict) {
        if (verdict === null) {
          status.textContent = "That cannot be checked: the public " +
            "key and the adaptor point must each be one whole " +
            "91-byte public key, the message between 1 and 2,000 " +
            "characters, and the line one whole p4a-adaptor-v1 " +
            "pre-signature.";
          return;
        }
        status.textContent = verdict ?
          "Genuine. That pre-signature is exactly one number short " +
            "of a signature under that key, over that exact " +
            "message, locked to that adaptor point: whoever " +
            "reveals the secret behind the point finishes it, and " +
            "nobody else can." :
          "NOT GENUINE. That well-formed line does not balance as " +
            "a pre-signature for that key, that message and that " +
            "adaptor point — do not rely on it completing when " +
            "the secret shows.";
      });
    });

    document.getElementById("adaptor-adapt").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var out = document.getElementById("adaptor-adapt-out");
      var status = document.getElementById("adaptor-adapt-result");
      out.value = "";
      var line = adaptAdaptorSignature(document.getElementById("adaptor-adapt-in").value,
        document.getElementById("adaptor-adapt-secret").value);
      if (!line) {
        status.textContent = "That cannot be adapted: the line " +
          "must be one whole p4a-adaptor-v1 pre-signature and the " +
          "secret one whole 64-hex number.";
        return;
      }
      out.value = line;
      status.textContent = "Adapted. If that was the secret whose " +
        "point the pre-signature was locked to, this is now an " +
        "ordinary signature: check it in tool 33's verify form " +
        "against the signer's public key and the exact message. " +
        "A different secret adapts to a line that same verifier " +
        "rejects — and anyone holding the pre-signature can now " +
        "extract the secret you used from the two lines, which " +
        "is the point of the shape.";
    });

    document.getElementById("adaptor-extract").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var out = document.getElementById("adaptor-extract-out");
      var status = document.getElementById("adaptor-extract-result");
      out.value = "";
      var secret = extractAdaptorSecret(document.getElementById("adaptor-extract-pre").value,
        document.getElementById("adaptor-extract-final").value);
      if (!secret) {
        status.textContent = "Nothing can be extracted: the first " +
          "line must be one whole p4a-adaptor-v1 pre-signature, " +
          "the second one whole p4a-schnorr-v1 signature adapted " +
          "from it — the same adapted commitment in both — and " +
          "their answers must actually differ.";
        return;
      }
      out.value = secret;
      status.textContent = "Extracted. That is the adaptor secret " +
        "itself, recovered from the two lines alone: check it in " +
        "the first form of tool 39 — its point is the adaptor " +
        "point the pre-signature was locked to — and use it to " +
        "adapt any other pre-signature locked to the same point.";
    });

    /* --- many keys, one signature (aggregate signatures) --- */
    document.getElementById("musig-aggregate").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var out = document.getElementById("musig-agg-out");
      var status = document.getElementById("musig-aggregate-result");
      out.value = "";
      status.textContent = "Working…";
      aggregateMusigKey(document.getElementById("musig-keys").value).then(function (agg) {
        if (!agg) {
          status.textContent = "No aggregate key: the list must be " +
            "two to five whole 91-byte public keys, one per line, " +
            "with no key repeated.";
          return;
        }
        out.value = agg;
        status.textContent = "Aggregate key computed. It is one " +
          "ordinary public key, weighted so no late joiner can " +
          "cancel the others out of it. Everyone on the list must " +
          "sign; the finished signature is checked against this " +
          "key in tool 33's verify form.";
      });
    });

    document.getElementById("musig-commit").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var lineOut = document.getElementById("musig-commitment-out");
      var stateOut = document.getElementById("musig-state-out");
      var status = document.getElementById("musig-commit-result");
      lineOut.value = "";
      stateOut.value = "";
      var made = makeMusigCommitment(parseInt(document.getElementById("musig-position").value, 10));
      if (!made) {
        status.textContent = "No commitment drawn: the position " +
          "must be a whole number from 1 to 5 — your place in the " +
          "agreed key list.";
        return;
      }
      lineOut.value = made.line;
      stateOut.value = made.state;
      status.textContent = "Commitment drawn for position " +
        made.index + ". Publish the commitment line; keep the " +
        "state line secret — it carries the nonce, and it is " +
        "shown here once and stored nowhere.";
    });

    document.getElementById("musig-part").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var out = document.getElementById("musig-part-out");
      var status = document.getElementById("musig-part-result");
      out.value = "";
      status.textContent = "Working…";
      musigPartialResponse(document.getElementById("musig-part-priv").value,
        document.getElementById("musig-part-state").value,
        document.getElementById("musig-part-keys").value,
        document.getElementById("musig-part-message").value,
        document.getElementById("musig-part-set").value).then(function (partial) {
          if (!partial) {
            status.textContent = "No partial answer: the private " +
              "key must be the key standing at the state's position " +
              "in the list, the state must be the commitment's own, " +
              "the commitment set must be complete — one line per " +
              "position, 1 through the list's count — and the " +
              "message a whole message of at most 2,000 characters.";
            return;
          }
          out.value = partial;
          status.textContent = "Partial answer computed. Publish " +
            "the number; it signs nothing alone — the signature " +
            "exists only when every signer's partial is in.";
        });
    });

    document.getElementById("musig-combine").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var out = document.getElementById("musig-combine-out");
      var status = document.getElementById("musig-combine-result");
      out.value = "";
      var line = combineMusigResponses(document.getElementById("musig-combine-set").value,
        document.getElementById("musig-combine-responses").value);
      if (!line) {
        status.textContent = "Nothing combined: the commitment set " +
          "must be whole and the answers exactly one per commitment " +
          "line — a missing signer is no signature, and this form " +
          "will not dress a partial sum up as one.";
        return;
      }
      out.value = line;
      status.textContent = "Combined. Check the line in tool 33's " +
        "verify form against the aggregate key from the first form " +
        "and the exact message — that check, not this page, is what " +
        "says the group signed.";
    });

    /* --- check them all at once (batch verification) --- */
    document.getElementById("batch-check").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var status = document.getElementById("batch-check-result");
      status.textContent = "Working…";
      verifyBatchSignatures(document.getElementById("batch-entries").value).then(function (verdict) {
        if (verdict === null) {
          status.textContent = "Cannot judge this pile: it must be " +
            "two to six entries separated by blank lines, each a " +
            "whole 91-byte public key, a whole p4a-schnorr-v1 " +
            "signature line, then the exact message that was signed.";
          return;
        }
        status.textContent = verdict ?
          "The batch balances. Every signature in the pile checks " +
            "out, in one weighted equation — the weights are hashed " +
            "from the whole pile, so two forged entries cannot " +
            "cancel each other out of it." :
          "The batch does not balance: at least one entry in the " +
            "pile is wrong. A batch verdict cannot say which — use " +
            "the finder below to name the failing positions.";
      });
    });

    document.getElementById("batch-find").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var out = document.getElementById("batch-find-out");
      var status = document.getElementById("batch-find-result");
      out.value = "";
      status.textContent = "Working…";
      findInvalidBatchEntries(document.getElementById("batch-find-entries").value).then(function (invalid) {
        if (invalid === null) {
          status.textContent = "Cannot judge this pile: it must be " +
            "two to six entries separated by blank lines, each a " +
            "whole 91-byte public key, a whole p4a-schnorr-v1 " +
            "signature line, then the exact message that was signed.";
          return;
        }
        if (invalid.length === 0) {
          out.value = "none";
          status.textContent = "Every entry passes on its own. If " +
            "the batch above still failed over this same pile, that " +
            "is the negligible-probability case the tool text " +
            "names — re-check that both forms hold the same pile, " +
            "in the same order.";
          return;
        }
        out.value = invalid.join(", ");
        status.textContent = "These positions fail tool 33's check " +
          "on their own — a wrong message, a nudged answer, or a " +
          "signature that belongs to a different key. The rest of " +
          "the pile passed individually.";
      });
    });

    /* --- hide the amount, keep the maths (Pedersen commitments) --- */
    document.getElementById("pedersen-make").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var out = document.getElementById("pedersen-commitment-out");
      var blindOut = document.getElementById("pedersen-blinding-out");
      var status = document.getElementById("pedersen-make-result");
      out.value = "";
      blindOut.value = "";
      status.textContent = "Working…";
      makePedersenCommitment(document.getElementById("pedersen-value").value).then(function (made) {
        if (made === null) {
          status.textContent = "Nothing committed: the value must " +
            "be a whole number from 0 to 1,000,000,000,000 — no " +
            "sign, no decimals, no other characters.";
          return;
        }
        out.value = made.commitment;
        blindOut.value = made.blinding;
        status.textContent = "Committed. The commitment above is " +
          "the public half — publish it anywhere. The blinding " +
          "below is the opening's secret half: whoever holds the " +
          "value and the blinding can prove what this commitment " +
          "hides, so keep it the way you keep a private key.";
      });
    });

    document.getElementById("pedersen-verify").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var status = document.getElementById("pedersen-verify-result");
      status.textContent = "Working…";
      verifyPedersenOpening(document.getElementById("pedersen-verify-commitment").value,
        document.getElementById("pedersen-verify-value").value,
        document.getElementById("pedersen-verify-blinding").value).then(function (verdict) {
        if (verdict === null) {
          status.textContent = "Cannot judge this opening: the " +
            "commitment must be a whole 91-byte point, the value a " +
            "whole number from 0 to 1,000,000,000,000, and the " +
            "blinding a whole 64-hex scalar that is not zero.";
          return;
        }
        status.textContent = verdict ?
          "The opening checks out: this value and this blinding " +
            "recompute exactly the commitment above. The " +
            "commitment was bound to this value from the moment " +
            "it was made." :
          "The opening does not check out: this value and blinding " +
            "recompute a different point. Either the value was " +
            "changed, the blinding belongs to another commitment, " +
            "or the commitment was never made from them.";
      });
    });

    document.getElementById("pedersen-sum").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var out = document.getElementById("pedersen-sum-out");
      var status = document.getElementById("pedersen-sum-result");
      var aCommit = document.getElementById("pedersen-sum-a-commitment").value;
      var bCommit = document.getElementById("pedersen-sum-b-commitment").value;
      out.value = pedersenCommitmentSum(aCommit, bCommit) || "";
      status.textContent = "Working…";
      checkPedersenSum(aCommit,
        document.getElementById("pedersen-sum-a-value").value,
        document.getElementById("pedersen-sum-a-blinding").value,
        bCommit,
        document.getElementById("pedersen-sum-b-value").value,
        document.getElementById("pedersen-sum-b-blinding").value).then(function (verdict) {
        if (verdict === null) {
          status.textContent = "Cannot judge this sum: each side " +
            "needs a whole 91-byte commitment point, a whole value " +
            "from 0 to 1,000,000,000,000, and a whole 64-hex " +
            "blinding that is not zero.";
          return;
        }
        status.textContent = verdict ?
          "It balances. The two commitments add — as points — to " +
            "the summed commitment above, and that point opens to " +
            "exactly the two values added together under the two " +
            "blindings added together. The amounts never had to " +
            "sit next to their commitments in public for the " +
            "arithmetic to be checkable." :
          "It does not balance: the added commitments are not a " +
            "commitment to the added values under the added " +
            "blindings. A value, a blinding or a commitment on one " +
            "side does not belong with the others.";
      });
    });

    /* --- in range, and I can prove it (range proofs) --- */
    document.getElementById("range-make").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var out = document.getElementById("range-proof-out");
      var status = document.getElementById("range-make-result");
      out.value = "";
      status.textContent = "Working…";
      makeRangeProof(document.getElementById("range-commitment").value,
        document.getElementById("range-value").value,
        document.getElementById("range-blinding").value).then(function (proof) {
        if (proof === null) {
          status.textContent = "No proof made: the commitment must " +
            "be a whole 91-byte point, the value a whole number " +
            "from 0 to 255, the blinding its whole 64-hex opening — " +
            "and the value and blinding must actually open the " +
            "commitment. A value past 255 cannot be proved in " +
            "range here, however good its commitment is.";
          return;
        }
        out.value = proof;
        status.textContent = "Proved. The line above says, in a " +
          "form anyone can check with the second form: the value " +
          "inside this commitment is a whole number from 0 to " +
          "255. It does not say which number, and the blinding " +
          "stays secret — keep it the way you keep a private key.";
      });
    });

    document.getElementById("range-check").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var status = document.getElementById("range-check-result");
      status.textContent = "Working…";
      verifyRangeProof(document.getElementById("range-check-commitment").value,
        document.getElementById("range-check-proof").value).then(function (verdict) {
        if (verdict === null) {
          status.textContent = "Cannot judge this proof: the " +
            "commitment must be a whole 91-byte point and the " +
            "proof a whole p4a-rangeproof-v1 line — eight bit " +
            "commitments, each with two branch challenges and " +
            "two responses, nothing missing and nothing extra.";
          return;
        }
        status.textContent = verdict ?
          "In range, proved. The bit commitments add up — with " +
            "their powers of two — to exactly this commitment, " +
            "and every bit's two branch challenges sum to the " +
            "one challenge the whole transcript hashes to: the " +
            "hidden value is a whole number from 0 to 255, and " +
            "you learned nothing else about it." :
          "Not proved. Either the bit commitments do not add " +
            "up to this commitment — the proof belongs to a " +
            "different value or was transplanted — or a branch " +
            "challenge pair does not sum to the transcript's " +
            "challenge, which is what a nudged response, a " +
            "swapped bit or a forged branch does to a proof.";
      });
    });

    /* --- same value, twice hidden (equality proofs) --- */
    document.getElementById("eq-make").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var out = document.getElementById("eq-proof-out");
      var status = document.getElementById("eq-make-result");
      out.value = "";
      status.textContent = "Working…";
      makeEqualityProof(document.getElementById("eq-a-commitment").value,
        document.getElementById("eq-a-value").value,
        document.getElementById("eq-a-blinding").value,
        document.getElementById("eq-b-commitment").value,
        document.getElementById("eq-b-value").value,
        document.getElementById("eq-b-blinding").value).then(function (proof) {
        if (proof === null) {
          status.textContent = "No proof made: each side needs a " +
            "whole 91-byte commitment point, a whole value from 0 " +
            "to 1,000,000,000,000 and its whole 64-hex blinding — " +
            "and the two values must be the same, under two " +
            "different blindings, with each opening actually " +
            "opening its own commitment. Two different values " +
            "cannot be proved equal, and identical commitments " +
            "need no proof.";
          return;
        }
        out.value = proof;
        status.textContent = "Proved. The line above says, in a " +
          "form anyone can check with the second form: these two " +
          "commitments hide the same value. It does not say which " +
          "value, and neither blinding is in it — whoever holds " +
          "both blindings could have made it, so keep them the " +
          "way you keep private keys.";
      });
    });

    document.getElementById("eq-check").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var status = document.getElementById("eq-check-result");
      status.textContent = "Working…";
      verifyEqualityProof(document.getElementById("eq-check-a-commitment").value,
        document.getElementById("eq-check-b-commitment").value,
        document.getElementById("eq-check-proof").value).then(function (verdict) {
        if (verdict === null) {
          status.textContent = "Cannot judge this proof: the two " +
            "commitments must be whole 91-byte points — and two " +
            "different ones, since identical commitments have no " +
            "difference point to prove against — and the proof a " +
            "whole p4a-eqproof-v1 line, nothing missing and " +
            "nothing extra.";
          return;
        }
        status.textContent = verdict ?
          "Same value, proved. The response balances against " +
            "the difference of the two commitments — a point " +
            "anyone can compute from the pair alone — under the " +
            "challenge the pair and the proof hash to: the two " +
            "commitments hide the same amount, and you learned " +
            "nothing about what the amount is." :
          "Not proved. The response does not balance against " +
            "this pair's difference point under its challenge — " +
            "what a nudged response, a proof transplanted to a " +
            "pair whose values differ, or the pair pasted in the " +
            "wrong order does to a proof.";
      });
    });

    /* --- one of these, I won't say which (set-membership proofs) --- */
    document.getElementById("set-make").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var out = document.getElementById("set-proof-out");
      var status = document.getElementById("set-make-result");
      out.value = "";
      status.textContent = "Working\u2026";
      makeSetMembershipProof(document.getElementById("set-commitment").value,
        document.getElementById("set-value").value,
        document.getElementById("set-blinding").value,
        document.getElementById("set-candidates").value).then(function (proof) {
        if (proof === null) {
          status.textContent = "No proof made: the commitment must " +
            "be a whole 91-byte point, the value a whole number " +
            "from 0 to 1,000,000,000,000 with its whole 64-hex " +
            "blinding actually opening it, and the list two to " +
            "six different whole values in that range, separated " +
            "by commas — with the hidden value on the list. A " +
            "value that is not one of the candidates cannot be " +
            "proved a member, and that refusal is the membership " +
            "question answering itself.";
          return;
        }
        out.value = proof;
        status.textContent = "Proved. The line above says, in a " +
          "form anyone can check with the second form and the " +
          "same list: the value inside this commitment is one " +
          "of the candidates. It does not say which one, and the " +
          "blinding is not in it — whoever holds the opening " +
          "could have made it, so keep it the way you keep " +
          "private keys.";
      });
    });

    document.getElementById("set-check").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var status = document.getElementById("set-check-result");
      status.textContent = "Working\u2026";
      verifySetMembershipProof(document.getElementById("set-check-commitment").value,
        document.getElementById("set-check-candidates").value,
        document.getElementById("set-check-proof").value).then(function (verdict) {
        if (verdict === null) {
          status.textContent = "Cannot judge this proof: the " +
            "commitment must be a whole 91-byte point, the list " +
            "two to six different whole values separated by " +
            "commas, and the proof a whole p4a-setmember-v1 line " +
            "with one branch per candidate — nothing missing " +
            "and nothing extra.";
          return;
        }
        status.textContent = verdict ?
          "A member, proved. Every branch balances against the " +
            "point its candidate shifts this commitment to, and " +
            "the branch challenges sum to the one challenge the " +
            "commitment, the list and the proof hash to: the " +
            "hidden value is one of these candidates, and you " +
            "learned nothing about which one." :
          "Not proved. Either a branch does not balance against " +
            "its candidate's shifted point, or the branch " +
            "challenges do not sum to the transcript's challenge " +
            "— what a nudged response, branches swapped between " +
            "candidates, a different list, or a proof transplanted " +
            "to a commitment whose value is on no list does to " +
            "a proof.";
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
