"use strict";
/* Privacy4All site tests — run: node tests/test-site.js */
const fs = require("fs");
const path = require("path");
const root = path.join(__dirname, "..");
const html = fs.readFileSync(path.join(root, "index.html"), "utf8");
const readme = fs.readFileSync(path.join(root, "README.md"), "utf8");
const guide = fs.readFileSync(path.join(root, "guides", "getting-started-midnight.md"), "utf8");
const app = require(path.join(root, "app.js"));

const ADA = "addr1q8hnl6vl5a6k3rw3n5g3jtte696zcl76kfatzv7gpswa9r0dj7fma6klq55y4ffm7tf0em09udnyhuk4ah92pl5x9jpqjae44v";
let failures = 0;
function check(name, cond) {
  console.log((cond ? "PASS" : "FAIL") + " " + name);
  if (!cond) failures++;
}

/* attribution on every user-facing surface */
for (const [label, doc] of [["index.html", html], ["README", readme], ["guide", guide]]) {
  check("ADA donation address in " + label, doc.includes(ADA));
  check("@kshot9000 in " + label, doc.includes("@kshot9000"));
  check("Midnight team GitHub tag in " + label, doc.includes("@midnightntwrk"));
}
check("Midnight team X tag in index.html", html.includes("@MidnightNtwrk"));
check("Midnight team X tag in README", readme.includes("@MidnightNtwrk"));

/* document structure */
check("exactly one <h1>", (html.match(/<h1[ >]/g) || []).length === 1);
check("has <main> landmark", /<main[\s>]/.test(html));
check("all main form controls labelled", ["q", "redact-in", "night", "claim", "secret", "threshold", "snippet-select", "life-night", "life-spend", "life-txs", "commit-secret", "commit-out", "check-commitment", "check-secret", "observer-select", "viewing-select", "strength-secret", "salt-out", "merkle-entries", "merkle-entry", "split-secret", "split-count", "split-out", "join-in", "join-out", "note-secret", "note-commit-out", "spend-secret", "spend-nullifier-out", "shamir-secret", "shamir-threshold", "shamir-count", "shamir-out", "shamir-join-in", "shamir-join-out", "seal-message", "seal-password", "seal-out", "open-sealed", "open-password", "open-out", "sign-pub-out", "sign-priv-out", "sign-message", "sign-priv-in", "sign-out", "verify-pub", "verify-message", "verify-sig", "agree-pub-out", "agree-priv-out", "agree-peer-pub-out", "agree-peer-priv-out", "agree-priv-in", "agree-peer-pub", "agree-out", "agree-fingerprint-out", "agree-check-priv", "agree-check-pub", "agree-check-out", "derive-secret", "derive-purpose", "derive-salt", "derive-out", "derive-check-secret", "derive-check-purpose", "derive-check-salt", "derive-check-key", "keyseal-message", "keyseal-key", "keyseal-out", "keyopen-sealed", "keyopen-key", "keyopen-out", "authseal-message", "authseal-priv", "authseal-key", "authseal-out", "authopen-sealed", "authopen-key", "authopen-pub", "authopen-out", "ratchet-start-in", "ratchet-start-out", "ratchet-seal-state", "ratchet-seal-message", "ratchet-seal-out", "ratchet-seal-next", "ratchet-open-state", "ratchet-open-in", "ratchet-open-out", "ratchet-open-next", "heal-pub-out", "heal-priv-out", "heal-state", "heal-priv-in", "heal-peer-pub", "heal-out"].every(id => html.includes(`for="${id}"`)));
check("cache keys present", html.includes("styles.css?v=3") && html.includes("app.js?v=21"));
check("dApp permission tool present", html.includes('id="dapp-see"') && html.includes('id="dapp-result"'));
check("ZK claim simulator present", html.includes('id="zk-prover"') && html.includes('id="zk-result"'));
check("ZK simulator honestly labelled a simulation", html.includes("teaching simulation, not a cryptographic proof"));
check("snippet library present", html.includes('id="snippets"') && html.includes('id="snippet-result"'));
check("snippet library honestly labelled not production", html.includes("not production contracts"));
check("DUST lifecycle tool present", html.includes('id="dust-life"') && html.includes('id="dust-life-result"'));
check("DUST lifecycle honestly states no generation rate", html.includes("states no generation rate or time"));
check("commitment tool present", html.includes('id="commit-make"') && html.includes('id="commit-check"') && html.includes('id="commit-out"'));
check("commitment tool honestly states its limits", html.includes("brute-forced from its hash") && html.includes("not Compact's on-chain persistent hash"));
check("commitment tool honestly states real local hashing", html.includes("real SHA-256 hash computed locally"));
check("observer tool present", html.includes('id="observer"') && html.includes('id="observer-result"'));
check("observer tool honestly scoped to ledger visibility", html.includes("simplified teaching model of ledger visibility only") && html.includes("does not model network-level metadata"));
check("viewing-key tool present", html.includes('id="viewing-key"') && html.includes('id="viewing-result"'));
check("viewing-key tool honestly labelled a teaching model of scoped disclosure", html.includes("simplified teaching model of scoped disclosure in principle") && html.includes("depend on your wallet and the contract involved"));
check("viewing-key tool warns never to paste a real key", html.includes("never paste a real viewing key into a web page"));

/* flagship links */
for (const url of ["https://kshot3000.github.io/Night-Messenger-/", "https://kshot3000.github.io/PlutusShield/",
  "https://kshot3000.github.io/Grok-CIP-113/", "https://nightdream.xyz/"]) {
  check("flagship linked: " + url, html.includes(url) && readme.includes(url));
}

/* redactor */
const sample = "Mail me at kyle@example.com, call (262) 555-0148, or send to " + ADA + " — thanks";
const red = app.redactText(sample);
check("redactor masks email", !red.text.includes("kyle@example.com") && red.text.includes("[EMAIL REDACTED]"));
check("redactor masks phone", !red.text.includes("555-0148") && red.text.includes("[PHONE REDACTED]"));
check("redactor masks Cardano address", !red.text.includes(ADA) && red.text.includes("[CARDANO ADDRESS REDACTED]"));
check("redactor counts 3 items", red.total === 3 && red.counts["email address"] === 1 && red.counts["phone number"] === 1 && red.counts["Cardano address"] === 1);
check("redactor leaves clean text untouched", app.redactText("nothing private here").total === 0);
check("redactor handles non-string", app.redactText(null).total === 0 && app.redactText(undefined).text === "");
const two = app.redactText("a@example.com and b@example.org");
check("redactor masks every occurrence", two.total === 2 && !two.text.includes("@example"));

/* disclosure planner */
const plan = app.planDisclosure(["dob", "idNumber", "fullName", "txHistory"]);
check("planner has 4 items", plan.items.length === 4);
check("planner tallies modes", plan.tally.share === 1 && plan.tally.proof === 1 && plan.tally.keep === 2);
check("DOB is proof-not-reveal", app.planDisclosure(["dob"]).items[0].mode === "proof");
check("ID number is keep-private", app.planDisclosure(["idNumber"]).items[0].mode === "keep");
check("wallet balance is proof", app.planDisclosure(["walletBalance"]).items[0].mode === "proof");
check("every catalog field has a plain-language note", Object.values(app.FIELD_CATALOG).every(f => f.note.length > 30 && f.label.length > 2));
check("unknown fields counted, not crashed", app.planDisclosure(["nope"]).tally.unknown === 1);
check("empty plan is empty", app.planDisclosure([]).items.length === 0);

/* DUST capacity — exact integer maths on the 5x model */
check("0 NIGHT = 0 DUST", app.dustCapacity("0") === "0");
check("1 NIGHT = 5 DUST", app.dustCapacity("1") === "5");
check("1000 NIGHT = 5000 DUST", app.dustCapacity("1000") === "5000");
check("fractional NIGHT exact", app.dustCapacity("2.5") === "12.5");
check("smallest unit exact", app.dustCapacity("0.000001") === "0.000005");
check("7 decimals rejected", app.dustCapacity("0.0000001") === null);
check("junk rejected", app.dustCapacity("abc") === null && app.dustCapacity("") === null && app.dustCapacity("-5") === null);
check("capacity constant is 5", app.DUST_PER_NIGHT_MAX === 5);

/* dApp permission explainer */
const assess = app.assessDappPermissions(["viewAddress", "viewBalance", "viewTxHistory"]);
check("dApp checker has 3 items", assess.items.length === 3);
check("dApp checker tallies levels", assess.tally.low === 1 && assess.tally.caution === 1 && assess.tally.high === 1);
check("dApp checker overall is high when any high present", assess.overall === "high");
check("viewing an address is low", app.assessDappPermissions(["viewAddress"]).overall === "low");
check("balance view alone is caution overall", app.assessDappPermissions(["viewBalance"]).overall === "caution");
check("full tx history is high", app.assessDappPermissions(["viewTxHistory"]).items[0].level === "high");
check("blind signing is high", app.assessDappPermissions(["signArbitrary"]).items[0].level === "high");
check("viewing key is high", app.assessDappPermissions(["viewingKey"]).items[0].level === "high");
check("every permission has a plain-language note", Object.values(app.PERMISSION_CATALOG).every(p => p.note.length > 30 && p.label.length > 2));
check("every HTML permission value exists in catalog", ["viewAddress", "viewBalance", "viewTxHistory", "viewContacts", "signTransaction", "signArbitrary", "viewingKey", "offchainData"].every(v => html.includes(`value="${v}"`) && app.PERMISSION_CATALOG[v]));
check("dApp checker counts unknown, not crashes", app.assessDappPermissions(["nope"]).tally.unknown === 1);
check("dApp checker empty is none", app.assessDappPermissions([]).overall === "none" && app.assessDappPermissions(null).overall === "none");

/* ZK claim simulator — exact comparison, statement reveals no secret */
const proof = app.evaluateProof("age", "34", "18");
check("age 34 proves 18+", proof.proved === true && proof.statement === "Age is at least 18");
check("statement and revealed facts hide the secret value", !proof.statement.includes("34") && !proof.revealed.join(" ").includes("34"));
check("exact threshold meets the claim", app.evaluateProof("age", "18", "18").proved === true);
check("below threshold does not prove", app.evaluateProof("balance", "99.5", "100").proved === false);
check("fractional comparison is exact", app.evaluateProof("balance", "0.000001", "0.000001").proved === true && app.evaluateProof("balance", "100.000001", "100").proved === true);
check("threshold is normalised in the statement", app.evaluateProof("income", "5000", "4000.500000").statement === "Income is at least 4000.5");
check("membership statement names months", app.evaluateProof("membership", "14", "12").statement === "Membership length is at least 12 months");
check("every claim explains what stays hidden", Object.values(app.CLAIM_CATALOG).every(c => c.hidden.length > 30 && c.label.length > 2));
check("every HTML claim value exists in catalog", ["age", "balance", "income", "membership"].every(v => html.includes(`value="${v}"`) && app.CLAIM_CATALOG[v]));
check("proof rejects junk, negatives and 7 decimals", app.evaluateProof("age", "abc", "18") === null && app.evaluateProof("age", "-1", "18") === null && app.evaluateProof("age", "18", "0.0000001") === null && app.evaluateProof("age", "", "18") === null);
check("proof rejects unknown claim and null input", app.evaluateProof("nope", "1", "1") === null && app.evaluateProof("age", null, null) === null);
check("failed proof still hides the secret", !app.evaluateProof("balance", "12345", "99999").revealed.join(" ").includes("12345"));

/* Compact snippet library */
check("library has 5 patterns", Object.keys(app.SNIPPET_CATALOG).length === 5);
check("known snippet returns its code", app.getSnippet("commit-secret").code.includes("commitment") && app.getSnippet("commit-secret").title.includes("Commit"));
check("unknown snippet is null, not a crash", app.getSnippet("nope") === null && app.getSnippet(null) === null);
check("every snippet has code, a note, and all three split lists", Object.values(app.SNIPPET_CATALOG).every(s => s.code.length > 80 && s.note.length > 30 && s.priv.length >= 1 && s.pub.length >= 1 && s.disclosed.length >= 1));
check("every snippet code declares a ledger or a witness", Object.values(app.SNIPPET_CATALOG).every(s => s.code.includes("ledger") || s.code.includes("witness")));
check("at least 3 patterns teach disclose()", Object.values(app.SNIPPET_CATALOG).filter(s => s.code.includes("disclose(")).length >= 3);
check("every HTML snippet value exists in catalog", ["public-counter", "commit-secret", "selective-disclose", "threshold-proof", "private-vote"].every(v => html.includes(`value="${v}"`) && app.SNIPPET_CATALOG[v]));
check("search with no query returns all patterns", app.searchSnippets("").length === 5 && app.searchSnippets(null).length === 5);
check("search finds the vote pattern case-insensitively", app.searchSnippets("VOTE").includes("private-vote"));
check("search finds commitment by its disclosed hash", app.searchSnippets("hash").includes("commit-secret"));
check("search with no match is empty, not a crash", app.searchSnippets("zzz-no-such-pattern").length === 0);
check("getSnippet returns copies, not the catalog itself", (() => { const c = app.getSnippet("public-counter"); c.priv.push("tampered"); return app.getSnippet("public-counter").priv.length === 1; })());

/* DUST lifecycle explainer — exact maths on the same 5x ceiling */
const life = app.simulateDustLifecycle("100", "1", "10");
check("lifecycle capacity is the 5x ceiling", life.capacity === "500" && life.spendPerTx === "1");
check("lifecycle covers all planned txs", life.affordableTxs === 10 && life.uncoveredTxs === 0 && life.txCount === 10);
check("lifecycle spend and remainder are exact", life.totalSpent === "10" && life.remaining === "490" && life.toRegenerate === "10");
const over = app.simulateDustLifecycle("10", "20", "5");
check("lifecycle caps spending at capacity", over.capacity === "50" && over.affordableTxs === 2 && over.uncoveredTxs === 3 && over.totalSpent === "40" && over.remaining === "10");
check("lifecycle can spend the ceiling exactly", app.simulateDustLifecycle("10", "25", "2").remaining === "0");
check("lifecycle zero-cost txs are all covered", app.simulateDustLifecycle("100", "0", "5").affordableTxs === 5 && app.simulateDustLifecycle("100", "0", "5").totalSpent === "0");
check("lifecycle zero NIGHT covers nothing", app.simulateDustLifecycle("0", "1", "3").affordableTxs === 0 && app.simulateDustLifecycle("0", "1", "3").uncoveredTxs === 3);
check("lifecycle fractional amounts are exact", app.simulateDustLifecycle("2.5", "0.5", "3").totalSpent === "1.5" && app.simulateDustLifecycle("2.5", "0.5", "3").remaining === "11");
check("lifecycle rejects junk amounts", app.simulateDustLifecycle("abc", "1", "1") === null && app.simulateDustLifecycle("100", "-1", "1") === null && app.simulateDustLifecycle("100", "0.0000001", "1") === null);
check("lifecycle rejects non-whole or zero tx counts", app.simulateDustLifecycle("100", "1", "2.5") === null && app.simulateDustLifecycle("100", "1", "0") === null && app.simulateDustLifecycle("100", "1", "") === null);
check("lifecycle rejects null input", app.simulateDustLifecycle(null, null, null) === null);

/* observer explainer — ledger visibility, honest about residual leaks */
check("observer catalog has 4 scenarios", Object.keys(app.OBSERVER_CATALOG).length === 4);
check("every HTML observer value exists in catalog", ["public-transfer", "shielded-transfer", "disclosed-claim", "shielded-contract"].every(v => html.includes(`value="${v}"`) && app.OBSERVER_CATALOG[v]));
check("unknown observer scenario is null, not a crash", app.getObserverView("nope") === null && app.getObserverView(null) === null);
check("every scenario has a note and all three lists", Object.values(app.OBSERVER_CATALOG).every(s => s.note.length > 30 && s.sees.length >= 2 && s.cannot.length >= 2 && s.leaks.length >= 1));
check("public transfer observer sees the exact amount", app.getObserverView("public-transfer").sees.join(" ").includes("exact amount"));
check("shielded transfer observer does NOT see the exact amount", !app.getObserverView("shielded-transfer").sees.join(" ").includes("exact amount") && app.getObserverView("shielded-transfer").cannot.join(" ").includes("exact amount"));
check("disclosed claim reveals the claim but not the birth date", app.getObserverView("disclosed-claim").sees.join(" ").includes("over 18") && app.getObserverView("disclosed-claim").cannot.join(" ").includes("date of birth"));
check("shielded contract keeps witness values off the ledger view", app.getObserverView("shielded-contract").cannot.join(" ").includes("witness"));
check("every scenario names at least one residual leak", Object.values(app.OBSERVER_CATALOG).every(s => s.leaks.every(l => l.length > 20)));
check("getObserverView returns copies, not the catalog itself", (() => { const v = app.getObserverView("shielded-transfer"); v.sees.push("tampered"); return app.getObserverView("shielded-transfer").sees.length === 2; })());

/* viewing-key scope simulator — scoped disclosure, read-only at every scope */
check("viewing catalog has 4 scopes", Object.keys(app.VIEWING_CATALOG).length === 4);
check("every HTML viewing value exists in catalog", ["single-transaction", "single-counterparty", "time-window", "full-history"].every(v => html.includes(`value="${v}"`) && app.VIEWING_CATALOG[v]));
check("unknown viewing scope is null, not a crash", app.getViewingView("nope") === null && app.getViewingView(null) === null);
check("every scope has a note and all three lists", Object.values(app.VIEWING_CATALOG).every(s => s.note.length > 30 && s.sees.length >= 2 && s.cannot.length >= 2 && s.risks.length >= 1));
check("every scope names at least one substantive risk", Object.values(app.VIEWING_CATALOG).every(s => s.risks.every(r => r.length > 20)));
check("single transaction does NOT expose other transactions", app.getViewingView("single-transaction").cannot.join(" ").includes("Your other transactions") && !app.getViewingView("single-transaction").sees.join(" ").includes("full"));
check("time window excludes transactions outside the window", app.getViewingView("time-window").cannot.join(" ").includes("before or after the window"));
check("single counterparty excludes other counterparties", app.getViewingView("single-counterparty").cannot.join(" ").includes("any other counterparty"));
check("full history sees the complete picture", app.getViewingView("full-history").sees.join(" ").includes("complete financial picture"));
check("viewing never grants spending at any scope", Object.values(app.VIEWING_CATALOG).every(s => (s.sees.join(" ") + s.cannot.join(" ")).toLowerCase().includes("spend")));
check("every scope warns a disclosure cannot be un-seen or can be kept", Object.values(app.VIEWING_CATALOG).every(s => s.risks.join(" ").includes("keep") || s.risks.join(" ").includes("un-seen")));
check("getViewingView returns copies, not the catalog itself", (() => { const v = app.getViewingView("single-transaction"); v.sees.push("tampered"); return app.getViewingView("single-transaction").sees.length === 2; })());

check("strength tool present", html.includes('id="secret-strength"') && html.includes('id="strength-result"') && html.includes('id="salt-out"'));
check("strength tool honestly labelled a rough teaching estimate", html.includes("rough teaching estimate, not a security audit") && html.includes("human-chosen secrets are far more predictable"));
check("strength tool labels its guessing rate an assumption", html.includes("labelled assumption"));

/* secret strength + salt — best-case entropy model, real local randomness */
check("strength of 'abc' is pool 26, 14.1 bits", app.analyzeSecret("abc").pool === 26 && app.analyzeSecret("abc").entropyBits === 14.1 && app.analyzeSecret("abc").verdict === "very weak");
check("strength detects all four classes", (() => { const a = app.analyzeSecret("aA1!"); return a.pool === 95 && a.classes.lower && a.classes.upper && a.classes.digit && a.classes.symbol; })());
check("digits-only pool is 10", app.analyzeSecret("1234").pool === 10 && app.analyzeSecret("1234").entropyBits === 13.3);
check("long passphrase reaches excellent on the model", app.analyzeSecret("correct horse battery staple").entropyBits === 164.7 && app.analyzeSecret("correct horse battery staple").verdict === "excellent");
check("strength rejects empty and non-string", app.analyzeSecret("") === null && app.analyzeSecret(null) === null && app.analyzeSecret(42) === null);
check("guessing rate constant is the labelled 10 billion", app.GUESSES_PER_SECOND === 10000000000);
check("crack seconds use half the search space", Math.abs(app.estimateCrackSeconds("ab") - Math.pow(2, 8.4) / 10000000000) < 1e-9);
check("crack seconds reject junk", app.estimateCrackSeconds("") === null && app.estimateCrackSeconds(null) === null);
check("duration under a second", app.formatApproxDuration(0.2) === "less than a second");
check("duration seconds and minutes", app.formatApproxDuration(45) === "about 45 seconds" && app.formatApproxDuration(90) === "about 2 minutes");
check("duration hours, days and years", app.formatApproxDuration(5400) === "about 2 hours" && app.formatApproxDuration(86400 * 3) === "about 3 days" && app.formatApproxDuration(86400 * 365.25 * 5) === "about 5 years");
check("duration huge years go scientific", app.formatApproxDuration(86400 * 365.25 * 3.17e12).includes("×10^") && app.formatApproxDuration(86400 * 365.25 * 3.17e12).includes("years"));
check("duration infinite and invalid", app.formatApproxDuration(Infinity).includes("age of the universe") && app.formatApproxDuration(-1) === null && app.formatApproxDuration("x") === null);
check("salt is 32 lowercase hex chars by default", /^[0-9a-f]{32}$/.test(app.generateSaltHex()));
check("salt honours byte count", app.generateSaltHex(8).length === 16 && app.generateSaltHex(64).length === 128);
check("two salts differ", app.generateSaltHex() !== app.generateSaltHex());
check("salt rejects bad byte counts", app.generateSaltHex(0) === null && app.generateSaltHex(7) === null && app.generateSaltHex(65) === null && app.generateSaltHex(2.5) === null && app.generateSaltHex("16") === null);
check("salted secret joins with a pipe and lowercases the salt", app.saltedSecret("my bid is 250", "AB12CD34EF56AB78CD90EF12AB34CD56") === "my bid is 250|ab12cd34ef56ab78cd90ef12ab34cd56");
check("salted secret rejects bad salt and empty secret", app.saltedSecret("x", "xyz") === null && app.saltedSecret("x", "abc") === null && app.saltedSecret("", "ab12cd34ef56ab78") === null && app.saltedSecret(null, null) === null);

check("merkle tool present", html.includes('id="merkle"') && html.includes('id="merkle-result"') && html.includes('id="merkle-entries"') && html.includes('id="merkle-entry"'));
check("merkle tool honestly labelled not zero-knowledge", html.includes("a Merkle proof is <em>not</em> zero-knowledge") && html.includes("teaching format, not a specific chain's tree format"));
check("merkle tool states duplicates are rejected", html.includes("duplicates rejected"));

check("secret-split tool present", html.includes('id="secret-split"') && html.includes('id="split-make"') && html.includes('id="split-join"') && html.includes('id="split-out"') && html.includes('id="join-out"'));
check("secret-split tool honestly labelled all-of-n, not Shamir", html.includes("losing one share loses the secret forever") && html.includes("threshold (k-of-n) sharing such as Shamir's") && html.includes("not implemented by this tool"));
check("secret-split tool honestly states length leaks", html.includes("a share's length leaks the secret's length"));
check("secret-split tool warns never to paste a real seed phrase", html.includes("never paste a real seed phrase"));
check("note-nullifier tool present", html.includes('id="note-nullifier"') && html.includes('id="note-create"') && html.includes('id="note-spend"') && html.includes('id="note-commit-out"') && html.includes('id="spend-nullifier-out"') && html.includes('id="note-ledger-status"'));
check("note-nullifier tool honestly labelled a simplified teaching model, not a real note", html.includes("simplified teaching model of the note-and-nullifier idea") && html.includes("not how a real Midnight note is constructed"));
check("note-nullifier tool honestly states the dictionary-check and retroactive-link limits", html.includes("dictionary-checked against both hashes") && html.includes("become linkable after the fact"));
check("note-nullifier tool honestly states a spend event still leaks", html.includes("a nullifier may appear only once, ever"));
check("shamir tool present", html.includes('id="shamir-split"') && html.includes('id="shamir-make"') && html.includes('id="shamir-join"') && html.includes('id="shamir-out"') && html.includes('id="shamir-join-out"'));
check("shamir tool honestly labelled a teaching implementation, not audited", html.includes("teaching implementation, not an audited library") && html.includes("computed locally for real"));
check("shamir tool honestly states there is no checksum, so a wrong share rebuilds silently wrong", html.includes("no checksum") && html.includes("rebuilds a wrong secret silently"));
check("shamir tool states fewer than k shares reveal nothing", html.includes("k−1 shares are consistent with every possible secret"));
check("shamir tool states a share's length leaks the secret's length", html.includes("a share's length leaks the secret's length"));
check("tool 13 now points at tool 15 for Shamir", html.includes("not implemented by this tool (tool 15 below implements it)"));
check("sealed-message tool present", html.includes('id="sealed-message"') && html.includes('id="seal-make"') && html.includes('id="seal-open"') && html.includes('id="seal-out"') && html.includes('id="open-out"'));
check("sealed-message tool honestly labelled a teaching implementation, not audited", html.includes("teaching implementation, not an audited encryption product") && html.includes("encrypted for real, locally"));
check("sealed-message tool honestly states password is its safety and length leaks", html.includes("its safety is exactly your password's safety") && html.includes("length reveals the message's approximate length"));
check("sealed-message tool states GCM authentication fails rather than gibberish", html.includes("fails to open instead of returning gibberish"));
check("sealed-message tool states PBKDF2 parameters plainly", html.includes("PBKDF2 (210,000 rounds, a fresh random salt per seal)"));
check("sealed constants are the labelled values", app.SEAL_FORMAT === "p4a-sealed-v1" && app.SEAL_ITERATIONS === 210000 && app.SEAL_MAX_MESSAGE_CHARS === 2000);
check("signed-message tool present", html.includes('id="signed-message"') && html.includes('id="sign-keys"') && html.includes('id="sign-do"') && html.includes('id="sign-verify"') && html.includes('id="sign-out"') && html.includes('id="verify-pub"'));
check("signed-message tool honestly labelled a teaching implementation, not an audited wallet", html.includes("teaching implementation, not an audited wallet") && html.includes("signs with ECDSA over SHA-256"));
check("signed-message tool honestly states a signature proves the key, not a name or a time", html.includes("does not prove a legal name or real-world identity") && html.includes("does not prove when the signing happened"));
check("signed-message tool honestly states signing does not hide the message and the private key is the identity", html.includes("signing does not hide it") && html.includes("anyone holding it can sign as you"));
check("signed-message tool states the P-256 vs secp256k1 curve distinction plainly", html.includes("Bitcoin and Ethereum use its sibling curve secp256k1, which Web Crypto does not offer"));
check("signing constants are the labelled values", app.SIGN_FORMAT === "p4a-sig-v1" && app.SIGN_MAX_MESSAGE_CHARS === 2000 && app.SIGN_PUBLIC_KEY_BYTES === 91 && app.SIGN_PRIVATE_KEY_BYTES === 138 && app.SIGN_SIGNATURE_BYTES === 64);
check("key-agreement tool present", html.includes('id="key-agreement"') && html.includes('id="agree-keys"') && html.includes('id="agree-peer"') && html.includes('id="agree-do"') && html.includes('id="agree-check"') && html.includes('id="agree-out"') && html.includes('id="agree-fingerprint-out"'));
check("key-agreement tool honestly labelled a teaching implementation, not an audited messaging app", html.includes("teaching implementation, not an audited messaging app") && html.includes("real ECDH on the P-256 curve, computed locally"));
check("key-agreement tool honestly states the secret is never exchanged and public keys are the only things exchanged", html.includes("that secret is never exchanged") && html.includes("the public keys are the only things exchanged"));
check("key-agreement tool honestly states the raw secret is never used directly and agreement does not prove who the other key belongs to", html.includes("never use the raw shared secret directly as a key") && html.includes("does not prove who the other public key belongs to") && html.includes("man-in-the-middle"));
check("key-agreement tool states fingerprints are compared, never the secret itself", html.includes("compare a fingerprint of the secret, never the secret itself"));
check("agreement constants are the labelled values", app.AGREE_PUBLIC_KEY_BYTES === 91 && app.AGREE_PRIVATE_KEY_BYTES === 138 && app.AGREE_SHARED_SECRET_BYTES === 32 && app.AGREE_FINGERPRINT_PREFIX === "p4a-ecdh-fingerprint-v1");
check("key-derivation tool present", html.includes('id="key-derivation"') && html.includes('id="derive-do"') && html.includes('id="derive-check"') && html.includes('id="derive-out"') && html.includes('id="derive-purpose"') && html.includes('id="derive-check-key"'));
check("key-derivation tool honestly labelled a teaching implementation, not audited, running real HKDF", html.includes("teaching implementation, not an audited key-management product") && html.includes("HKDF (RFC 5869) over SHA-256"));
check("key-derivation tool honestly states one secret, many keys, never the secret itself as a key", html.includes("one secret, many keys") && html.includes("never the secret itself as a key") && html.includes("a different purpose means a different key"));
check("key-derivation tool honestly states the salt is not a secret and both sides must match purpose and salt", html.includes("The salt is not a secret") && html.includes("both sides must pick the same purpose and the same salt"));
check("key-derivation tool honestly states derivation does not strengthen a weak input", html.includes("derivation does not strengthen a weak input") && html.includes("already high-entropy key material") && html.includes("no password stretching here"));
check("key-sealed tool present", html.includes('id="key-sealed-message"') && html.includes('id="keyseal-make"') && html.includes('id="keyseal-open"') && html.includes('id="keyseal-out"') && html.includes('id="keyopen-out"'));
check("key-sealed tool honestly labelled a teaching implementation, not an audited messaging app", html.includes("teaching implementation, not an audited messaging app") && html.includes("real messengers add ratcheting"));
check("key-sealed tool honestly states it uses the derived key directly, no password or salt", html.includes("uses the derived key directly") && html.includes("no password, no stretching and no salt") && html.includes("carries only a fresh random IV"));
check("key-sealed tool honestly states a wrong key fails outright and the key is the whole secret", html.includes("a wrong key fails outright") && html.includes("The key itself is the whole secret") && html.includes("no password fallback"));
check("key-sealed README entry present", readme.includes("Use the key — lock a message with the key you both derived") && readme.includes("p4a-keysealed-v1"));
check("auth-sealed tool present", html.includes('id="auth-sealed-message"') && html.includes('id="authseal-make"') && html.includes('id="authseal-open"') && html.includes('id="authseal-out"') && html.includes('id="authopen-out"'));
check("auth-sealed tool honestly labelled a teaching implementation, not an audited messaging app", html.includes("teaching implementation, not an audited messaging app") && html.includes("the signature goes inside the seal"));
check("auth-sealed tool honestly states the seal proves the key, not the person", html.includes("AES-GCM proves the key, not the person") && html.includes("Anyone who holds the session key can seal a message in anyone's name"));
check("auth-sealed tool honestly states private is not the same as from them", html.includes("private is not the same as from them") && html.includes("The signature proves the signing key, not a legal name"));
check("auth-sealed tool warns never to paste a real private key", html.includes("Never paste a real wallet's private key into any web page"));
check("auth-sealed README entry present", readme.includes("Know it's really from them — sign it, then seal it") && readme.includes("p4a-authsealed-v1") && readme.includes("p4a-signed-v1"));
check("ratchet tool present", html.includes('id="ratchet-message"') && html.includes('id="ratchet-start"') && html.includes('id="ratchet-seal"') && html.includes('id="ratchet-open"') && html.includes('id="ratchet-seal-out"') && html.includes('id="ratchet-open-out"'));
check("ratchet tool honestly labelled a teaching implementation, not an audited messaging app", html.includes("teaching implementation, not an audited messaging app") && html.includes("in its simplest symmetric form"));
check("ratchet tool honestly states one fresh key per message and no way back to an earlier key", html.includes("one fresh key per message") && html.includes("no way to recompute an earlier message key"));
check("ratchet tool honestly states a leaked current state opens everything after it and order is strict", html.includes("a leaked current state opens every message after it") && html.includes("messages open strictly in order"));
check("ratchet tool warns never to paste a real session key", html.includes("Never paste a real wallet key or a production session key into any web page"));
check("ratchet README entry present", readme.includes("One key per message — the ratchet") && readme.includes("p4a-chain-v1"));
check("heal tool present", html.includes('id="chain-heal-tool"') && html.includes('id="heal-keys"') && html.includes('id="chain-heal"') && html.includes('id="heal-out"'));
check("heal tool honestly labelled a teaching implementation, not an audited messaging app", html.includes("teaching implementation, not an audited messaging app") && html.includes("a simplified version of the second, asymmetric ratchet"));
check("heal tool honestly states a leaked-state holder cannot follow and healing protects only what comes after", html.includes("someone holding only the leaked state cannot follow") && html.includes("healing protects only what comes after it"));
check("heal tool honestly states both sides must heal from exactly the same current state", html.includes("both sides must heal from exactly the same current state"));
check("heal README entry present", readme.includes("Heal the chain — a fresh agreement restarts") && readme.includes("privacy4all-heal-v1"));
check("derivation constants are the labelled values", app.DERIVE_KEY_BYTES === 32 && app.DERIVE_SALT_BYTES === 16 && app.DERIVE_SECRET_MIN_BYTES === 16 && app.DERIVE_SECRET_MAX_BYTES === 64 && Object.keys(app.DERIVE_PURPOSE_CATALOG).length === 3 && app.DERIVE_PURPOSE_CATALOG.messaging.info === "privacy4all-hkdf-v1 messaging");

/* XOR secret sharing — real local sharing, complete sets only */
const split3 = app.splitSecret("the cake is in the blue locker", 3);
check("split returns the requested share count", split3 !== null && split3.count === 3 && split3.shares.length === 3);
check("every share carries the versioned format", split3.shares.every(s => /^p4a-share-v1:3:[123]:[0-9a-f]+$/.test(s)));
check("share hex is exactly the secret's byte length", split3.shares.every(s => s.split(":")[3].length === 2 * "the cake is in the blue locker".length));
check("no share contains the secret in plain text", !split3.shares.join(" ").includes("blue locker"));
check("all shares differ from each other", new Set(split3.shares).size === 3);
check("complete set rebuilds the secret exactly", app.combineShares(split3.shares) === "the cake is in the blue locker");
check("rebuild works from one pasted block, blank lines and padding tolerated", app.combineShares("\n  " + split3.shares.join("  \n") + "\n") === "the cake is in the blue locker");
check("share order does not matter", app.combineShares([split3.shares[2], split3.shares[0], split3.shares[1]]) === "the cake is in the blue locker");
check("exact secret is preserved, spaces included", (() => { const s = app.splitSecret(" pad me ", 2); return app.combineShares(s.shares) === " pad me "; })());
check("unicode secret round-trips exactly", (() => { const s = app.splitSecret("sécret — code 42", 4); return s.shares.length === 4 && app.combineShares(s.shares) === "sécret — code 42"; })());
check("two-share minimum and eight-share maximum round-trip", (() => { const a = app.splitSecret("tiny", 2); const b = app.splitSecret("tiny", 8); return app.combineShares(a.shares) === "tiny" && app.combineShares(b.shares) === "tiny"; })());
check("one share alone rebuilds nothing", app.combineShares([split3.shares[0]]) === null);
check("a missing share rebuilds nothing", app.combineShares(split3.shares.slice(0, 2)) === null);
check("a duplicated share is not a set", app.combineShares([split3.shares[0], split3.shares[0], split3.shares[1]]) === null);
check("an extra share rebuilds nothing", app.combineShares(split3.shares.concat(split3.shares[0])) === null);
check("shares from two splits do not mix", (() => { const other = app.splitSecret("the cake is in the blue locker", 3); return app.combineShares([split3.shares[0], split3.shares[1], other.shares[2]]) !== "the cake is in the blue locker"; })());
check("a tampered share does not rebuild the secret", (() => { const bad = split3.shares.slice(); const parts = bad[1].split(":"); parts[3] = (parts[3][0] === "0" ? "1" : "0") + parts[3].slice(1); bad[1] = parts.join(":"); const out = app.combineShares(bad); return out !== "the cake is in the blue locker"; })());
check("mismatched share lengths are rejected", (() => { const short = app.splitSecret("hi", 3); return app.combineShares([split3.shares[0], split3.shares[1], short.shares[2]]) === null; })());
check("combine rejects junk and empty input", app.combineShares("") === null && app.combineShares([]) === null && app.combineShares(["hello"]) === null && app.combineShares(null) === null && app.combineShares(42) === null);
check("split rejects bad counts", app.splitSecret("x", 1) === null && app.splitSecret("x", 9) === null && app.splitSecret("x", 2.5) === null && app.splitSecret("x", "3") === null && app.splitSecret("x", null) === null);
check("split rejects empty, blank, non-string and over-long secrets", app.splitSecret("", 3) === null && app.splitSecret("   ", 3) === null && app.splitSecret(null, 3) === null && app.splitSecret(42, 3) === null && app.splitSecret("x".repeat(app.SHARE_MAX_SECRET_CHARS + 1), 3) === null);
check("share constants are the labelled bounds", app.SHARE_MIN_COUNT === 2 && app.SHARE_MAX_COUNT === 8 && app.SHARE_FORMAT === "p4a-share-v1");
check("parseShare reads a valid share", (() => { const p = app.parseShare(split3.shares[1]); return p !== null && p.total === 3 && p.index === 2 && p.bytes.length === "the cake is in the blue locker".length; })());
check("parseShare rejects junk, bad index and odd hex", app.parseShare("p4a-share-v1:3:9:abcd") === null && app.parseShare("p4a-share-v1:3:1:abc") === null && app.parseShare("hello") === null && app.parseShare(null) === null);

/* Shamir k-of-n sharing — real GF(256) threshold sharing */
check("gf(256) multiplication known values", app.gfMul(0, 0x53) === 0 && app.gfMul(1, 0x53) === 0x53 && app.gfMul(2, 2) === 4 && app.gfMul(2, 3) === 6 && app.gfMul(3, 3) === 5 && app.gfMul(0x57, 0x83) === 0xc1);
check("gf(256) division inverts multiplication and rejects division by zero", app.gfDiv(app.gfMul(0x57, 0x83), 0x83) === 0x57 && app.gfDiv(0, 7) === 0 && app.gfDiv(5, 0) === null);
check("shamir known-answer vector: 'A' under y = 0x41 + 2x rebuilds from any two points", app.combineThresholdShares(["p4a-shamir-v1:2:3:1:43", "p4a-shamir-v1:2:3:2:45"]) === "A" && app.combineThresholdShares(["p4a-shamir-v1:2:3:1:43", "p4a-shamir-v1:2:3:3:47"]) === "A" && app.combineThresholdShares(["p4a-shamir-v1:2:3:2:45", "p4a-shamir-v1:2:3:3:47"]) === "A" && app.combineThresholdShares(["p4a-shamir-v1:2:3:1:43", "p4a-shamir-v1:2:3:2:45", "p4a-shamir-v1:2:3:3:47"]) === "A");
const sham23 = app.splitThresholdSecret("the cake is in the blue locker", 2, 3);
check("shamir split returns the requested shares and threshold", sham23 !== null && sham23.threshold === 2 && sham23.count === 3 && sham23.shares.length === 3);
check("every shamir share carries the versioned format", sham23.shares.every(s => /^p4a-shamir-v1:2:3:[123]:[0-9a-f]+$/.test(s)));
check("shamir share hex is exactly the secret's byte length", sham23.shares.every(s => s.split(":")[4].length === 2 * "the cake is in the blue locker".length));
check("no shamir share contains the secret in plain text", !sham23.shares.join(" ").includes("blue locker"));
check("all shamir shares differ from each other", new Set(sham23.shares).size === 3);
check("any two of three shamir shares rebuild the secret", app.combineThresholdShares([sham23.shares[0], sham23.shares[1]]) === "the cake is in the blue locker" && app.combineThresholdShares([sham23.shares[0], sham23.shares[2]]) === "the cake is in the blue locker" && app.combineThresholdShares([sham23.shares[1], sham23.shares[2]]) === "the cake is in the blue locker");
check("all three shamir shares also rebuild (more than k)", app.combineThresholdShares(sham23.shares) === "the cake is in the blue locker");
check("shamir share order does not matter", app.combineThresholdShares([sham23.shares[2], sham23.shares[0]]) === "the cake is in the blue locker");
check("shamir rebuild works from one pasted block, blank lines and padding tolerated", app.combineThresholdShares("\n  " + sham23.shares.slice(0, 2).join("  \n") + "\n") === "the cake is in the blue locker");
check("one shamir share alone rebuilds nothing (below threshold)", app.combineThresholdShares([sham23.shares[0]]) === null);
const sham35 = app.splitThresholdSecret("sécret — code 42", 3, 5);
check("unicode secret round-trips from any three of five", sham35.shares.length === 5 && app.combineThresholdShares([sham35.shares[4], sham35.shares[1], sham35.shares[3]]) === "sécret — code 42" && app.combineThresholdShares(sham35.shares) === "sécret — code 42");
check("two of a 3-of-5 split rebuild nothing", app.combineThresholdShares(sham35.shares.slice(0, 2)) === null);
check("exact secret is preserved by shamir, spaces included", (() => { const s = app.splitThresholdSecret(" pad me ", 2, 2); return app.combineThresholdShares(s.shares) === " pad me "; })());
check("maximum bounds round-trip (8-of-8 and 2-of-8)", (() => { const a = app.splitThresholdSecret("tiny", 8, 8); const b = app.splitThresholdSecret("tiny", 2, 8); return app.combineThresholdShares(a.shares) === "tiny" && app.combineThresholdShares(b.shares.slice(0, 2)) === "tiny" && app.combineThresholdShares(b.shares.slice(0, 7)) === "tiny"; })());
check("a duplicated shamir share is not a set", app.combineThresholdShares([sham23.shares[0], sham23.shares[0]]) === null);
check("more shares than the split made are rejected", app.combineThresholdShares(sham23.shares.concat(sham23.shares[0])) === null);
check("shares from two shamir splits do not rebuild the secret", (() => { const other = app.splitThresholdSecret("the cake is in the blue locker", 2, 3); const out = app.combineThresholdShares([sham23.shares[0], other.shares[1]]); return out !== "the cake is in the blue locker"; })());
check("mixed thresholds do not combine", (() => { const t3 = app.splitThresholdSecret("the cake is in the blue locker", 3, 3); return app.combineThresholdShares([sham23.shares[0], t3.shares[1], t3.shares[2]]) === null; })());
check("mismatched shamir share lengths are rejected", (() => { const short = app.splitThresholdSecret("hi", 2, 3); return app.combineThresholdShares([sham23.shares[0], short.shares[1]]) === null; })());
check("a tampered shamir share does not rebuild the secret (no checksum — a wrong result, not an error)", (() => { const bad = sham23.shares.slice(0, 2); const parts = bad[1].split(":"); parts[4] = (parts[4][0] === "0" ? "1" : "0") + parts[4].slice(1); bad[1] = parts.join(":"); const out = app.combineThresholdShares(bad); return out !== "the cake is in the blue locker"; })());
check("shamir combine rejects junk and empty input", app.combineThresholdShares("") === null && app.combineThresholdShares([]) === null && app.combineThresholdShares(["hello"]) === null && app.combineThresholdShares(null) === null && app.combineThresholdShares(42) === null);
check("shamir split rejects bad thresholds and counts", app.splitThresholdSecret("x", 1, 3) === null && app.splitThresholdSecret("x", 3, 2) === null && app.splitThresholdSecret("x", 2, 9) === null && app.splitThresholdSecret("x", 9, 9) === null && app.splitThresholdSecret("x", 2.5, 3) === null && app.splitThresholdSecret("x", "2", 3) === null && app.splitThresholdSecret("x", 2, "3") === null && app.splitThresholdSecret("x", null, null) === null);
check("shamir split rejects empty, blank, non-string and over-long secrets", app.splitThresholdSecret("", 2, 3) === null && app.splitThresholdSecret("   ", 2, 3) === null && app.splitThresholdSecret(null, 2, 3) === null && app.splitThresholdSecret(42, 2, 3) === null && app.splitThresholdSecret("x".repeat(app.SHARE_MAX_SECRET_CHARS + 1), 2, 3) === null);
check("shamir constants are the labelled bounds", app.SHAMIR_MIN_THRESHOLD === 2 && app.SHAMIR_MAX_COUNT === 8 && app.SHAMIR_FORMAT === "p4a-shamir-v1");
check("parseShamirShare reads a valid share", (() => { const p = app.parseShamirShare(sham23.shares[1]); return p !== null && p.threshold === 2 && p.count === 3 && p.index === 2 && p.bytes.length === "the cake is in the blue locker".length; })());
check("parseShamirShare rejects junk, bad index, threshold above count and odd hex", app.parseShamirShare("p4a-shamir-v1:2:3:9:abcd") === null && app.parseShamirShare("p4a-shamir-v1:3:2:1:abcd") === null && app.parseShamirShare("p4a-shamir-v1:2:3:1:abc") === null && app.parseShamirShare("p4a-share-v1:3:1:abcd") === null && app.parseShamirShare("hello") === null && app.parseShamirShare(null) === null);

/* Merkle entry parsing — sync validation before any hashing */
check("merkle parse splits, trims and skips blank lines", JSON.stringify(app.parseMerkleEntries(" alice \n\nbob\r\ncarol ")) === JSON.stringify(["alice", "bob", "carol"]));
check("merkle parse rejects duplicates", app.parseMerkleEntries("alice\nalice") === null && app.parseMerkleEntries("alice\n alice ") === null);
check("merkle parse rejects empty and non-string", app.parseMerkleEntries("") === null && app.parseMerkleEntries("  \n \n") === null && app.parseMerkleEntries(null) === null && app.parseMerkleEntries(42) === null);
check("merkle parse rejects over the entry cap", app.parseMerkleEntries(Array.from({ length: app.MERKLE_MAX_ENTRIES + 1 }, (_, i) => "e" + i).join("\n")) === null);
check("merkle parse accepts exactly the cap", app.parseMerkleEntries(Array.from({ length: app.MERKLE_MAX_ENTRIES }, (_, i) => "e" + i).join("\n")).length === app.MERKLE_MAX_ENTRIES);
check("merkle normalize rejects non-string entries", app.normalizeMerkleEntries(["alice", 42]) === null && app.normalizeMerkleEntries("alice") === null && app.normalizeMerkleEntries([]) === null);

/* hash commitments — real SHA-256 via Web Crypto (async) */
check("commitment message is versioned and exact", app.commitmentMessage("my bid is 250") === app.COMMIT_PREFIX + "\nmy bid is 250");
check("commitment message keeps the secret exactly (no trim)", app.commitmentMessage(" pad ") === app.COMMIT_PREFIX + "\n pad ");
check("commitment message rejects empty, blank and non-string", app.commitmentMessage("") === null && app.commitmentMessage("   ") === null && app.commitmentMessage(null) === null && app.commitmentMessage(42) === null);

(async () => {
  check("sha256 of empty string matches the published vector", await app.sha256Hex("") === "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  check("sha256 of 'abc' matches the published vector", await app.sha256Hex("abc") === "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  check("sha256 of the pangram matches the published vector", await app.sha256Hex("The quick brown fox jumps over the lazy dog") === "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592");
  check("sha256 rejects non-string", await app.sha256Hex(null) === null);
  const c1 = await app.makeCommitment("the bridge opens on Friday");
  check("commitment is 64 lowercase hex chars", /^[0-9a-f]{64}$/.test(c1));
  check("commitment is deterministic", await app.makeCommitment("the bridge opens on Friday") === c1);
  check("different secrets give different commitments", await app.makeCommitment("the bridge opens on Saturday") !== c1);
  check("commitment never contains the secret", !c1.includes("bridge"));
  check("commitment of empty secret is null", await app.makeCommitment("") === null && await app.makeCommitment("  ") === null);
  check("reveal of the exact secret verifies", await app.verifyCommitment(c1, "the bridge opens on Friday") === true);
  check("verify tolerates uppercase and padded commitment", await app.verifyCommitment("  " + c1.toUpperCase() + " ", "the bridge opens on Friday") === true);
  check("wrong secret does not verify", await app.verifyCommitment(c1, "the bridge opens on Saturday") === false);
  check("near-miss secret (trailing space) does not verify", await app.verifyCommitment(c1, "the bridge opens on Friday ") === false);
  check("malformed commitment is null, not false", await app.verifyCommitment("xyz", "the bridge opens on Friday") === null && await app.verifyCommitment(c1.slice(0, 63), "the bridge opens on Friday") === null && await app.verifyCommitment(null, "x") === null);
  check("empty secret against a real commitment is null", await app.verifyCommitment(c1, "") === null);

  /* Merkle trees — real SHA-256 inclusion proofs (async) */
  const solo = await app.buildMerkleTree(["alice"]);
  check("single-entry root is its leaf hash", solo.root === await app.merkleLeafHash("alice") && solo.size === 1);
  check("leaf hash is domain-separated from a bare hash of the entry", solo.root !== await app.sha256Hex("alice"));
  const soloProof = await app.getMerkleProof(["alice"], "alice");
  check("single-entry proof is empty and verifies", soloProof.proof.length === 0 && await app.verifyMerkleProof("alice", soloProof.proof, soloProof.root) === true);
  const pair = await app.buildMerkleTree(["alice", "bob"]);
  const pairSwapped = await app.buildMerkleTree(["bob", "alice"]);
  check("entry order changes the root", pair.root !== pairSwapped.root);
  check("root is deterministic", (await app.buildMerkleTree(["alice", "bob"])).root === pair.root);
  const four = ["alice", "bob", "carol", "dave"];
  const fourTree = await app.buildMerkleTree(four);
  let allFour = true;
  for (const name of four) {
    const p = await app.getMerkleProof(four, name);
    if (!p || p.root !== fourTree.root || p.proof.length !== 2 ||
        await app.verifyMerkleProof(name, p.proof, p.root) !== true) allFour = false;
  }
  check("every member of a 4-list proves with a 2-step proof that verifies", allFour);
  const three = ["alice", "bob", "carol"];
  const carolProof = await app.getMerkleProof(three, "carol");
  check("odd leaf is promoted: 3-list last-entry proof has 1 step and verifies", carolProof.proof.length === 1 && await app.verifyMerkleProof("carol", carolProof.proof, carolProof.root) === true);
  const five = ["a1", "b2", "c3", "d4", "e5"];
  let allFive = true;
  for (const name of five) {
    const p = await app.getMerkleProof(five, name);
    if (!p || await app.verifyMerkleProof(name, p.proof, p.root) !== true) allFive = false;
  }
  check("every member of a 5-list (two promotions deep) verifies", allFive);
  const eightProof = await app.getMerkleProof(["a", "b", "c", "d", "e", "f", "g", "h"], "g");
  check("proof length is log2 of list size for 8 entries", eightProof.proof.length === 3);
  check("non-member gets no proof", await app.getMerkleProof(four, "mallory") === null);
  const bobProof = await app.getMerkleProof(four, "bob");
  check("non-member does not verify against a member's proof", await app.verifyMerkleProof("mallory", bobProof.proof, bobProof.root) === false);
  check("a member's proof does not verify for a different member", await app.verifyMerkleProof("alice", bobProof.proof, bobProof.root) === false);
  const tampered = bobProof.proof.map(s => ({ hash: s.hash, side: s.side }));
  tampered[0] = { hash: await app.merkleLeafHash("mallory"), side: tampered[0].side };
  check("tampered sibling does not verify", await app.verifyMerkleProof("bob", tampered, bobProof.root) === false);
  check("proof against the wrong root does not verify", await app.verifyMerkleProof("bob", bobProof.proof, pair.root) === false);
  check("verify tolerates uppercase and padded root", await app.verifyMerkleProof("bob", bobProof.proof, "  " + bobProof.root.toUpperCase() + " ") === true);
  check("malformed root is null, not false", await app.verifyMerkleProof("bob", bobProof.proof, "xyz") === null && await app.verifyMerkleProof("bob", bobProof.proof, null) === null);
  check("malformed proof steps are null, not false", await app.verifyMerkleProof("bob", [{ hash: "xyz", side: "left" }], bobProof.root) === null && await app.verifyMerkleProof("bob", [{ hash: bobProof.proof[0].hash, side: "up" }], bobProof.root) === null && await app.verifyMerkleProof("bob", "nope", bobProof.root) === null);
  check("empty entry against a real root is null", await app.verifyMerkleProof("", [], bobProof.root) === null);
  check("build rejects duplicates, empty and junk lists", await app.buildMerkleTree(["alice", "alice"]) === null && await app.buildMerkleTree([]) === null && await app.buildMerkleTree(null) === null && await app.buildMerkleTree(["alice", 42]) === null);
  check("leaf hash rejects blank and non-string", await app.merkleLeafHash("") === null && await app.merkleLeafHash("  ") === null && await app.merkleLeafHash(null) === null);
  check("proof never contains another entry in plain text", !JSON.stringify(bobProof).includes("carol") && !JSON.stringify(bobProof).includes("dave"));

  /* notes & nullifiers — domain-separated SHA-256, spend-once ledger (async) */
  const noteA = await app.noteCommitment("locker note number seven");
  const nullA = await app.noteNullifier("locker note number seven");
  check("note commitment and nullifier are 64 lowercase hex", /^[0-9a-f]{64}$/.test(noteA) && /^[0-9a-f]{64}$/.test(nullA));
  check("note commitment and nullifier differ for the same secret (domain separation)", noteA !== nullA);
  check("note hashes differ from tool 8's commitment for the same secret", noteA !== await app.makeCommitment("locker note number seven") && nullA !== await app.makeCommitment("locker note number seven"));
  check("note hashes are deterministic and secret-sensitive", await app.noteCommitment("locker note number seven") === noteA && await app.noteNullifier("locker note number eight") !== nullA);
  check("note hashes never contain the secret", !noteA.includes("locker") && !nullA.includes("locker"));
  check("note hashes reject empty, blank and non-string secrets", await app.noteCommitment("") === null && await app.noteCommitment("  ") === null && await app.noteNullifier(null) === null && await app.noteCommitment(42) === null);
  check("note prefixes are distinct and versioned", app.NOTE_COMMIT_PREFIX !== app.NOTE_NULLIFIER_PREFIX && app.NOTE_COMMIT_PREFIX.includes("v1") && app.NOTE_NULLIFIER_PREFIX.includes("v1"));
  check("hex list normalises case and padding", JSON.stringify(app.normalizeHexList(["  " + noteA.toUpperCase() + " "])) === JSON.stringify([noteA]));
  check("hex list rejects malformed, duplicated and non-array input", app.normalizeHexList(["xyz"]) === null && app.normalizeHexList([noteA, noteA]) === null && app.normalizeHexList("nope") === null && app.normalizeHexList(null) === null && app.normalizeHexList([42]) === null);
  const noteB = await app.noteCommitment("a second note secret");
  const ledger = [noteA, noteB];
  const firstSpend = await app.attemptSpend(ledger, [], "locker note number seven");
  check("first spend of a created note succeeds and records exactly its nullifier", firstSpend.status === "spent" && firstSpend.commitment === noteA && firstSpend.nullifier === nullA && JSON.stringify(firstSpend.seen) === JSON.stringify([nullA]));
  const doubleSpend = await app.attemptSpend(ledger, firstSpend.seen, "locker note number seven");
  check("second spend of the same note is a double-spend and adds nothing", doubleSpend.status === "double-spend" && doubleSpend.seen.length === 1);
  const unknownSpend = await app.attemptSpend(ledger, firstSpend.seen, "never created this secret");
  check("spending a never-created note is unknown-note and adds nothing", unknownSpend.status === "unknown-note" && unknownSpend.seen.length === 1);
  const secondNoteSpend = await app.attemptSpend(ledger, firstSpend.seen, "a second note secret");
  check("a different created note still spends after the first", secondNoteSpend.status === "spent" && secondNoteSpend.seen.length === 2 && secondNoteSpend.nullifier !== nullA);
  check("attemptSpend never mutates its input lists", ledger.length === 2 && firstSpend.seen.length === 1);
  check("attemptSpend tolerates uppercase ledger entries", (await app.attemptSpend([noteA.toUpperCase()], [], "locker note number seven")).status === "spent");
  check("attemptSpend rejects malformed ledgers and empty secrets as null, not a verdict", await app.attemptSpend(["xyz"], [], "locker note number seven") === null && await app.attemptSpend(ledger, ["xyz"], "locker note number seven") === null && await app.attemptSpend(ledger, [], "") === null && await app.attemptSpend(null, null, null) === null);
  check("a near-miss secret (trailing space) is a different, unknown note", (await app.attemptSpend(ledger, [], "locker note number seven ")).status === "unknown-note");

  /* sealed messages — real AES-GCM via Web Crypto, PBKDF2 key (async) */
  const sealed1 = await app.sealMessage("the meeting moves to the blue room at nine", "correct horse battery staple");
  check("sealed text carries the versioned format with 16-byte salt and 12-byte IV", /^p4a-sealed-v1:[0-9a-f]{32}:[0-9a-f]{24}:[0-9a-f]+$/.test(sealed1));
  check("sealed text never contains the message or the password", !sealed1.includes("blue room") && !sealed1.includes("correct horse"));
  check("ciphertext hex length is plaintext bytes plus the 16-byte GCM tag", sealed1.split(":")[3].length === 2 * ("the meeting moves to the blue room at nine".length + 16));
  check("the right password opens the exact message", await app.unsealMessage(sealed1, "correct horse battery staple") === "the meeting moves to the blue room at nine");
  check("unseal tolerates uppercase and padded sealed text", await app.unsealMessage("  " + sealed1.toUpperCase() + " ", "correct horse battery staple") === "the meeting moves to the blue room at nine");
  check("exact message is preserved by sealing, spaces and unicode included", await app.unsealMessage(await app.sealMessage(" sécret — code 42 ", "pw-nine-nine"), "pw-nine-nine") === " sécret — code 42 ");
  const sealed2 = await app.sealMessage("the meeting moves to the blue room at nine", "correct horse battery staple");
  check("two seals of the same message under one password differ (fresh salt and IV)", sealed2 !== sealed1 && await app.unsealMessage(sealed2, "correct horse battery staple") === "the meeting moves to the blue room at nine");
  check("a wrong password opens nothing", await app.unsealMessage(sealed1, "correct horse battery staple!") === null && await app.unsealMessage(sealed1, "wrong") === null);
  check("a near-miss password (trailing space) opens nothing — passwords are exact", await app.unsealMessage(sealed1, "correct horse battery staple ") === null);
  const tamperedSealed = (() => { const p = sealed1.split(":"); p[3] = (p[3][0] === "0" ? "1" : "0") + p[3].slice(1); return p.join(":"); })();
  check("one changed ciphertext character opens nothing (GCM authentication)", await app.unsealMessage(tamperedSealed, "correct horse battery staple") === null);
  check("a truncated-but-parseable seal opens nothing (GCM catches what parsing cannot)", await app.unsealMessage(sealed1.slice(0, sealed1.length - 40), "correct horse battery staple") === null);
  const swappedSalt = (() => { const a = sealed1.split(":"); const b = sealed2.split(":"); return [a[0], b[1], a[2], a[3]].join(":"); })();
  check("a swapped salt opens nothing", await app.unsealMessage(swappedSalt, "correct horse battery staple") === null);
  check("parseSealed reads a valid seal", (() => { const p = app.parseSealed(sealed1); return p !== null && p.salt.length === 16 && p.iv.length === 12 && p.cipher.length === "the meeting moves to the blue room at nine".length + 16; })());
  check("parseSealed rejects junk, wrong sizes and short ciphertext", app.parseSealed("hello") === null && app.parseSealed(null) === null && app.parseSealed("p4a-sealed-v1:abcd:abcd:abcd") === null && app.parseSealed("p4a-sealed-v1:" + "ab".repeat(16) + ":" + "cd".repeat(12) + ":" + "ef".repeat(10)) === null && app.parseSealed(sealed1.slice(0, 20)) === null);
  check("unseal rejects malformed text and blank passwords as null", await app.unsealMessage("p4a-sealed-v1:xyz", "pw") === null && await app.unsealMessage(sealed1, "") === null && await app.unsealMessage(sealed1, "   ") === null && await app.unsealMessage(null, null) === null);
  check("seal rejects empty, blank, non-string and over-long messages", await app.sealMessage("", "pw") === null && await app.sealMessage("   ", "pw") === null && await app.sealMessage(null, "pw") === null && await app.sealMessage("x".repeat(app.SEAL_MAX_MESSAGE_CHARS + 1), "pw") === null);
  check("seal rejects blank and non-string passwords", await app.sealMessage("hello", "") === null && await app.sealMessage("hello", "   ") === null && await app.sealMessage("hello", null) === null && await app.sealMessage("hello", 42) === null);

  /* signed messages — real ECDSA P-256 via Web Crypto (async) */
  const pairA = await app.generateSigningKeyPair();
  const pairB = await app.generateSigningKeyPair();
  check("generated key pair carries hex keys of the labelled sizes", pairA !== null && /^[0-9a-f]{182}$/.test(pairA.publicKey) && /^[0-9a-f]{276}$/.test(pairA.privateKey));
  check("two generated key pairs differ", pairA.publicKey !== pairB.publicKey && pairA.privateKey !== pairB.privateKey);
  check("key material never contains the message to be signed", !pairA.publicKey.includes("blue locker") && !pairA.privateKey.includes("blue locker"));
  const sigMsg = "I agree to sell the blue locker for 40 ADA — signed, me";
  const sigA = await app.signMessage(pairA.privateKey, sigMsg);
  check("signature carries the versioned format at 64 bytes", /^p4a-sig-v1:[0-9a-f]{128}$/.test(sigA));
  check("signature never contains the message", !sigA.includes("blue locker"));
  check("the signer's own key verifies the exact message", await app.verifySignature(pairA.publicKey, sigMsg, sigA) === true);
  check("verify tolerates uppercase and padded key and signature input", await app.verifySignature("  " + pairA.publicKey.toUpperCase() + " ", sigMsg, " " + sigA.toUpperCase() + " ") === true);
  check("exact message is preserved by signing, spaces and unicode included", await app.verifySignature(pairA.publicKey, " sécret — code 42 ", await app.signMessage(pairA.privateKey, " sécret — code 42 ")) === true);
  const sigA2 = await app.signMessage(pairA.privateKey, sigMsg);
  check("two signatures of one message under one key differ (ECDSA is randomised) yet both verify", sigA2 !== sigA && await app.verifySignature(pairA.publicKey, sigMsg, sigA2) === true);
  check("one changed message character fails verification — false, not null", await app.verifySignature(pairA.publicKey, sigMsg.replace("40 ADA", "41 ADA"), sigA) === false);
  check("a near-miss message (trailing space) fails verification — messages are exact", await app.verifySignature(pairA.publicKey, sigMsg + " ", sigA) === false);
  check("a different key fails verification of this signature", await app.verifySignature(pairB.publicKey, sigMsg, sigA) === false);
  check("a signature made by a different key fails against this key", await app.verifySignature(pairA.publicKey, sigMsg, await app.signMessage(pairB.privateKey, sigMsg)) === false);
  const tamperedSig = (() => { const p = sigA.split(":"); p[1] = (p[1][0] === "0" ? "1" : "0") + p[1].slice(1); return p.join(":"); })();
  check("one changed signature character fails verification", await app.verifySignature(pairA.publicKey, sigMsg, tamperedSig) === false);
  check("parseSignature reads a valid signature at 64 bytes", (() => { const p = app.parseSignature(sigA); return p !== null && p.signature.length === 64; })());
  check("parseSignature rejects junk, wrong sizes and missing prefix", app.parseSignature("hello") === null && app.parseSignature(null) === null && app.parseSignature("p4a-sig-v1:abcd") === null && app.parseSignature(sigA.slice(0, sigA.length - 2)) === null && app.parseSignature(sigA.replace("p4a-sig-v1", "p4a-sig-v2")) === null);
  check("verify returns null (not false) for malformed key, signature and message inputs", await app.verifySignature("xyz", sigMsg, sigA) === null && await app.verifySignature(pairA.privateKey, sigMsg, sigA) === null && await app.verifySignature(pairA.publicKey, sigMsg, "p4a-sig-v1:zz") === null && await app.verifySignature(pairA.publicKey, "", sigA) === null && await app.verifySignature(pairA.publicKey, "   ", sigA) === null && await app.verifySignature(null, null, null) === null);
  check("sign rejects a public key, junk keys, and empty, blank, non-string and over-long messages", await app.signMessage(pairA.publicKey, sigMsg) === null && await app.signMessage("xyz", sigMsg) === null && await app.signMessage(pairA.privateKey, "") === null && await app.signMessage(pairA.privateKey, "   ") === null && await app.signMessage(pairA.privateKey, null) === null && await app.signMessage(pairA.privateKey, "x".repeat(app.SIGN_MAX_MESSAGE_CHARS + 1)) === null && await app.signMessage(null, sigMsg) === null);

  /* key agreement — real ECDH P-256 via Web Crypto (async) */
  const agreeA = await app.generateAgreementKeyPair();
  const agreeB = await app.generateAgreementKeyPair();
  const agreeC = await app.generateAgreementKeyPair();
  check("generated agreement pair carries hex keys of the labelled sizes", agreeA !== null && /^[0-9a-f]{182}$/.test(agreeA.publicKey) && /^[0-9a-f]{276}$/.test(agreeA.privateKey));
  check("two generated agreement pairs differ", agreeA.publicKey !== agreeB.publicKey && agreeA.privateKey !== agreeB.privateKey);
  const secretAB = await app.deriveSharedSecret(agreeA.privateKey, agreeB.publicKey);
  const secretBA = await app.deriveSharedSecret(agreeB.privateKey, agreeA.publicKey);
  check("shared secret is 32 bytes of lowercase hex", /^[0-9a-f]{64}$/.test(secretAB));
  check("both sides of an agreement derive exactly the same secret", secretAB === secretBA && secretAB !== null);
  check("agreement is deterministic for the same key pair", await app.deriveSharedSecret(agreeA.privateKey, agreeB.publicKey) === secretAB);
  check("derive tolerates uppercase and padded key input", await app.deriveSharedSecret("  " + agreeA.privateKey.toUpperCase() + " ", " " + agreeB.publicKey.toUpperCase() + " ") === secretAB);
  check("a different pairing derives a different secret", await app.deriveSharedSecret(agreeA.privateKey, agreeC.publicKey) !== secretAB && await app.deriveSharedSecret(agreeC.privateKey, agreeB.publicKey) !== secretAB);
  check("agreeing with your own public key is a different secret again", await app.deriveSharedSecret(agreeA.privateKey, agreeA.publicKey) !== secretAB);
  check("the shared secret is neither side's key material", secretAB !== agreeA.publicKey && secretAB !== agreeB.publicKey && !agreeA.privateKey.includes(secretAB) && !agreeB.privateKey.includes(secretAB));
  check("parseSharedSecret reads a valid secret and normalises case and padding", app.parseSharedSecret("  " + secretAB.toUpperCase() + " ") === secretAB);
  check("parseSharedSecret rejects junk, wrong sizes and non-strings", app.parseSharedSecret("hello") === null && app.parseSharedSecret(secretAB.slice(0, 62)) === null && app.parseSharedSecret(secretAB + "ab") === null && app.parseSharedSecret("") === null && app.parseSharedSecret(null) === null && app.parseSharedSecret(42) === null);
  const fpAB = await app.sharedSecretFingerprint(secretAB);
  check("fingerprint is 64 lowercase hex and is not the secret", /^[0-9a-f]{64}$/.test(fpAB) && fpAB !== secretAB);
  check("fingerprint is deterministic and tolerates case and padding", await app.sharedSecretFingerprint(" " + secretAB.toUpperCase() + " ") === fpAB);
  check("a different secret has a different fingerprint", await app.sharedSecretFingerprint(await app.deriveSharedSecret(agreeA.privateKey, agreeC.publicKey)) !== fpAB);
  check("fingerprint rejects junk, wrong sizes and non-strings as null", await app.sharedSecretFingerprint("xyz") === null && await app.sharedSecretFingerprint(secretAB.slice(0, 32)) === null && await app.sharedSecretFingerprint(null) === null && await app.sharedSecretFingerprint(42) === null);
  check("derive rejects junk, null and non-string keys as null", await app.deriveSharedSecret("xyz", agreeB.publicKey) === null && await app.deriveSharedSecret(agreeA.privateKey, "xyz") === null && await app.deriveSharedSecret(null, null) === null && await app.deriveSharedSecret(42, agreeB.publicKey) === null);
  check("derive rejects swapped and wrong-size keys as null, never a plausible secret", await app.deriveSharedSecret(agreeA.publicKey, agreeB.publicKey) === null && await app.deriveSharedSecret(agreeA.privateKey, agreeB.privateKey) === null && await app.deriveSharedSecret(agreeA.privateKey.slice(0, 100), agreeB.publicKey) === null && await app.deriveSharedSecret(agreeA.privateKey, agreeB.publicKey.slice(0, 100)) === null);

  /* key derivation — real HKDF-SHA-256 via Web Crypto (async),
     cross-checked against Node's independent hkdfSync oracle */
  const { hkdfSync } = require("crypto");
  const hkSecret = "0b".repeat(22);
  const hkSalt = "000102030405060708090a0b0c0d0e0f";
  const hkMsg = await app.deriveSessionKey(hkSecret, "messaging", hkSalt);
  check("HKDF key is 32 bytes of lowercase hex and is not the secret", /^[0-9a-f]{64}$/.test(hkMsg) && hkMsg !== hkSecret);
  check("HKDF matches Node's independent hkdfSync oracle (salted)", hkMsg === Buffer.from(hkdfSync("sha256", Buffer.from(hkSecret, "hex"), Buffer.from(hkSalt, "hex"), Buffer.from(app.DERIVE_PURPOSE_CATALOG.messaging.info, "utf8"), 32)).toString("hex"));
  check("HKDF matches the oracle with no salt (blank means none)", await app.deriveSessionKey(hkSecret, "messaging", "") === Buffer.from(hkdfSync("sha256", Buffer.from(hkSecret, "hex"), Buffer.alloc(0), Buffer.from(app.DERIVE_PURPOSE_CATALOG.messaging.info, "utf8"), 32)).toString("hex"));
  check("HKDF matches the oracle for the storage purpose", await app.deriveSessionKey(hkSecret, "storage", hkSalt) === Buffer.from(hkdfSync("sha256", Buffer.from(hkSecret, "hex"), Buffer.from(hkSalt, "hex"), Buffer.from(app.DERIVE_PURPOSE_CATALOG.storage.info, "utf8"), 32)).toString("hex"));
  check("HKDF is deterministic and tolerates uppercase and padded input", await app.deriveSessionKey("  " + hkSecret.toUpperCase() + " ", "messaging", " " + hkSalt.toUpperCase() + " ") === hkMsg);
  check("a different purpose derives an unrelated key from the same secret", await app.deriveSessionKey(hkSecret, "storage", hkSalt) !== hkMsg && await app.deriveSessionKey(hkSecret, "backup", hkSalt) !== hkMsg && await app.deriveSessionKey(hkSecret, "storage", hkSalt) !== await app.deriveSessionKey(hkSecret, "backup", hkSalt));
  check("a different salt derives a different key; no salt differs from any salt", await app.deriveSessionKey(hkSecret, "messaging", "ff".repeat(16)) !== hkMsg && await app.deriveSessionKey(hkSecret, "messaging", "") !== hkMsg);
  check("a different secret derives a different key", await app.deriveSessionKey("0c".repeat(22), "messaging", hkSalt) !== hkMsg);
  check("tool 18's real shared secret derives a valid key (the tools chain)", /^[0-9a-f]{64}$/.test(await app.deriveSessionKey(secretAB, "messaging", "")));
  check("parseDeriveSecret accepts 16..64 byte hex and normalises case and padding", app.parseDeriveSecret("  " + hkSecret.toUpperCase() + " ") === hkSecret && app.parseDeriveSecret("ab".repeat(16)) !== null && app.parseDeriveSecret("ab".repeat(64)) !== null);
  check("parseDeriveSecret rejects junk, wrong sizes and non-strings", app.parseDeriveSecret("hello") === null && app.parseDeriveSecret("ab".repeat(15)) === null && app.parseDeriveSecret("ab".repeat(65)) === null && app.parseDeriveSecret("") === null && app.parseDeriveSecret(null) === null && app.parseDeriveSecret(42) === null);
  check("parseDeriveSalt: blank is no salt, 16-byte hex parses, anything else is null", app.parseDeriveSalt("").length === 0 && app.parseDeriveSalt("   ").length === 0 && app.parseDeriveSalt(hkSalt).length === 16 && app.parseDeriveSalt("abcd") === null && app.parseDeriveSalt("ab".repeat(17)) === null && app.parseDeriveSalt(null) === null);
  check("getDerivePurpose reads the catalog and rejects unknown purposes", app.getDerivePurpose("messaging").info === "privacy4all-hkdf-v1 messaging" && app.getDerivePurpose("nope") === null && app.getDerivePurpose(null) === null && app.getDerivePurpose("constructor") === null);
  check("HKDF rejects junk secrets, unknown purposes and bad salts as null", await app.deriveSessionKey("xyz", "messaging", hkSalt) === null && await app.deriveSessionKey(hkSecret, "nope", hkSalt) === null && await app.deriveSessionKey(hkSecret, "messaging", "abcd") === null && await app.deriveSessionKey(null, null, null) === null && await app.deriveSessionKey(hkSecret.slice(0, 30), "messaging", hkSalt) === null);
  check("checkDerivedKey is true for the exact key those inputs derive", await app.checkDerivedKey(hkSecret, "messaging", hkSalt, hkMsg) === true && await app.checkDerivedKey(hkSecret.toUpperCase(), "messaging", hkSalt, " " + hkMsg.toUpperCase() + " ") === true);
  check("checkDerivedKey is false (not null) for a well-formed but different key, purpose or salt", await app.checkDerivedKey(hkSecret, "messaging", hkSalt, await app.deriveSessionKey(hkSecret, "storage", hkSalt)) === false && await app.checkDerivedKey(hkSecret, "storage", hkSalt, hkMsg) === false && await app.checkDerivedKey(hkSecret, "messaging", "", hkMsg) === false);
  check("checkDerivedKey is null (not false) for malformed inputs", await app.checkDerivedKey(hkSecret, "messaging", hkSalt, "xyz") === null && await app.checkDerivedKey(hkSecret, "messaging", hkSalt, hkMsg.slice(0, 32)) === null && await app.checkDerivedKey("xyz", "messaging", hkSalt, hkMsg) === null && await app.checkDerivedKey(hkSecret, "nope", hkSalt, hkMsg) === null && await app.checkDerivedKey(null, null, null, null) === null);

  /* key-sealed messages — real AES-GCM with a raw derived key
     (async), cross-checked against Node's independent crypto:
     Web Crypto appends the 16-byte GCM tag to the ciphertext,
     Node's createCipheriv keeps it separate */
  const { createCipheriv, createDecipheriv, randomBytes } = require("crypto");
  const ksKey = await app.deriveSessionKey(hkSecret, "messaging", hkSalt);
  const ksMsg = "the blue locker, Friday, nine — bring the spare key";
  const ksSealed = await app.sealWithSessionKey(ksMsg, ksKey);
  check("key-sealed constants are the labelled bounds", app.KEYSEAL_FORMAT === "p4a-keysealed-v1" && app.KEYSEAL_KEY_BYTES === 32 && app.KEYSEAL_IV_BYTES === 12 && app.KEYSEAL_MAX_MESSAGE_CHARS === 2000);
  check("key-sealed output is one versioned line and does not contain the key or the message", /^p4a-keysealed-v1:[0-9a-f]{24}:[0-9a-f]+$/.test(ksSealed) && !ksSealed.includes(ksKey) && !ksSealed.includes("locker"));
  check("key-sealed ciphertext is plaintext bytes plus the 16-byte GCM tag", app.parseKeySealed(ksSealed).cipher.length === Buffer.byteLength(ksMsg, "utf8") + 16 && app.parseKeySealed(ksSealed).iv.length === 12);
  check("key-sealed round-trips exactly with the same key", await app.openWithSessionKey(ksSealed, ksKey) === ksMsg);
  check("key-sealed round-trips unicode and trailing spaces exactly", await app.openWithSessionKey(await app.sealWithSessionKey("café 🔐 note ", ksKey), ksKey) === "café 🔐 note ");
  check("key-sealed tolerates uppercase and padded sealed text and key", await app.openWithSessionKey("  " + ksSealed.toUpperCase() + " ", " " + ksKey.toUpperCase() + " ") === ksMsg);
  check("each seal uses a fresh IV, so the same message seals differently and both open", await (async () => { const a = await app.sealWithSessionKey(ksMsg, ksKey); const b = await app.sealWithSessionKey(ksMsg, ksKey); return a !== b && await app.openWithSessionKey(a, ksKey) === ksMsg && await app.openWithSessionKey(b, ksKey) === ksMsg; })());
  check("Node's independent AES-256-GCM opens the app's sealed output", (() => { const p = app.parseKeySealed(ksSealed); const d = createDecipheriv("aes-256-gcm", Buffer.from(ksKey, "hex"), Buffer.from(p.iv)); d.setAuthTag(Buffer.from(p.cipher.slice(p.cipher.length - 16))); return Buffer.concat([d.update(Buffer.from(p.cipher.slice(0, p.cipher.length - 16))), d.final()]).toString("utf8") === ksMsg; })());
  check("the app opens a message sealed by Node's independent AES-256-GCM", await (async () => { const iv = randomBytes(12); const c = createCipheriv("aes-256-gcm", Buffer.from(ksKey, "hex"), iv); const ct = Buffer.concat([c.update(ksMsg, "utf8"), c.final(), c.getAuthTag()]); return await app.openWithSessionKey("p4a-keysealed-v1:" + iv.toString("hex") + ":" + ct.toString("hex"), ksKey) === ksMsg; })());
  check("a different derived key (other purpose, salt or secret) opens nothing", await app.openWithSessionKey(ksSealed, await app.deriveSessionKey(hkSecret, "storage", hkSalt)) === null && await app.openWithSessionKey(ksSealed, await app.deriveSessionKey(hkSecret, "messaging", "")) === null && await app.openWithSessionKey(ksSealed, await app.deriveSessionKey("0c".repeat(22), "messaging", hkSalt)) === null);
  check("a tampered ciphertext byte or IV opens nothing", await (async () => { const p = ksSealed.split(":"); const flip = (h) => (h[0] === "0" ? "1" : "0") + h.slice(1); return await app.openWithSessionKey(p[0] + ":" + p[1] + ":" + flip(p[2]), ksKey) === null && await app.openWithSessionKey(p[0] + ":" + flip(p[1]) + ":" + p[2], ksKey) === null; })());
  check("a truncated seal opens nothing", await app.openWithSessionKey(ksSealed.slice(0, ksSealed.length - 10), ksKey) === null);
  check("parseKeySealed reads a valid seal and rejects junk, wrong IV size and too-short cipher", app.parseKeySealed(ksSealed) !== null && app.parseKeySealed("p4a-keysealed-v1:abcd:" + "ab".repeat(20)) === null && app.parseKeySealed("p4a-keysealed-v1:" + "ab".repeat(12) + ":" + "ab".repeat(10)) === null && app.parseKeySealed("p4a-sealed-v1:" + "ab".repeat(16) + ":" + "ab".repeat(12) + ":" + "ab".repeat(20)) === null && app.parseKeySealed("hello") === null && app.parseKeySealed(null) === null && app.parseKeySealed(42) === null);
  check("key-seal rejects blank, over-long and non-string messages as null", await app.sealWithSessionKey("", ksKey) === null && await app.sealWithSessionKey("   ", ksKey) === null && await app.sealWithSessionKey("x".repeat(app.KEYSEAL_MAX_MESSAGE_CHARS + 1), ksKey) === null && await app.sealWithSessionKey(null, ksKey) === null && await app.sealWithSessionKey(42, ksKey) === null);
  check("key-seal rejects junk, wrong-size and non-string keys as null, never a plausible seal", await app.sealWithSessionKey(ksMsg, "xyz") === null && await app.sealWithSessionKey(ksMsg, ksKey.slice(0, 62)) === null && await app.sealWithSessionKey(ksMsg, ksKey + "ab") === null && await app.sealWithSessionKey(ksMsg, null) === null && await app.openWithSessionKey(ksSealed, "xyz") === null && await app.openWithSessionKey("hello", ksKey) === null && await app.openWithSessionKey(null, null) === null);
  check("the full chain works: tool 18 agreement -> tool 19 messaging key -> tool 20 locked message", await (async () => { const key = await app.deriveSessionKey(secretAB, "messaging", ""); const sealed = await app.sealWithSessionKey(ksMsg, key); return sealed !== null && await app.openWithSessionKey(sealed, await app.deriveSessionKey(secretBA, "messaging", "")) === ksMsg; })());

  /* authenticated messages — ECDSA signature inside an AES-GCM
     seal (async): opening and verifying are separate answers,
     and a message signed by the wrong key must come back with
     its text and verified === false, never as verified */
  const authPair = await app.generateSigningKeyPair();
  const authOther = await app.generateSigningKeyPair();
  const authMsg = "the blue locker, Friday, nine — and yes, this one is really from me";
  const authSealed = await app.signAndSealMessage(authPair.privateKey, authMsg, ksKey);
  check("auth-sealed constants are the labelled bounds", app.AUTHSEAL_FORMAT === "p4a-authsealed-v1" && app.AUTHSEAL_ENVELOPE_FORMAT === "p4a-signed-v1" && app.AUTHSEAL_MAX_MESSAGE_CHARS === 1800);
  check("auth-sealed output is one versioned line and leaks neither message, key nor signing key", /^p4a-authsealed-v1:[0-9a-f]{24}:[0-9a-f]+$/.test(authSealed) && !authSealed.includes("locker") && !authSealed.includes(ksKey) && !authSealed.includes(authPair.privateKey.slice(0, 32)));
  check("auth-sealed opens verified against the signer's public key", await (async () => { const r = await app.openAuthenticatedMessage(authSealed, ksKey, authPair.publicKey); return r !== null && r.message === authMsg && r.verified === true; })());
  check("auth-sealed round-trips unicode and trailing spaces exactly, verified", await (async () => { const s = await app.signAndSealMessage(authPair.privateKey, "café 🔐 note ", ksKey); const r = await app.openAuthenticatedMessage(s, ksKey, authPair.publicKey); return r !== null && r.message === "café 🔐 note " && r.verified === true; })());
  check("auth-sealed tolerates uppercase and padded sealed text and keys", await (async () => { const r = await app.openAuthenticatedMessage("  " + authSealed.toUpperCase() + " ", " " + ksKey.toUpperCase() + " ", " " + authPair.publicKey.toUpperCase() + " "); return r !== null && r.message === authMsg && r.verified === true; })());
  check("the same seal checked against a different public key opens UNVERIFIED, text intact", await (async () => { const r = await app.openAuthenticatedMessage(authSealed, ksKey, authOther.publicKey); return r !== null && r.message === authMsg && r.verified === false; })());
  check("a forged envelope (sealed by a key-holder, signed by an impostor) opens UNVERIFIED", await (async () => { const sig = await app.signMessage(authOther.privateKey, authMsg); const inner = JSON.stringify({ format: app.AUTHSEAL_ENVELOPE_FORMAT, message: authMsg, signature: sig }); const raw = await app.sealWithSessionKey(inner, ksKey); const forged = app.AUTHSEAL_FORMAT + raw.slice(app.KEYSEAL_FORMAT.length); const r = await app.openAuthenticatedMessage(forged, ksKey, authPair.publicKey); return r !== null && r.message === authMsg && r.verified === false; })());
  check("an envelope whose message was swapped after signing opens UNVERIFIED", await (async () => { const sig = await app.signMessage(authPair.privateKey, "a different message entirely"); const inner = JSON.stringify({ format: app.AUTHSEAL_ENVELOPE_FORMAT, message: authMsg, signature: sig }); const raw = await app.sealWithSessionKey(inner, ksKey); const swapped = app.AUTHSEAL_FORMAT + raw.slice(app.KEYSEAL_FORMAT.length); const r = await app.openAuthenticatedMessage(swapped, ksKey, authPair.publicKey); return r !== null && r.message === authMsg && r.verified === false; })());
  check("an envelope with a malformed signature is null, not unverified", await (async () => { const inner = JSON.stringify({ format: app.AUTHSEAL_ENVELOPE_FORMAT, message: authMsg, signature: "p4a-sig-v1:zz" }); const raw = await app.sealWithSessionKey(inner, ksKey); const bad = app.AUTHSEAL_FORMAT + raw.slice(app.KEYSEAL_FORMAT.length); return await app.openAuthenticatedMessage(bad, ksKey, authPair.publicKey) === null; })());
  check("a plain tool-20 seal is not an authenticated message (null, both directions)", await app.openAuthenticatedMessage(ksSealed, ksKey, authPair.publicKey) === null && await app.openWithSessionKey(authSealed, ksKey) === null && app.parseAuthSealed(ksSealed) === null && app.parseKeySealed(authSealed) === null);
  check("a wrong session key opens nothing, even with the right public key", await app.openAuthenticatedMessage(authSealed, await app.deriveSessionKey(hkSecret, "storage", hkSalt), authPair.publicKey) === null);
  check("a tampered auth-sealed byte or IV opens nothing", await (async () => { const p = authSealed.split(":"); const flip = (h) => (h[0] === "0" ? "1" : "0") + h.slice(1); return await app.openAuthenticatedMessage(p[0] + ":" + p[1] + ":" + flip(p[2]), ksKey, authPair.publicKey) === null && await app.openAuthenticatedMessage(p[0] + ":" + flip(p[1]) + ":" + p[2], ksKey, authPair.publicKey) === null; })());
  check("a truncated auth-seal opens nothing", await app.openAuthenticatedMessage(authSealed.slice(0, authSealed.length - 10), ksKey, authPair.publicKey) === null);
  check("a malformed sender public key is null, not a failed check", await app.openAuthenticatedMessage(authSealed, ksKey, "xyz") === null && await app.openAuthenticatedMessage(authSealed, ksKey, authPair.privateKey) === null && await app.openAuthenticatedMessage(authSealed, ksKey, null) === null);
  check("parseAuthSealed reads a valid seal and rejects junk, wrong IV size and too-short cipher", app.parseAuthSealed(authSealed) !== null && app.parseAuthSealed("p4a-authsealed-v1:abcd:" + "ab".repeat(20)) === null && app.parseAuthSealed("p4a-authsealed-v1:" + "ab".repeat(12) + ":" + "ab".repeat(10)) === null && app.parseAuthSealed("hello") === null && app.parseAuthSealed(null) === null && app.parseAuthSealed(42) === null);
  check("parseSignedEnvelope reads a real envelope and rejects junk, wrong format and bad signatures", await (async () => { const sig = await app.signMessage(authPair.privateKey, authMsg); const good = JSON.stringify({ format: "p4a-signed-v1", message: authMsg, signature: sig }); const env = app.parseSignedEnvelope(good); return env !== null && env.message === authMsg && env.signature === sig && app.parseSignedEnvelope("not json") === null && app.parseSignedEnvelope(JSON.stringify({ format: "p4a-signed-v2", message: authMsg, signature: sig })) === null && app.parseSignedEnvelope(JSON.stringify({ format: "p4a-signed-v1", message: "", signature: sig })) === null && app.parseSignedEnvelope(JSON.stringify({ format: "p4a-signed-v1", message: authMsg, signature: "junk" })) === null && app.parseSignedEnvelope(null) === null && app.parseSignedEnvelope(42) === null; })());
  check("sign-and-seal rejects blank, over-long and non-string messages as null", await app.signAndSealMessage(authPair.privateKey, "", ksKey) === null && await app.signAndSealMessage(authPair.privateKey, "   ", ksKey) === null && await app.signAndSealMessage(authPair.privateKey, "x".repeat(app.AUTHSEAL_MAX_MESSAGE_CHARS + 1), ksKey) === null && await app.signAndSealMessage(authPair.privateKey, null, ksKey) === null && await app.signAndSealMessage(authPair.privateKey, 42, ksKey) === null);
  check("a message at exactly the labelled cap seals and opens verified (envelope still fits the seal)", await (async () => { const big = "x".repeat(app.AUTHSEAL_MAX_MESSAGE_CHARS); const s = await app.signAndSealMessage(authPair.privateKey, big, ksKey); const r = await app.openAuthenticatedMessage(s, ksKey, authPair.publicKey); return r !== null && r.message === big && r.verified === true; })());
  check("sign-and-seal rejects junk keys as null, never a plausible seal", await app.signAndSealMessage("xyz", authMsg, ksKey) === null && await app.signAndSealMessage(authPair.publicKey, authMsg, ksKey) === null && await app.signAndSealMessage(authPair.privateKey, authMsg, "xyz") === null && await app.signAndSealMessage(authPair.privateKey, authMsg, ksKey.slice(0, 62)) === null && await app.signAndSealMessage(null, null, null) === null);
  check("each sign-and-seal differs (fresh IV and randomised signature) and both open verified", await (async () => { const a = await app.signAndSealMessage(authPair.privateKey, authMsg, ksKey); const b = await app.signAndSealMessage(authPair.privateKey, authMsg, ksKey); const ra = await app.openAuthenticatedMessage(a, ksKey, authPair.publicKey); const rb = await app.openAuthenticatedMessage(b, ksKey, authPair.publicKey); return a !== b && ra.verified === true && rb.verified === true; })());
  check("the full private-messaging chain works: agreement -> derived key -> sign -> seal -> open -> verified, from the other side's derivation", await (async () => { const keyA = await app.deriveSessionKey(secretAB, "messaging", ""); const sealed = await app.signAndSealMessage(authPair.privateKey, authMsg, keyA); const keyB = await app.deriveSessionKey(secretBA, "messaging", ""); const r = await app.openAuthenticatedMessage(sealed, keyB, authPair.publicKey); return r !== null && r.message === authMsg && r.verified === true; })());

  /* the ratchet — one key per message; each step is HKDF over
     the chain key with domain-separated info strings, cross-
     checked against Node's independent hkdfSync oracle */
  const nodeHkdf = require("crypto").hkdfSync;
  const rState0 = app.startChainState(ksKey);
  const rStep0 = await app.ratchetStep(ksKey);
  check("ratchet constants are the labelled values", app.RATCHET_STATE_FORMAT === "p4a-chain-v1" && app.RATCHET_MAX_INDEX === 1000000 && app.RATCHET_MSG_INFO !== app.RATCHET_NEXT_INFO && app.RATCHET_MSG_INFO.includes("message") && app.RATCHET_NEXT_INFO.includes("next"));
  check("a chain starts at position 0 on the session key itself", rState0 === "p4a-chain-v1:0:" + ksKey && app.parseChainState(rState0).index === 0 && app.parseChainState(rState0).chainKey === ksKey);
  check("startChainState rejects junk keys as null", app.startChainState("xyz") === null && app.startChainState(ksKey.slice(0, 62)) === null && app.startChainState(null) === null && app.startChainState(42) === null);
  check("parseChainState reads a valid state and rejects junk, leading zeros, over-cap indexes and bad keys", app.parseChainState("  " + rState0.toUpperCase() + " ") !== null && app.parseChainState("p4a-chain-v1:007:" + ksKey) === null && app.parseChainState("p4a-chain-v1:-1:" + ksKey) === null && app.parseChainState("p4a-chain-v1:1.5:" + ksKey) === null && app.parseChainState("p4a-chain-v1:" + (app.RATCHET_MAX_INDEX + 1) + ":" + ksKey) === null && app.parseChainState("p4a-chain-v1:0:" + ksKey.slice(0, 62)) === null && app.parseChainState("hello") === null && app.parseChainState(null) === null && app.parseChainState(42) === null);
  check("formatChainState round-trips and rejects bad indexes and keys", app.formatChainState(7, ksKey) === "p4a-chain-v1:7:" + ksKey && app.formatChainState(app.RATCHET_MAX_INDEX, ksKey) !== null && app.formatChainState(-1, ksKey) === null && app.formatChainState(1.5, ksKey) === null && app.formatChainState(app.RATCHET_MAX_INDEX + 1, ksKey) === null && app.formatChainState(0, "xyz") === null && app.formatChainState("0", ksKey) === null);
  check("ratchetStep is deterministic, domain-separated and 32-byte throughout", await (async () => { const again = await app.ratchetStep(ksKey); return rStep0 !== null && again !== null && again.messageKey === rStep0.messageKey && again.nextChainKey === rStep0.nextChainKey && rStep0.messageKey !== rStep0.nextChainKey && /^[0-9a-f]{64}$/.test(rStep0.messageKey) && /^[0-9a-f]{64}$/.test(rStep0.nextChainKey) && rStep0.nextChainKey !== ksKey; })());
  check("ratchetStep matches Node's independent hkdfSync oracle for both outputs", rStep0.messageKey === Buffer.from(nodeHkdf("sha256", Buffer.from(ksKey, "hex"), Buffer.alloc(0), Buffer.from(app.RATCHET_MSG_INFO, "utf8"), 32)).toString("hex") && rStep0.nextChainKey === Buffer.from(nodeHkdf("sha256", Buffer.from(ksKey, "hex"), Buffer.alloc(0), Buffer.from(app.RATCHET_NEXT_INFO, "utf8"), 32)).toString("hex"));
  check("ratchetStep rejects junk keys as null", await app.ratchetStep("xyz") === null && await app.ratchetStep(ksKey.slice(0, 62)) === null && await app.ratchetStep(null) === null);
  const rMsg1 = "first ratcheted note — this key exists for this message only";
  const rMsg2 = "second ratcheted note, sealed under a key the first state cannot recompute";
  const rSeal1 = await app.sealRatchetMessage(rState0, rMsg1);
  const rSeal2 = await app.sealRatchetMessage(rSeal1.state, rMsg2);
  check("sealing advances the state exactly one position per message, to a new chain key each time", app.parseChainState(rSeal1.state).index === 1 && app.parseChainState(rSeal2.state).index === 2 && app.parseChainState(rSeal1.state).chainKey === rStep0.nextChainKey && app.parseChainState(rSeal2.state).chainKey !== app.parseChainState(rSeal1.state).chainKey);
  check("a ratcheted seal is a plain tool-20 line, opened by that step's message key alone", app.parseKeySealed(rSeal1.sealed) !== null && await app.openWithSessionKey(rSeal1.sealed, rStep0.messageKey) === rMsg1 && !rSeal1.sealed.includes("ratcheted"));
  check("the receiver opens in order and lands on exactly the sender's next state", await (async () => { const o = await app.openRatchetMessage(rState0, rSeal1.sealed); return o !== null && o.message === rMsg1 && o.state === rSeal1.state; })());
  check("the second message opens from the advanced state", await (async () => { const o1 = await app.openRatchetMessage(rState0, rSeal1.sealed); const o2 = await app.openRatchetMessage(o1.state, rSeal2.sealed); return o2 !== null && o2.message === rMsg2 && o2.state === rSeal2.state; })());
  check("forward secrecy: the advanced state cannot reopen the first message — its key is gone", await app.openRatchetMessage(rSeal1.state, rSeal1.sealed) === null && await app.openWithSessionKey(rSeal1.sealed, (await app.ratchetStep(app.parseChainState(rSeal1.state).chainKey)).messageKey) === null);
  check("a replayed message fails against a state that has already passed it", await app.openRatchetMessage(rSeal2.state, rSeal1.sealed) === null && await app.openRatchetMessage(rSeal2.state, rSeal2.sealed) === null);
  check("out of order opens nothing, then succeeds once the missing message arrives (a failed open consumes nothing)", await (async () => { if (await app.openRatchetMessage(rState0, rSeal2.sealed) !== null) return false; const a = await app.openRatchetMessage(rState0, rSeal1.sealed); if (a === null) return false; const b = await app.openRatchetMessage(a.state, rSeal2.sealed); return b !== null && b.message === rMsg2; })());
  check("a chain started from a different session key opens nothing", await (async () => { const other = app.startChainState(await app.deriveSessionKey(hkSecret, "storage", hkSalt)); return other !== null && await app.openRatchetMessage(other, rSeal1.sealed) === null; })());
  check("a tampered ratcheted seal opens nothing", await (async () => { const p = rSeal1.sealed.split(":"); const flip = (h) => (h[0] === "0" ? "1" : "0") + h.slice(1); return await app.openRatchetMessage(rState0, p[0] + ":" + p[1] + ":" + flip(p[2])) === null; })());
  check("ratchet seal and open reject blank, over-long and non-string messages and malformed states as null", await app.sealRatchetMessage(rState0, "") === null && await app.sealRatchetMessage(rState0, "   ") === null && await app.sealRatchetMessage(rState0, "x".repeat(app.KEYSEAL_MAX_MESSAGE_CHARS + 1)) === null && await app.sealRatchetMessage(rState0, null) === null && await app.sealRatchetMessage("junk", rMsg1) === null && await app.sealRatchetMessage(null, rMsg1) === null && await app.openRatchetMessage("junk", rSeal1.sealed) === null && await app.openRatchetMessage(rState0, "junk") === null && await app.openRatchetMessage(rState0, null) === null);
  check("a chain at the labelled cap refuses to advance rather than run unbounded", await (async () => { const capped = app.formatChainState(app.RATCHET_MAX_INDEX, ksKey); return capped !== null && await app.sealRatchetMessage(capped, "x") === null && await app.openRatchetMessage(capped, rSeal1.sealed) === null; })());
  check("the full chain works end to end: agreement -> session key -> ratcheted conversation, opened from the other side's derivation", await (async () => { const keyA = await app.deriveSessionKey(secretAB, "messaging", ""); const keyB = await app.deriveSessionKey(secretBA, "messaging", ""); let send = app.startChainState(keyA); let recv = app.startChainState(keyB); if (send === null || send !== recv) return false; for (const m of ["one", "two", "three"]) { const s = await app.sealRatchetMessage(send, "ratcheted: " + m); const o = await app.openRatchetMessage(recv, s.sealed); if (o === null || o.message !== "ratcheted: " + m) return false; send = s.state; recv = o.state; } return send === recv && app.parseChainState(send).index === 3; })());

  /* the heal — a fresh ECDH agreement mixed with the current
     chain key through HKDF (fresh secret as input, chain key
     as salt), cross-checked against Node's hkdfSync oracle */
  const healA = await app.generateAgreementKeyPair();
  const healB = await app.generateAgreementKeyPair();
  const healSecret = await app.deriveSharedSecret(healA.privateKey, healB.publicKey);
  const healFrom = app.parseChainState(rSeal1.state);
  const healedAB = await app.healChainState(rSeal1.state, healA.privateKey, healB.publicKey);
  const healedBA = await app.healChainState(rSeal1.state, healB.privateKey, healA.publicKey);
  check("heal info label is the labelled value", app.HEAL_INFO === "privacy4all-heal-v1 chain");
  check("both sides heal from the same state to the identical new chain, at position 0", healedAB !== null && healedAB === healedBA && app.parseChainState(healedAB).index === 0 && app.parseChainState(healedAB).chainKey !== healFrom.chainKey);
  check("the healed key matches Node's independent hkdfSync oracle (fresh secret as input, old chain key as salt)", app.parseChainState(healedAB).chainKey === Buffer.from(nodeHkdf("sha256", Buffer.from(healSecret, "hex"), Buffer.from(healFrom.chainKey, "hex"), Buffer.from(app.HEAL_INFO, "utf8"), 32)).toString("hex"));
  check("the healed key is neither ingredient, nor a plain ratchet step of the old chain", app.parseChainState(healedAB).chainKey !== healSecret && app.parseChainState(healedAB).chainKey !== rStep0.nextChainKey && await (async () => { const step = await app.ratchetStep(healFrom.chainKey); return app.parseChainState(healedAB).chainKey !== step.nextChainKey && app.parseChainState(healedAB).chainKey !== step.messageKey; })());
  check("the heal binds both ingredients: a different old state or a different fresh agreement heals to a different chain", await app.healChainState(rState0, healA.privateKey, healB.publicKey) !== healedAB && await app.healChainState(rSeal1.state, healA.privateKey, agreeC.publicKey) !== healedAB && await app.healChainState(rSeal2.state, healA.privateKey, healB.publicKey) !== healedAB);
  check("someone holding only the leaked state cannot follow: post-heal seals open on the healed chain, never under the old state — and pre-heal seals do not open under the healed chain", await (async () => { const s = await app.sealRatchetMessage(healedAB, "written after the heal"); if (s === null) return false; const o = await app.openRatchetMessage(healedBA, s.sealed); if (o === null || o.message !== "written after the heal") return false; if (await app.openRatchetMessage(rSeal1.state, s.sealed) !== null) return false; if (await app.openRatchetMessage(rSeal2.state, s.sealed) !== null) return false; return await app.openRatchetMessage(healedAB, rSeal1.sealed) === null; })());
  check("heal rejects malformed states and junk, swapped or wrong-size keys as null, never a plausible chain", await app.healChainState("junk", healA.privateKey, healB.publicKey) === null && await app.healChainState(null, healA.privateKey, healB.publicKey) === null && await app.healChainState(rSeal1.state, "xyz", healB.publicKey) === null && await app.healChainState(rSeal1.state, healA.publicKey, healB.publicKey) === null && await app.healChainState(rSeal1.state, healA.privateKey, healB.privateKey) === null && await app.healChainState(rSeal1.state, healA.privateKey.slice(0, 100), healB.publicKey) === null && await app.healChainState(rSeal1.state, null, null) === null);
  check("the full recovery story works: conversation, leak, heal — the conversation resumes on the healed chain, opened from the other side's heal", await (async () => { const keyA = await app.deriveSessionKey(secretAB, "messaging", ""); const keyB = await app.deriveSessionKey(secretBA, "messaging", ""); let send = app.startChainState(keyA); let recv = app.startChainState(keyB); const s1 = await app.sealRatchetMessage(send, "before the leak"); const o1 = await app.openRatchetMessage(recv, s1.sealed); if (o1 === null || o1.message !== "before the leak") return false; send = s1.state; recv = o1.state; if (send !== recv) return false; const hA = await app.generateAgreementKeyPair(); const hB = await app.generateAgreementKeyPair(); const healedSend = await app.healChainState(send, hA.privateKey, hB.publicKey); const healedRecv = await app.healChainState(recv, hB.privateKey, hA.publicKey); if (healedSend === null || healedSend !== healedRecv) return false; const s2 = await app.sealRatchetMessage(healedSend, "after the heal"); const o2 = await app.openRatchetMessage(healedRecv, s2.sealed); return o2 !== null && o2.message === "after the heal" && o2.state === s2.state && await app.openRatchetMessage(send, s2.sealed) === null; })());

  console.log(failures === 0 ? "\nALL TESTS PASS" : `\n${failures} FAILURE(S)`);
  process.exit(failures === 0 ? 0 : 1);
})();
