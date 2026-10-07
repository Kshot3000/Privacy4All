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
check("all main form controls labelled", ["q", "redact-in", "night", "claim", "secret", "threshold", "snippet-select", "life-night", "life-spend", "life-txs"].every(id => html.includes(`for="${id}"`)));
check("cache keys present", html.includes("styles.css?v=3") && html.includes("app.js?v=5"));
check("dApp permission tool present", html.includes('id="dapp-see"') && html.includes('id="dapp-result"'));
check("ZK claim simulator present", html.includes('id="zk-prover"') && html.includes('id="zk-result"'));
check("ZK simulator honestly labelled a simulation", html.includes("teaching simulation, not a cryptographic proof"));
check("snippet library present", html.includes('id="snippets"') && html.includes('id="snippet-result"'));
check("snippet library honestly labelled not production", html.includes("not production contracts"));
check("DUST lifecycle tool present", html.includes('id="dust-life"') && html.includes('id="dust-life-result"'));
check("DUST lifecycle honestly states no generation rate", html.includes("states no generation rate or time"));

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

console.log(failures === 0 ? "\nALL TESTS PASS" : `\n${failures} FAILURE(S)`);
process.exit(failures === 0 ? 0 : 1);
