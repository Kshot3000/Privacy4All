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
check("all main form controls labelled", ["q", "redact-in", "night"].every(id => html.includes(`for="${id}"`)));
check("cache keys present", html.includes("styles.css?v=1") && html.includes("app.js?v=1"));

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

console.log(failures === 0 ? "\nALL TESTS PASS" : `\n${failures} FAILURE(S)`);
process.exit(failures === 0 ? 0 : 1);
