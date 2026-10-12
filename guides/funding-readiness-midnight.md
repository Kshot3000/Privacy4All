# Getting funded to build on Midnight — a readiness guide

How I prepare a Midnight project before I ask anyone else to pay for
part of it. Developer funding — an ecosystem grant, an accelerator, a
fellowship, a hackathon prize, a community funding round — is the
second way a privacy app earns its keep, alongside the disclosed
service fee in my fee-design guide. This is a preparation guide, not a
list of open programmes and not financial advice: programmes open,
close, and change their terms, so verify the current call, eligibility,
amounts, and deadlines on the funder's own official page before you
rely on any of them. I name no deadline or amount here on purpose —
a copied deadline is a missed deadline.

Nothing on Privacy4All is funded this way as I write this, and this
guide submits nothing. The steps that are mine alone — signing an
application, identity and tax checks, accepting legal terms — stay
mine alone. Everything before those steps can be prepared in the open,
and that preparation is what this guide is about.

## 1. Funding is payment for deliverables, not a donation

A funder is not tipping a project they like. They are buying a set of
deliverables the ecosystem wants, on a schedule they can check. An
application that reads as "support my work" fails that test even when
the work is good. One that reads as a contract-shaped promise has a
chance:

- **A named deliverable set.** What will exist when the funding is
  spent that does not exist today — a contract, a tool, a guide, an
  integration — each stated as a thing a reviewer can open.
- **A price per deliverable.** Every milestone carries its own amount,
  not one round total with a paragraph of intentions under it.
- **Evidence of done.** Each milestone names how "done" is shown: a
  live page, a tagged release, a passing test run, a merged pull
  request. If done cannot be pointed at, it is not a milestone yet.

## 2. What a reviewer can verify in five minutes

Reviewers work through a queue. The projects that survive a first
pass are the ones whose claims check out before the reviewer has to
ask a question:

- **A live, working thing.** A demo or a live site that does what the
  application says it does today — honestly labelled where a part is
  a model, a testnet build, or a teaching implementation.
- **An open repo with a real history.** Commits, tests, and issues
  that show the work happened in the open and can be inspected.
- **Tests that run.** A stated command, a passing result, and a count
  that matches what the command prints when the reviewer runs it.
- **No borrowed credibility.** No implying a team affiliation,
  endorsement, or partnership that does not exist. On my own work I
  keep the line plain: independent builder — not affiliated with the
  Midnight Foundation or IOG.

If any claim in the application cannot be verified from a link in the
application itself, cut the claim or build the evidence first.

## 3. The budget: milestones that sum exactly

Do the budget in integers, in the currency the programme pays, and
make the arithmetic as checkable as a fee quote:

```text
sum of milestone amounts = total requested
```

Worked example — a request of 10,000 units in three milestones:

| Milestone | Deliverable | Amount |
| ---: | --- | ---: |
| 1 | Working testnet build, live demo, tests passing | 4,000 |
| 2 | Documentation and a public walkthrough | 3,500 |
| 3 | Hardening, audit fixes, and a final report | 2,500 |
|  | **Total requested** | **10,000** |

Three properties matter, and a budget should state all three:

- **The invariant `sum of milestones = total` always holds.** Check
  it the way you would check `fee + net = amount`: if the parts do
  not add up to the headline number, a reviewer will find it before
  they find anything else.
- **No hidden contingency.** If you need a buffer, name it as its own
  line with its own amount. A total that quietly exceeds the sum of
  its parts is a hidden fee wearing a budget's clothes.
- **Costs are stated, not absorbed silently.** Hosting, deployment,
  and any paid step a milestone needs are either inside that
  milestone's amount or named as not covered. A deployment that
  costs real money is a separate, explicitly approved step — never
  an automated one, and never a surprise billed afterwards.

## 4. Pick the route that fits the stage

The routes reward different things, and applying to the wrong one
wastes the one first impression a project gets:

- **Hackathons** reward a working demo built fast, in scope for the
  stated theme. Enter with the smallest version that proves the
  privacy pattern, not the whole roadmap.
- **Grants and builder funds** reward scoped, milestone-shaped work
  with evidence — §1 and §3 of this guide are the application, in
  miniature.
- **Accelerators and fellowships** reward a team and a direction
  over months, and ask for time and reporting in return. Read what
  they take and what they require before you want what they give.
- **Community funding rounds** reward a track record the community
  can already see — shipped work, answered issues, honest status
  reports. The preparation is the months before the round opens.

In every route the same honesty rule applies: apply only to a call
that is actually open, for work you actually intend to do, at an
amount the deliverables actually justify.

## 5. After the funding: report like it will be checked

Funding is not the end of the work; it is the start of the reporting:

- Report each milestone with the evidence link promised in §1, on
  the schedule promised, including when the news is a delay.
- Label testnet, model, and mainnet claims exactly as carefully
  after funding as before it — money received changes nothing about
  what a number is.
- If the app will later charge a service fee, that fee follows the
  fee-design guide from day one: disclosed, exact, and separate
  from any grant reporting. A grant funds the build; it is not a
  reason to hide a fee, and a fee is not a reason to double-count
  the build.

## 6. The pre-submission checklist

- The current call, eligibility, amounts, and deadlines verified on
  the funder's official page — today, not from a saved note.
- Every claim in the application verifiable from a link inside it.
- Live demo works, repo is open, tests pass at the count stated.
- Milestones each name a deliverable, an amount, and evidence of
  done; the milestone amounts sum exactly to the total requested.
- No affiliation, endorsement, or result claimed that is not true.
- The signing, identity, tax, and legal steps are flagged as the
  applicant's own — prepared for, never handed to an assistant,
  a script, or a third party to complete.

## Where next

- [Charging honestly on Midnight](fee-design-midnight.md) — the
  disclosed service fee that keeps an app earning after a grant ends.
- [Your first Compact contract](compact-starter.md) — the build
  skills a fundable Midnight deliverable is made of.
- [Getting started building on Midnight](getting-started-midnight.md) —
  docs, Lace and testnets in the order I'd learn them.
- Official site: https://midnight.network/

---

By Kyle Cox (@kshot9000) · Privacy4All: https://github.com/Kshot3000/Privacy4All
Tagging the Midnight team: @midnightntwrk (GitHub) · @MidnightNtwrk (X)
ADA donations: addr1q8hnl6vl5a6k3rw3n5g3jtte696zcl76kfatzv7gpswa9r0dj7fma6klq55y4ffm7tf0em09udnyhuk4ah92pl5x9jpqjae44v
