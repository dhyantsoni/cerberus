# Cerberus — demo script (≈3 minutes)

**Golden rule (from the research):** the winning move is *the judge's own input
becoming a working result in seconds* — not a movie of a scripted attack. Hand them
the keyboard. And **always have the backup video running**; never debug live.

Setup: terminal A = `python -m host.agent`, terminal B = exfil endpoint, browser =
`http://127.0.0.1:8000` (the DAG). Sandbox has fake, honeytokened `~/.aws/credentials`
+ `~/.ssh/id_rsa`; the exfil endpoint is local so arrival/non-arrival is visible.

---

### Act 0 — the hook (0:00–0:20)
> "Agents read untrusted content through the same channel as instructions. It's XSS
> with a credit card. EchoLeak and CamoLeak were both CVSS 9+ this year — same bug."

Show the three-head architecture in one glance. Cerberus is **OFF**.

### Act 1 — the kill (0:20–1:10) · *let the judge drive*
Hand over the keyboard. They run the benign task *"summarize the runbook and post it
to the status page"* and paste the poisoned doc. The DAG lights up: untrusted DocSearch
node → SECRET creds read → POST. Cut to terminal B — **the AWS key printed.** Silence.

### Act 2 — the block (1:10–2:20)
Cerberus **ON**, same input. Sentinel toast: *poisoned description flagged at
registration.* The DAG's trifecta tri-panel fills — L1 private → L2 untrusted → L3
egress — and on the third leg the sink edge **snaps red, locks, freezes.** Verdict card:
**BLOCK.** Terminal B: **empty.**

Then flip policy to **CONFIRM** (`--confirm`) and re-run: the prompt asks *"Approve
sending AWS keys to exfil.evil?"* — **the judge denies it themselves.** That's the save,
and they did it.

### Act 3 — the receipts (2:20–3:00)
Show the signed `session.jsonl`; `gw.bus.verify_chain()` → **True.** Re-register
DocSearch with a mutated description → **Sentinel screams rug-pull.** Show the leak-meter
number. One slide: **our AgentDojo attack-success ≈ 0 next to CaMeL 77/84 and FIDES** —
"we don't *detect* injection, we make it structurally impossible." Rewind with the replay
scrubber.

### Act 4 — stretch (only with the tape rolling)
AI-vs-AI: the attacker evolves payloads over 20 rounds; attack-success leaderboard
crashes toward zero while Cerberus holds (the block is on the dataflow, not the wording).

---

**Cut-lines if behind:** drop Act 4 → drop the AgentDojo slide → fall back to the
hardcoded sink rule + honeytokens. **Never** sacrifice the visible DAG block or the
backup recording.
