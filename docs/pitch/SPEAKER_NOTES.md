# mcp-terra — 5-minute pitch (speaker script)

Open `docs/pitch/index.html` in a browser (arrow keys to advance; `S` for speaker
view). Target ~50 seconds per slide = ~5 minutes. Audience: general Terra users.

---

### Slide 1 — Title (~20s)
> "Hi — this is **mcp-terra**. The one-liner: it lets an AI assistant *run, fix,
> and explain* your Terra analyses — without you leaving the chat. It's built
> safety-first: no delete anywhere, controlled-access aware, and it ships with
> 382 passing security tests."

### Slide 2 — Motivation (~55s)
> "Here's the gap. On your **laptop**, a coding assistant like Claude Code writes
> your code *and runs it* — reads the error, fixes it, runs again. That tight
> loop is why it's useful.
>
> On **Terra**, that same assistant can only copy a notebook into your bucket.
> It can't pick a machine, start a VM, run the notebook, or fix a failure. So you
> drop back to manual clicking — choose a machine type, wait for it to boot, open
> Jupyter, run, read the traceback, repeat. For the thousands of Terra users who
> aren't cloud experts, *that's the wall.*"

### Slide 3 — Main goal (~55s)
> "Our goal: give Terra a **credentialed, safety-gated bridge** so the AI can
> drive the *whole loop* — the same experience you have locally.
>
> It **provisions** the right-sized VM for your notebook, **runs** it, **auto-fixes**
> the bugs that come up and re-runs, and then **explains** the results: it emails
> you a verified report *plus* a NotebookLM-style **audio** walkthrough of what
> the results mean and which bugs it fixed and how.
>
> And the point is *who* this is for — every Terra user. No MCP, cloud, or DevOps
> background. You type a sentence; the agent does the cloud."

### Slide 4 — Methods & execution (~60s)
> "Under the hood it's an **MCP server** wrapping the Terra stack — Rawls,
> Leonardo, Sam, Agora, Cromwell, and gsutil — exposing 45 credentialed tools.
> Jobs actually run via a small **on-VM runner** that only executes
> **HMAC-signed** specs, so a bucket co-member can't forge or replay a job.
>
> The thing I most want to land: **safety is enforced in code, not docs.** There's
> *no delete or overwrite primitive anywhere*. A controlled-access guard keeps
> genomic data from ever reaching a public model. A spend cap makes the VM
> self-stop before your dollar limit. It's aware of Terra's 24-hour session
> window, so long runs don't hit a credential cliff. And it runs jobs in
> parallel — across multiple VMs, via WDL scatter, and now multiple jobs on one
> VM."

### Slide 5 — Results & demo (~55s)
> "And it works today. One command installs it — as a Claude Code plugin or a
> script. Then you say, in plain English: *'Run my notebook end-to-end via the
> auto-fix loop, auto-stop on success, email me the verified report.'*
>
> It provisions a VM, runs, fixes the bugs, re-runs until it succeeds, and emails
> you the verified report and the audio explainer. We've tested the live path
> against real Terra. Next up: a broader skill library and an org-wide plugin
> marketplace."

### Slide 6 — Why you can trust it / close (~35s)
> "Last thing — trust. **382** security tests across **52** attack classes,
> **zero** delete primitives, adversarially reviewed line by line. Every
> data-returning tool is guarded, every job is signed, every action is audited.
>
> So: **type a sentence, get a finished, explained analysis — safely.** Thank you."

---

**If you have 30 extra seconds for a live demo:** run `terra_health` to show it's
connected, then kick off a one-line notebook run and show the email + audio land.

**Q&A one-liners**
- *"What if I don't want it touching my email/Slack?"* — Both are opt-in; nothing
  is sent unless you configure SMTP / a Slack webhook.
- *"Controlled-access data?"* — A guard (off by default) blocks raw data egress to
  the model; the on-VM compute + all diagnostics still work.
- *"Can it delete my work?"* — No. There is no delete or overwrite primitive at
  any layer, by design.
