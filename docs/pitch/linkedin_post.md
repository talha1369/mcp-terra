# LinkedIn post (public)

What if you could run a full cloud analysis just by *describing* it?

On a laptop, AI coding assistants have changed how we work: they write code, run
it, read the error, and fix it — a tight loop. But the moment your data lives in
the cloud (for many biomedical researchers, that's the Terra platform), the loop
breaks. The assistant could drop a notebook into cloud storage, but it couldn't
pick a machine, launch it, run the analysis, or debug a failure. You're back to
manual clicking.

I built **mcp-terra** to close that gap — a safety-gated bridge, built on the
open **Model Context Protocol**, that lets an AI assistant drive the whole loop
on Terra:

→ provision the right-sized VM for the workload
→ run the analysis and auto-fix the bugs that surface
→ email a verified report + a short audio explainer of what the results mean

The goal is access: make cloud analysis usable by the thousands of researchers
who aren't cloud experts. You describe the task; the agent does the
infrastructure.

Because it acts on real research data and budgets, I built it safety-first: no
delete or overwrite capability anywhere, a guard that keeps controlled-access
data off external models, a spend cap that stops the VM before a budget is
exceeded, and 392 automated security tests across 52 attack classes —
adversarially reviewed line by line.

If you work in computational biology or cloud research platforms, I'd love your
feedback. 👇

#ComputationalBiology #Bioinformatics #CloudComputing #AI #OpenSource #Genomics #Terra
