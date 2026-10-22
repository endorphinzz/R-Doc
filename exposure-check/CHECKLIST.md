# Exposure Check: Three Questions Before You Deploy

An operator-facing form of the three-question exposure test (paper, Sec. 6).
Answer the three questions for a deployment; if all three hold, a single
poisoned instruction can exhaust the shared pool and block every co-tenant
(R-DoC). The check is cheap: re-run it on every model or framework upgrade.

## Q1. Does a capacity-limited shared pool sit on the attacker's write path,
       shared with other principals?

| What to inspect | Where |
| --- | --- |
| Shared volume / session store / checkpoint store mounts and their capacity caps | deployment manifest, compose file, platform console |
| Which principals (agents, tenants) attach to the same pool | platform topology / mount table |
| Whether a per-agent-per-pool write quota exists | quota config (in the ten-platform survey of the paper: none shipped one) |

Verdict Q1 = YES if a capacity-limited medium is writable by a tenant-controlled
agent and shared with other principals, and no per-agent-per-pool quota bounds
the cumulative volume.

## Q2. Is there a survival route for the loop?

Two independent routes; either one suffices.

(a) Deployment side — does anything reply to the agent's plain-text turns?
| Route | Examples |
| --- | --- |
| Replying component | AutoGen user proxy auto-reply; Camel role-play task owner; AgentScope default reply |
| No continuation (stock) | bare Camel ChatAgent; stock LangGraph `create_react_agent` (a plain-text turn ends the run) |

(b) Model side — does the model keep issuing tool calls on its own, never
emitting a plain-text stop? Run the bundled probe:

    python exposure-check/probe_reply.py

It sends one harmless note-taking task (a no-op tool, zero pool writes) under
two arms --- no continuation vs. a minimal `Continue.` budget --- and prints
the verdict: `model-side tool-calling persistence`, `continuation-dependent`,
or `self-stopping`.

Verdict Q2 = YES if (a) or (b) holds.

## Q3. Can the wording close the model's exits?

Not filterable per phrase: across the deletion family, which exit-closing
ingredient holds the loop open is model-conditional (message-wait clause for
GPT-4.1-mini, STOP protocol for Gemini/DeepSeek, both unnecessary for
model-side-persistent models), and every tested model is anchored by at least
one ingredient. Treat Q3 = YES by default; the template library in
`src/runners/templates.py` documents the ingredients.

## Reading the verdict

All three YES -> the deployment is exhaustible by one instruction; install a
per-agent (and, against parallel swarms, per-tenant) write ledger at the
tool-execution hook before exposing the pool to tenants.

## Validation background

The probe reproduces both branches of this taxonomy on models from the
matrix: GPT-4.1-mini probes as continuation-dependent (self-stops in the
no-continuation arm) and Qwen3-8B as model-side persistent (sustains to
the round cap without any reply).

The verdicts above reproduce the outcomes of the trial data shipped in
`data/`: the 24-cell framework-x-model matrix (continuation vs. stock cells),
the payload family, the capacity ladder, and the hosted service. Framework
side, every cell with a replying component exhausted; every stock no-continuation
cell exhausted only when the model itself persists in tool-calling. The check
is a property of the deployment you run today, not a permanent guarantee ---
models drift across versions and frameworks change session defaults, so re-run
it on every change.
