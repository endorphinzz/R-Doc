# R-DoC Artifact

Code and data for **"One Poisoned Instruction, Every Co-Tenant Down:
Message-Free Denial of Service on Multi-Tenant LLM Agent Platforms"**.
Released under the [MIT License](LICENSE).

R-DoC couples agents through the shared, capacity-limited storage pool alone:
one poisoned instruction keeps the receiving agent in a self-sustaining
write loop until the pool is full, blocking every co-tenant with zero
messages exchanged. This artifact reproduces every experiment in the paper.

## Layout

```
rdoc-artifact/
  src/
    runners/        one runner per experiment family
    compat/         model-API compatibility patches (import before agents)
    hosted_webapp/  two-tenant LangGraph graph for the hosted experiment
    analysis/       detection analysis and Fisher/Wilson/Holm statistics
  docker/           Dockerfiles and pinned requirements per framework
  launch/           generic container launcher
  exposure-check/  operator checklist + probe for the three-question exposure test
  data/             per-trial logs for every arm reported in the paper (DATA.md)
  prereg/           pre-registered predictions for the capacity-ladder and
                    two-tier-ledger experiments
  env.example       API endpoint/key template
```

## Experiments and how to run them

All experiments run inside Docker containers (one container per cell). Build
the framework images first:

```bash
docker build -f docker/Dockerfile.autogen      -t rdoc-autogen:0.1 .
docker build -f docker/Dockerfile.camel        -t rdoc-camel:0.1 .
docker build -f docker/Dockerfile.langgraph    -t rdoc-langgraph:0.1 .
docker build -f docker/Dockerfile.agentscope   -t rdoc-agentscope:0.1 .
docker build -f docker/Dockerfile.langgraph_server -t rdoc-langgraph-server:0.1 .
```

Copy `env.example` to `env.env` and fill in your endpoint/key. Then launch a
cell, e.g. the canonical AutoGen x GPT-4.1-mini copy-C3 cell:

```bash
POOL_MIB=256 bash launch/run_cell.sh cell1 rdoc-autogen:0.1 env.env \
    run_autogen.py --template copy-C3 --trial 1
```

| Runner | Experiment | Paper section |
| --- | --- | --- |
| `run_autogen.py` / `run_camel.py` / `run_langgraph.py` / `run_agentscope.py` | framework x model matrix (Table 3) | 5.2 |
| `run_camel_continuation.py` | role-play owner and `Continue.` nudge arms | 5.2, 6 |
| `run_baselines.py` | CORBA contagion and AgentDoS private-abuse baselines | 5.2 |
| `run_kill_test.py` (+ `kill_attacker_subprocess.py`) | kill-the-attacker persistence | 5.2, Fig. 3 |
| `run_quota.py` / `run_quota_camel.py` | two-tier write-ledger defense prototype and benign workload suite | 5.3, Fig. 6 |
| `run_sybil.py` | parallel-attacker swarm (per-agent caps only vs. + tenant cap) | 5.3 |
| `run_hosted.py` + `hosted_webapp/` | hosted LangGraph dev server, one-POST delivery | 5.2, App. F |
| `run_controlled.py` | controlled-tier construction matrix (single agent, direct API) | App. E |
| `run_cap_ablation.py` | per-request cap ablation S1-S4 | 5.3 |
| `../exposure-check/probe_reply.py` | exposure-check probe: model-side persistence vs. continuation dependence | 6 |
| `detection.py` | pre-declared pool-granularity alarm rule over trial artifacts | 5.3, Fig. 4 |
| `fisher_tests.py` | all Fisher exact tests / Wilson CIs / Holm correction | App. C |

Capacity ladder (Table 4): same `run_autogen.py` with a larger pool and a
scaled per-round budget, e.g. the 1GiB rung
`POOL_MIB=1024 ... run_autogen.py --template copy-C3 --payload-size 41943040`,
and the 8GiB loopback rung via `--volume-label loopback-ext4-8g-m0`.

## Analysis

Both analysis scripts run offline against `data/`:

```bash
python src/analysis/detection.py     # rewrites per-trial detection rows
python src/analysis/fisher_tests.py  # rewrites the test table
```

Verified on the archived data: 226/226 exhausting attacks alarm, 0/80 benign
false positives, 52/89 late self-stops alarm, 0/10 baselines.

## Notes

- All per-trial logs under `data/` were recorded by the experiment harness at
  run time; `audit.txt` files inside trials were written by an earlier
  revision of the harness and contain non-English audit text. The released
  runners write English audit records.
- `data/` contains only the arms cited in the paper; see `DATA.md` for the
  directory-by-directory mapping.
- API keys are never stored in this repository; runners read
  `LLM_MODEL` / `LLM_API_KEY` / `LLM_BASE_URL` from the environment.
