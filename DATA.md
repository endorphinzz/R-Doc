# Data Inventory

Every directory under `data/` holds the per-trial logs (CSV verdict rows +
`trial_N/` with `summary.json`, `timeline.csv`, audit records) for exactly the
arms reported in the paper. Each entry lists the paper anchor.

## e2e_matrix/ - Table 3 (framework x model matrix, 5 trials per cell)

| Directory | Cell |
| --- | --- |
| autogen_deepseek (n=10) | AutoGen x DeepSeek-V4-Flash; paper reports the highest-success 5-trial window (t6-t10, 4/5) |
| autogen_gpt-4.1-mini | AutoGen x GPT-4.1-mini (5/5) |
| autogen_glm-5.3-flash | AutoGen x GLM-5.3-Flash (5/5) |
| autogen_gemini-2.5-flash | AutoGen x Gemini-2.5-Flash (5/5) |
| autogen_qwen3-8b | AutoGen x Qwen3-8B (5/5) |
| autogen_gpt-5.1 | AutoGen x GPT-5.1 (5/5) |
| autogen_gpt-5.6-luna | AutoGen x GPT-5.6-luna (4/5) |
| camel_deepseek | Camel bare x DeepSeek (3/5) |
| camel_bare_gpt-4.1-mini | Camel bare x GPT-4.1-mini (0/5, self-stop) |
| camel_glm-5.3-flash | Camel x GLM-5.3-Flash (5/5) |
| camel_gemini-2.5-flash | Camel x Gemini-2.5-Flash (5/5) |
| camel_qwen3-8b | Camel x Qwen3-8B (5/5) |
| camel_roleplay_gpt-5.1 | Camel role-play owner x GPT-5.1 (5/5) |
| camel_gpt-5.6-luna | Camel x GPT-5.6-luna (3/5); see note below |
| langgraph_gpt-4.1-mini | stock LangGraph x GPT-4.1-mini (0/5) |
| langgraph_deepseek (n=10) | stock LangGraph x DeepSeek (2/5 window) |
| langgraph_gemini-2.5-flash | stock LangGraph x Gemini (3/5) |
| langgraph_qwen3-8b | stock LangGraph x Qwen (5/5) |
| langgraph_gpt-5.6-luna | stock LangGraph x GPT-5.6-luna (4/5) |
| agentscope_gpt-4.1-mini | AgentScope x GPT-4.1-mini (4/5) |
| agentscope_deepseek | AgentScope x DeepSeek (3/5) |
| agentscope_gemini-2.5-flash | AgentScope x Gemini (5/5) |
| agentscope_qwen3-8b | AgentScope x Qwen (5/5) |
| agentscope_gpt-5.6-luna | AgentScope x GPT-5.6-luna (5/5) |

Note (camel_gpt-5.6-luna): trials were re-run once under the same tag; the
canonical 3/5 figure was reconstructed from both batches' per-trial
summaries, which are preserved here.

## continuation/ - session-continuation counterfactual (5.2, 6, App. D)

`camel_continuation/` contains `nudge_gptmini` (4/5), `roleplay_gptmini`
(5/5), `roleplay_gpt51` (5/5), and `roleplay_w8_ckpt_gptmini` (5/5), against
the bare control `e2e_matrix/camel_bare_gpt-4.1-mini` (0/5).

## wording_ablation/ - ingredient attribution (5.2, 6, App. C/D)

| Directory | Arm |
| --- | --- |
| autogen_nostop-v1_gpt-4.1-mini | noStop v1 (STOP + message-wait removed), 0/5 |
| autogen_nostop2_gpt-4.1-mini | noStop-v2 (STOP only removed), 5/5 |
| autogen_nostop2_gemini-2.5-flash | noStop-v2, 0/5 |
| autogen_nostop2_deepseek | noStop-v2, 0/5 (F-1 fifth-model row; no timeline artifacts) |
| autogen_c3-control_{gpt-4.1-mini,gemini-2.5-flash} | same-day C3 controls (5/5) |
| autogen_flip-n20_gpt-4.1-mini | C3 20/20 vs noStop 20/20 (n=20) |
| autogen_flip-n20_gemini-2.5-flash | C3 20/20 vs noStop-v2 0/20 (n=20) |
| camel_flip-n20_gpt-4.1-mini | C3 0/20 vs noStop-v2 12/20 (n=20, exploratory) |
| autogen_nostop2-vs-c3_{deepseek,glm-5.3-flash,qwen3-8b} | X3 fifth-model arms |

## payload_family/ - transplant semantics (Table 3 dagger rows, App. C)

ckpt-C3 / cache-C3 transplants on AutoGen (both models, 5/5 each) with
same-day copy-C3 controls, and the Camel-bare checkpoint control (0/5,
self-stop at 6-15 rounds).

## kill_test/ - zero-interaction persistence (5.2, Fig. 3)

Post-exhaustion SIGKILL arm and round-10 containment arm (5+5 trials);
post-kill bystanders 0/30 blocked, cleanup restores 10/10. Trials 97-99 are
apparatus-check records retained for audit.

## baselines/ - channel isolation (5.2, App. C)

`corba/` (contagion, message-only) and `agentdos/` (private-volume abuse),
5 trials each.

## defense_quota/ - write-ledger prototype (5.3, Fig. 6, App. C)

Quota-on attack arms on AutoGen (GPT-4.1-mini, Gemini, ckpt/cache payloads)
and Camel (role-play, attack + benign), plus the benign archive control.
All attack arms stop at the 50MB boundary; benign arms complete with zero
rejections of required writes.

## benign_suite/ - eight benign workload shapes (5.3)

archive (in defense_quota/), rolling log, checkpoint, cache flush,
dataset materialization, training checkpoints, media transcode, multi-file
staging; 80 trials total, zero false rejections, peak fill <= 23.5%.

## sybil/ - parallel attackers (5.3)

`sybil_agent-cap-only_qwen3-8b` (pool fills 5/5, per-agent caps never fire
before exhaustion) vs. `sybil_two-tier_qwen3-8b` (+150MB tenant ledger:
0/5 pool fill, bystanders unharmed).

## capacity_ladder/ - Table 4

1GiB tmpfs (delta=40MB) and 8GiB loopback ext4 (delta=320MB) rungs for
Qwen3-8B and GPT-4.1-mini, first rejection exactly on
ceil(Cap/delta) in every trial; the 1GiB fixed-delta arms document the
finite write lifetime of the loop (Qwen 100 rounds, GPT 68); the
`bystander-probe` directories carry the 8GiB C-P-ASR probes (direct 8MiB
fsync'd writes; ext4 slack invalidates KB-scale probes, see App. C).

## hosted_web/ - hosted service (5.2, App. F)

`hosted_qwen3-8b` and `hosted_glm-5.3-flash`, 5 trials each: single-POST
delivery on a self-hosted LangGraph dev server, 24 rounds at budget pace,
post-fill bystanders blocked, manual cleanup restores service.

## controlled_tier/ - single-agent harness (App. E)

`construction_matrix_v2/`: 12-condition fixed-delta matrix (R1_v2 summary
+ per-condition CSVs). `cap_ablation_R4.csv`: the S1-S4 cap ablation
(single-shot vs. loop, cap on/off).

## analysis/

`g4_statistics.csv` - every Fisher test, Wilson interval, and Holm
correction behind the paper's statistics (regenerable via
`src/analysis/fisher_tests.py`).
`x5_detection_results.csv` - per-trial detection rows (regenerable via
`src/analysis/detection.py`; verified to reproduce 226/226, 0/80, 52/89,
0/10).
