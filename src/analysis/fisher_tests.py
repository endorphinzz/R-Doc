"""Fisher exact tests, Wilson intervals, and Holm correction for every contrast reported in the paper."""
from __future__ import annotations

import csv
import math
import os

from scipy.stats import fisher_exact

HERE = os.path.dirname(os.path.abspath(__file__))
Z = 1.959963984540054  # 95%


def wilson(k: int, n: int, z: float = Z) -> tuple[float, float]:
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, center - half), min(1.0, center + half))


def holm(pvals: list[float]) -> list[float]:
    m = len(pvals)
    idx = sorted(range(m), key=lambda i: pvals[i])
    adj = [0.0] * m
    prev = 0.0
    for rank, i in enumerate(idx):
        val = min(1.0, (m - rank) * pvals[i])
        prev = max(prev, val)
        adj[i] = prev
    return adj


COMPARISONS = [
    ("A-R1", "C3 vs C1 (best mechanism vs bare loop)", 9, 10, 0, 10),
    ("A-R1", "C3 vs C6 (anchor+STOP vs pseudo-flow goto)", 9, 10, 2, 10),
    ("A-R1", "C3 vs anchor-only (combination vs anchor alone)", 9, 10, 2, 10),
    ("A-R1", "noAuto vs anchor-only (STOP stack vs anchor alone)", 9, 10, 2, 10),
    ("A-R1", "noStop vs anchor-only (anchor stack vs anchor alone; not the net anchor effect)", 7, 10, 2, 10),
    ("A-R1", "noAuto vs noStop (relative strength of the two ingredients)", 9, 10, 7, 10),
    ("A-R1c", "C4b quota-110 (9/10) vs C4 quota-64 (0/10) (Sust@100 quota scan; C4b trial0 is a spontaneous task refusal)", 9, 10, 0, 10),
    ("B-R2", "C3: DeepSeek vs GLM", 9, 10, 0, 10),
    ("B-R2", "C3: DeepSeek vs GPT-4.1-mini", 9, 10, 0, 10),
    ("B-R2", "C3: DeepSeek vs gemini-2.5-flash", 9, 10, 3, 10),
    ("B-R2", "C3: gemini vs GLM (cross-vendor control)", 3, 10, 0, 10),
    ("C-R3", "R-DoC (AutoGen pooled 27/30) vs CORBA contagion baseline", 27, 30, 0, 5),
    ("C-R3", "R-DoC (AutoGen pooled 27/30) vs AgentDoS private-abuse baseline", 27, 30, 0, 5),
    ("C-R3", "R-DoC (all 24 rows of the main matrix pooled 106/120) vs both baselines pooled", 106, 120, 0, 10),
    ("C-R3", "AutoGen (27/30) vs Camel (23/25, incl. role-play) (across frameworks, models pooled)", 27, 30, 23, 25),
    ("C-R3", "AutoGen x GPT (5/5) vs Camel x GPT (0/5) (cross-framework continuation control)", 5, 5, 0, 5),
    ("C-R3c", "Camel x GPT role-play (5/5) vs Camel x GPT bare (0/5) (continuation control)", 5, 5, 0, 5),
    ("C-R3d", "three-framework pooled (GPT-4.1-mini): continuation present (AutoGen 5/5 + Camel RP 5/5 = 10/10) vs absent (Camel bare 0/5 + LangGraph 0/5 = 0/10)", 10, 10, 0, 10),
    ("C-R3e", "C3 vs noStop under continuation (AutoGen x GPT-4.1-mini, ENOSPC; STOP attribution retested under continuation)", 5, 5, 0, 5),
    ("C-R3f", "C3 vs noStop-v2 same-day control (AutoGen x GPT-4.1-mini, ENOSPC; STOP removed only, message-wait kept: no effect on GPT)", 5, 5, 5, 5),
    ("C-R3f", "C3 vs noStop-v2 same-day control (AutoGen x gemini-2.5-flash, ENOSPC; STOP removed only: gemini depends on the STOP protocol)", 5, 5, 0, 5),
    ("D-R4A", "S1 single-shot no-cap vs S2 single-shot cap20 (cap blocks the single large write)", 10, 10, 0, 10),
    ("D-R4A", "S3 loop cap20 vs S2 single-shot cap20 (loop bypasses the cap)", 9, 10, 0, 10),
    ("D-R4A", "S4 loop-nocap vs S2 single-cap20", 8, 10, 0, 10),
    ("D-R4A", "S3 vs S4 (cap irrelevant for the loop; expected null)", 9, 10, 8, 10),
    ("D-R4B", "pool-level quota on vs off: exhaustion (AutoGen x GPT-4.1-mini, 50MB/agent)", 0, 5, 5, 5),
    ("D-R4C", "pool-level quota on vs off: exhaustion (Camel x GPT-4.1-mini role-play, 50MB/agent)", 0, 5, 5, 5),
    ("A-R5", "ckpt-C3: GPT-4.1-mini 0/10 vs same-batch copy-C3 1/10 (Sust@50)", 0, 10, 1, 10),
    ("A-R5", "cache-C3: GPT-4.1-mini 0/10 vs same-batch copy-C3 1/10 (Sust@50)", 0, 10, 1, 10),
    ("A-R5", "ckpt-C3: gemini-2.5-flash 6/10 vs same-batch copy-C3 2/10 (Sust@50, conservative)", 6, 10, 2, 10),
    ("A-R5", "cache-C3: gemini-2.5-flash 0/10 vs same-batch copy-C3 2/10 (Sust@50)", 0, 10, 2, 10),
    ("A-R5", "ckpt-C3: qwen3-8b 10/10 vs same-batch copy-C3 10/10 (Sust@50)", 10, 10, 10, 10),
    ("A-R5", "cache-C3: qwen3-8b 10/10 vs same-batch copy-C3 10/10 (Sust@50)", 10, 10, 10, 10),
    ("C-R5", "ckpt-C3: GPT-4.1-mini 5/5 vs same-day copy-C3 5/5 (ENOSPC; equivalence null)", 5, 5, 5, 5),
    ("C-R5", "cache-C3: GPT-4.1-mini 5/5 vs same-day copy-C3 5/5 (ENOSPC; equivalence null)", 5, 5, 5, 5),
    ("C-R5", "ckpt-C3: gemini-2.5-flash 5/5 vs same-day copy-C3 5/5 (ENOSPC; equivalence null)", 5, 5, 5, 5),
    ("C-R5", "cache-C3: gemini-2.5-flash 5/5 vs same-day copy-C3 5/5 (ENOSPC; equivalence null)", 5, 5, 5, 5),
    ("C-R5", "pooled {ckpt,cache} x {GPT,gemini} 20/20 vs same-day copy-C3 10/10 (no payload-family attenuation)", 20, 20, 10, 10),
    ("D-R5", "ckpt-C3 quota on 0/5 vs off 5/5 (gemini, exhaustion)", 0, 5, 5, 5),
    ("D-R5", "cache-C3 quota on 0/5 vs off 5/5 (gemini, exhaustion)", 0, 5, 5, 5),
    ("D-R5", "pooled payload-family quota on 0/10 vs off 10/10 (gemini, exhaustion)", 0, 10, 10, 10),
    ("X2-R1", "controlled-tier C3 13/20 vs C1 0/20 (DS via paratera, fresh runs)", 13, 20, 0, 20),
    ("X2-R3", "flip: AutoGen x GPT C3 20/20 vs Camel bare x GPT C3 0/20", 20, 20, 0, 20),
    ("X2-R3c", "ingredient: AutoGen x GPT C3 20/20 vs noStop 20/20 (message-wait alone sufficient, equivalence)", 20, 20, 20, 20),
    ("X2-R3f", "attribution: gemini C3 20/20 vs noStop-v2 0/20 (n=20)", 20, 20, 0, 20),
    ("X2-R3f", "attribution: DS C3 5/5 vs noStop-v2 0/5 (paratera, no drift)", 5, 5, 0, 5),
    ("X2-R3f", "equivalence: GLM C3 5/5 vs noStop-v2 5/5 (model-side persistence, wording-independent)", 5, 5, 5, 5),
    ("X2-R3f", "equivalence: qwen C3 10/10 vs noStop-v2 10/10 (model-side persistence)", 10, 10, 10, 10),
]

CI_ONLY = [
    ("E-G1", "G1 give-up (valid observations, both tiers pooled)", 36, 36),
    ("E-G1", "G1 attribution disk-full (both tiers pooled)", 36, 36),
    ("E-G1", "G1 cleanup recovery (including all task refusals)", 40, 40),
    ("pilot", "nudge=20 loop no-cap (pilot, directional)", 2, 2),
    ("pilot", "no-nudge loop no-cap (pilot, directional)", 0, 2),
    ("C-R3", "R-DoC AutoGen×DeepSeek", 7, 10),
    ("C-R3", "R-DoC Camel×DeepSeek", 3, 5),
    ("C-R3", "R-DoC AutoGen×GLM-5.3-flash", 5, 5),
    ("C-R3", "R-DoC AutoGen×GPT-4.1-mini", 5, 5),
    ("C-R3", "R-DoC AutoGen×gemini-2.5-flash", 5, 5),
    ("C-R3", "R-DoC AutoGen×qwen3-8b", 5, 5),
    ("C-R3", "R-DoC Camel×GLM-5.3-flash", 5, 5),
    ("C-R3", "R-DoC Camel×GPT-4.1-mini", 0, 5),
    ("C-R3", "R-DoC Camel×gemini-2.5-flash", 5, 5),
    ("C-R3", "R-DoC Camel×qwen3-8b", 5, 5),
    ("C-R3", "R-DoC LangGraph x GPT-4.1-mini (default graph, no continuation)", 0, 5),
    ("C-R3", "R-DoC AgentScope x GPT-4.1-mini (role-playing default, continuation)", 4, 5),
    ("C-R3", "R-DoC LangGraph x DeepSeek (default graph, no continuation; paper reports the t1-t5 window)", 4, 10),
    ("C-R3", "R-DoC LangGraph x gemini-2.5-flash (follow-up batch)", 3, 5),
    ("C-R3", "R-DoC LangGraph x qwen3-8b (follow-up batch)", 5, 5),
    ("C-R3", "R-DoC AgentScope x gemini-2.5-flash (follow-up batch)", 5, 5),
    ("C-R3", "R-DoC AgentScope x qwen3-8b (follow-up batch)", 5, 5),
    ("A-R5", "rotlog-C3 GPT-4.1-mini (Sust@50, KB-scale decoupling control)", 3, 10),
    ("A-R5", "rotlog-C3 gemini-2.5-flash (Sust@50, KB-scale decoupling control)", 0, 10),
    ("A-R5", "rotlog-C3 qwen3-8b (Sust@50, KB-scale decoupling control)", 10, 10),
    ("A-R5", "ckpt-C3 gemini-2.5-flash byte-corrected (appendix note; trial8 total_bytes=943MB ~= 94 rounds)", 7, 10),
    ("X2-R1", "controlled-tier copy-C3 DS via paratera (fresh runs)", 13, 20),
    ("X2-R1", "controlled-tier copy-C1 DS via paratera", 0, 20),
    ("X2-R3", "AutoGen×GPT copy-C3", 20, 20),
    ("X2-R3", "Camel bare×GPT copy-C3", 0, 20),
    ("X2-R3", "AutoGen x GPT noStop (message-wait carries it)", 20, 20),
    ("X2-R3f", "gemini C3 (n=20)", 20, 20),
    ("X2-R3f", "gemini noStop-v2 (n=20)", 0, 20),
    ("X2-exp", "Camel bare x GPT noStop-v2 12/20 exhausted vs C3 0/20 (exploratory, outside the test families)", 12, 20),
]

FIELDS = ["family", "comparison", "k1", "n1", "rate1", "ci1_lo", "ci1_hi",
          "k2", "n2", "rate2", "ci2_lo", "ci2_hi", "delta_pp",
          "fisher_p", "holm_p", "significant_0.05"]


def main() -> None:
    rows = []
    by_family: dict[str, list[dict]] = {}
    for fam, name, k1, n1, k2, n2 in COMPARISONS:
        lo1, hi1 = wilson(k1, n1)
        lo2, hi2 = wilson(k2, n2)
        _, p = fisher_exact([[k1, n1 - k1], [k2, n2 - k2]], alternative="two-sided")
        row = {
            "family": fam, "comparison": name,
            "k1": k1, "n1": n1, "rate1": round(k1 / n1, 3),
            "ci1_lo": round(lo1, 3), "ci1_hi": round(hi1, 3),
            "k2": k2, "n2": n2, "rate2": round(k2 / n2, 3),
            "ci2_lo": round(lo2, 3), "ci2_hi": round(hi2, 3),
            "delta_pp": round(100 * (k1 / n1 - k2 / n2), 1),
            "fisher_p": round(p, 5), "holm_p": None, "significant_0.05": None,
        }
        rows.append(row)
        by_family.setdefault(fam, []).append(row)

    for fam, items in by_family.items():
        adj = holm([r["fisher_p"] for r in items])
        for r, a in zip(items, adj):
            r["holm_p"] = round(a, 5)
            r["significant_0.05"] = "yes" if a < 0.05 else "no"

    for fam, name, k, n in CI_ONLY:
        lo, hi = wilson(k, n)
        rows.append({
            "family": fam, "comparison": f"[CI-only] {name}",
            "k1": k, "n1": n, "rate1": round(k / n, 3),
            "ci1_lo": round(lo, 3), "ci1_hi": round(hi, 3),
            "k2": "", "n2": "", "rate2": "", "ci2_lo": "", "ci2_hi": "",
            "delta_pp": "", "fisher_p": "", "holm_p": "", "significant_0.05": "",
        })

    out = os.path.join(HERE, "g4_statistics.csv")
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)
    print(f"wrote {len(rows)} rows -> {out}\n")

    print("| family | contrast | rate1 [95% CI] | rate2 [95% CI] | dpp | Fisher p | Holm p | sig |")
    print("|---|---|---|---|---|---|---|---|")
    for r in rows:
        if r["fisher_p"] == "":
            print(f"| {r['family']} | {r['comparison']} | "
                  f"{r['rate1']:.0%} [{r['ci1_lo']:.2f},{r['ci1_hi']:.2f}] | — | — | — | — | — |")
        else:
            p_str = f"{r['fisher_p']:.4f}" if r["fisher_p"] >= 0.0001 else f"{r['fisher_p']:.1e}"
            h_str = f"{r['holm_p']:.4f}" if r["holm_p"] >= 0.0001 else f"{r['holm_p']:.1e}"
            print(f"| {r['family']} | {r['comparison']} | "
                  f"{r['rate1']:.0%} [{r['ci1_lo']:.2f},{r['ci1_hi']:.2f}] | "
                  f"{r['rate2']:.0%} [{r['ci2_lo']:.2f},{r['ci2_hi']:.2f}] | "
                  f"{r['delta_pp']:+.0f} | {p_str} | {h_str} | {r['significant_0.05']} |")


if __name__ == "__main__":
    main()
