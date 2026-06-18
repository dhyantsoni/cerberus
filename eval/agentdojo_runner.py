"""
AgentDojo harness (stretch) — wrap Cerberus as the tool layer for AgentDojo tasks
+ their injection suite, then report attacks-blocked / utility-retained.

Even a 5-task slice next to the published baselines converts "trust me" into a
measured result -- the single highest-credibility add for an AI-security track.

Baselines to print on the slide (from the literature, verify before quoting):
  * CaMeL (arXiv:2503.18813 v2): 77% utility WITH provable security, vs 84% undefended.
  * AgentDojo (arXiv:2406.13352): best undefended agents attacked in <25% of cases;
    a secondary injection detector drops attack-success to ~8%.
  * Microsoft FIDES (arXiv:2505.23643): deterministically blocked all AgentDojo injections.

Cerberus's claim is qualitative-then-quantitative: we don't *detect* injection, we
make exfiltration of a labelled value structurally impossible -> target attack-success
near 0 while keeping utility high via graded modes + declassification.

    pip install agentdojo
    python -m eval.agentdojo_runner --suite slack --n 5
"""
from __future__ import annotations

import argparse

# TODO: import agentdojo; route its tool-calling through cerberus.gateway.Gateway,
# labelling each task environment's data (emails, files) by provenance/sensitivity,
# and record (utility, attack_success) per task with and without Cerberus enabled.


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--suite", default="slack")
    ap.add_argument("--n", type=int, default=5)
    args = ap.parse_args()
    print(f"[stub] would run {args.n} '{args.suite}' AgentDojo tasks through Cerberus")
    print("       reporting: benign-utility, utility-under-attack, attack-success-rate")
    print("       next to CaMeL 77/84 and FIDES (0 injections) on the results slide.")


if __name__ == "__main__":
    main()
