import json

from mitre.mitre_agent import analyze_mitre, warm_up

RUNS = 2  # run 1 = cold-ish, run 2+ = what production will look like

behavioral_findings = [
    {"behavior": "internal_network_scan", "score": 30, "confidence": 0.85,
     "evidence": {"unique_targets": 170, "unique_ports": 22, "total_flows": 350,
                  "ports": [80, 443, 445, 8080]}},
    {"behavior": "possible_lateral_movement", "score": 25, "confidence": 0.72,
     "evidence": {"smb_connections": 140, "unique_targets": 105, "destination_port": 445}},
]

host_state = {
    "window_seconds": 300, "flows": 350, "dns_queries": 0, "ldap_queries": 0,
    "smb_connections": 140, "rdp_connections": 0, "unique_targets": 170,
    "unique_ports": 22, "ports": [80, 443, 445, 8080],
}


def ns_to_s(value):
    return (value or 0) / 1e9


print("\nWARM-UP")
print(f"Model load     : {warm_up():.2f} sec (not counted below)")

for run in range(1, RUNS + 1):
    out = analyze_mitre(
        attack_label="Reconnaissance",
        confidence=0.91,
        behavioral_findings=behavioral_findings,
        host_state=host_state,
    )
    m = out["ollama_metrics"]

    print(f"\n==================== RUN {run} ====================")

    if run == 1:
        print("\nCANDIDATES SENT TO QWEN\n")
        for c in out["candidates"]:
            print(c["rank"], c["id"], c["name"])

    print("\nRESULT\n")
    print(json.dumps(out["result"], indent=2, ensure_ascii=False))

    gen_s = ns_to_s(m["eval_duration_ns"])
    tps = (m["eval_count"] or 0) / gen_s if gen_s else 0

    print("\nTIMING\n")
    print(f"Retrieval      : {out['retrieval_seconds']:.4f} sec")
    print(f"Qwen call      : {out['qwen_seconds']:.2f} sec")
    print(f"Total          : {out['elapsed_seconds']:.2f} sec")
    print(f"Model load     : {ns_to_s(m['load_duration_ns']):.2f} sec")
    print(f"Prompt tokens  : {m['prompt_eval_count']}  ({ns_to_s(m['prompt_eval_duration_ns']):.2f} sec)")
    print(f"Generated tok. : {m['eval_count']}  ({gen_s:.2f} sec, {tps:.1f} tok/s)")
