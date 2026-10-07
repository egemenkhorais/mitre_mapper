import time

from mitre.mitre_retriever import MitreRetriever
from mitre.mitre_multi_retriever import retrieve_candidates

behavioral_findings = [
    {
        "behavior": "internal_network_scan",
        "score": 30,
        "confidence": 0.85,
        "evidence": {
            "unique_targets": 170,
            "unique_ports": 22,
            "total_flows": 350,
            "ports": [80, 443, 445, 8080],
        },
    },
    {
        "behavior": "possible_lateral_movement",
        "score": 25,
        "confidence": 0.72,
        "evidence": {
            "smb_connections": 140,
            "unique_targets": 105,
            "destination_port": 445,
        },
    },
]

print("\nINITIALIZING RETRIEVER...\n")
started = time.perf_counter()
retriever = MitreRetriever()
init_time = time.perf_counter() - started
print(f"Retriever initialized in {init_time:.4f} sec")

print("\nRUNNING RETRIEVAL...\n")
started = time.perf_counter()
retrieval_result = retrieve_candidates(
    retriever=retriever,
    behavioral_findings=behavioral_findings,
    per_query_k=10,
    final_k=10,
)
retrieval_time = time.perf_counter() - started

print("\nQUERIES\n")
for query in retrieval_result["queries"]:
    print("-", query)

print("\nTOP CANDIDATES\n")
for index, candidate in enumerate(retrieval_result["candidates"], start=1):
    print(f"{index}. {candidate['id']} {candidate['name']} (fusion={candidate['fusion_score']:.6f})")
    print(
        "   relevance:", candidate.get("relevance_score", 0.0),
        "| evidence bonus:", candidate.get("evidence_bonus", 0.0),
        "| query support:", candidate.get("query_support", 0),
    )
    for reason in candidate.get("evidence_reasons", []):
        print("   evidence ->", reason)
    for match in candidate.get("matched_queries", []):
        print(
            "   query ->", match["query"],
            "| rank:", match["rank"],
            "| lexical:", match.get("match_score", "N/A"),
            "| normalized:", match.get("normalized_score", "N/A"),
            "| weight:", match.get("query_weight", "N/A"),
        )

print("\nTIMING\n")
print(f"Retriever Init : {init_time:.4f} sec")
print(f"Retrieval Only : {retrieval_time:.4f} sec")
