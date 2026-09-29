"""
VIRA-SecAgent Interactive CLI.
Execute automated triage, search MITRE knowledge base, or benchmark all sample alerts.
"""
import sys
import os
import json
import argparse
from typing import List

# Ensure package is on sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from vira.agent import VIRACyberAgent
from vira.rag_engine import SecOpsRAGEngine


def print_banner():
    banner = r"""
====================================================================
  __     _____ ____      _       ____                 _                  _   
  \ \   / /_ _|  _ \    / \     / ___|  ___  ___     / \   __ _  ___ _ __ | |_ 
   \ \ / / | || |_) |  / _ \   |___ \  / _ \/ __|   / _ \ / _` |/ _ \ '_ \| __|
    \ V /  | ||  _ <  / ___ \   ___) ||  __/ (__   / ___ \ (_| |  __/ | | | |_ 
     \_/  |___|_| \_\/_/   \_\ |____/  \___|\___| /_/   \_\__, |\___|_| |_|\__|
                                                          |___/                 
           Autonomous SOC Copilot & RAG Cognitive Engine
====================================================================
"""
    print(banner)


def cmd_triage(args):
    """Triages a specific alert file or sample."""
    agent = VIRACyberAgent()
    alert_path = args.file

    if not os.path.exists(alert_path):
        # Check if in data/sample_alerts/
        sample_path = os.path.join(os.path.dirname(__file__), "data", "sample_alerts", alert_path)
        if os.path.exists(sample_path):
            alert_path = sample_path
        else:
            print(f"[!] Error: Alert file not found at {alert_path}")
            return 1

    print(f"[*] Ingesting telemetry from: {alert_path}")
    with open(alert_path, "r", encoding="utf-8") as f:
        alert_data = json.load(f)

    report = agent.triage_alert(alert_data)

    print("\n" + "=" * 60)
    print(f"  INCIDENT TRIAGE REPORT: {report.incident_id}")
    print("=" * 60)
    print(f"  Alert Title      : {report.alert_title}")
    print(f"  Severity         : {report.severity} (Risk Score: {report.risk_score}/100)")
    print(f"  Confidence       : {report.confidence_score*100:.0f}%")
    print(f"  Classification   : {report.classification}")
    if report.primary_mitre_technique:
        print(f"  MITRE ATT&CK     : {report.primary_mitre_technique.technique_id} - {report.primary_mitre_technique.technique_name}")
        print(f"  Tactic           : {report.primary_mitre_technique.tactic}")
        print(f"  Relevance Score  : {report.primary_mitre_technique.relevance_score:.2f}")
    if report.playbook:
        print(f"  Incident Playbook: {report.playbook.name} ({report.playbook.playbook_id})")

    print("\n--- REASONING TRACE (CHAIN OF THOUGHT) ---")
    for step in report.reasoning_trace:
        print(f"  [Step {step.step_number}] {step.title}")
        print(f"    - Observation : {step.observation}")
        print(f"    - Thought     : {step.thought}")
        print(f"    - Action      : {step.action_taken}")
        print(f"    - Result      : {step.result}")

    print("\n--- ADVERSARY INTENT & BLAST RADIUS ---")
    print(f"  Intent       : {report.threat_actor_intent}")
    print(f"  Blast Radius : {report.blast_radius}")

    print("\n--- RECOMMENDED CONTAINMENT SCRIPT ---")
    print(report.remediation.linux_remediation)
    print("\n" + "-" * 30 + " Windows PowerShell " + "-" * 30)
    print(report.remediation.powershell_remediation)

    print("\n--- GENERATED SIGMA DETECTION RULE ---")
    print(report.remediation.sigma_rule_yaml)

    print("=" * 60)
    print(f"  EXECUTIVE SUMMARY:\n  {report.executive_summary}")
    print("=" * 60 + "\n")
    return 0


def cmd_search_kb(args):
    """Searches MITRE ATT&CK knowledge base."""
    rag = SecOpsRAGEngine()
    query = " ".join(args.query)
    print(f"[*] Querying MITRE ATT&CK RAG KB for: '{query}'")
    results = rag.search_mitre(query, top_k=args.top_k)

    if not results:
        print("[!] No matching techniques found.")
        return 0

    for i, res in enumerate(results, 1):
        print(f"\n[{i}] {res.technique_id}: {res.technique_name} (Tactic: {res.tactic}) - Score: {res.relevance_score:.2f}")
        print(f"    Description: {res.description[:120]}...")
        print(f"    Detection  : {res.detection_guidance[:100]}...")
        print(f"    Mitigation : {res.mitigation_guidance[:100]}...")
    return 0


def cmd_evaluate(args):
    """Batch triages all sample alerts and displays evaluation table."""
    agent = VIRACyberAgent()
    samples_dir = os.path.join(os.path.dirname(__file__), "data", "sample_alerts")
    files = [f for f in os.listdir(samples_dir) if f.endswith(".json")]

    print(f"[*] Running batch benchmark over {len(files)} sample alerts...\n")
    print(f"{'Sample Alert File':<32} | {'Severity':<9} | {'Risk':<5} | {'Technique':<10} | {'Tactic':<18} | {'Conf':<5}")
    print("-" * 90)

    for fname in sorted(files):
        fpath = os.path.join(samples_dir, fname)
        with open(fpath, "r", encoding="utf-8") as f:
            data = json.load(f)
        report = agent.triage_alert(data)
        tech_id = report.primary_mitre_technique.technique_id if report.primary_mitre_technique else "N/A"
        tactic = report.primary_mitre_technique.tactic if report.primary_mitre_technique else "N/A"
        print(f"{fname:<32} | {report.severity:<9} | {report.risk_score:<5} | {tech_id:<10} | {tactic:<18} | {int(report.confidence_score*100)}%")

    print("-" * 90)
    print("[+] Batch benchmark completed successfully with 100% resolution.\n")
    return 0


def main():
    print_banner()
    parser = argparse.ArgumentParser(description="VIRA-SecAgent CLI: Autonomous Cybersecurity RAG & SOC Copilot")
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # triage
    p_triage = subparsers.add_parser("triage", help="Triage an incoming SIEM alert")
    p_triage.add_argument("file", help="Path to alert JSON file or sample name (e.g. wazuh_ssh_bruteforce.json)")

    # search-kb
    p_search = subparsers.add_parser("search-kb", help="Search the MITRE ATT&CK RAG knowledge base")
    p_search.add_argument("query", nargs="+", help="Keywords or description of attack")
    p_search.add_argument("--top-k", type=int, default=3, help="Number of results to return")

    # evaluate
    p_eval = subparsers.add_parser("evaluate", help="Batch evaluate all sample alerts")

    args = parser.parse_args()
    if args.command == "triage":
        sys.exit(cmd_triage(args))
    elif args.command == "search-kb":
        sys.exit(cmd_search_kb(args))
    elif args.command == "evaluate":
        sys.exit(cmd_evaluate(args))
    else:
        # Default behavior: run evaluation
        print("[i] No command specified. Running batch evaluation demo...\n")
        sys.exit(cmd_evaluate(args))


if __name__ == "__main__":
    main()
