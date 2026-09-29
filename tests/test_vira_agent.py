"""
Unit & Integration Tests for VIRA-SecAgent.
"""
import unittest
import os
import json
import sys

# Add project root to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vira.parser import AlertParser
from vira.rag_engine import SecOpsRAGEngine
from vira.remediator import RemediationEngine
from vira.agent import VIRACyberAgent


class TestVIRASecAgent(unittest.TestCase):

    def setUp(self):
        self.data_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
        self.samples_dir = os.path.join(self.data_dir, "sample_alerts")
        self.agent = VIRACyberAgent(data_dir=self.data_dir)
        self.rag = SecOpsRAGEngine(data_dir=self.data_dir)

    def test_alert_parser_wazuh(self):
        sample_path = os.path.join(self.samples_dir, "wazuh_ssh_bruteforce.json")
        with open(sample_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        parsed = AlertParser.parse(data)
        self.assertEqual(parsed.source_type, "syslog")
        self.assertIn("185.220.101.45", parsed.iocs.source_ips)
        self.assertTrue(parsed.iocs.is_external_src)
        self.assertIn("root", parsed.iocs.usernames)

    def test_alert_parser_windows_powershell(self):
        sample_path = os.path.join(self.samples_dir, "win_encoded_powershell.json")
        with open(sample_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        parsed = AlertParser.parse(data)
        self.assertEqual(parsed.source_type, "windows_event")
        self.assertIn("powershell.exe", parsed.iocs.processes)
        self.assertIn("EXCEL.EXE", parsed.iocs.parent_processes)
        self.assertIn("kevin.finance", parsed.iocs.usernames)

    def test_rag_retrieval_ssh_bruteforce(self):
        results = self.rag.search_mitre("ssh brute force failed login invalid user", top_k=1)
        self.assertTrue(len(results) > 0)
        self.assertEqual(results[0].technique_id, "T1110.001")
        self.assertEqual(results[0].tactic, "Credential Access")

    def test_rag_retrieval_ransomware_vssadmin(self):
        results = self.rag.search_mitre("vssadmin delete shadows /all /quiet", top_k=1)
        self.assertTrue(len(results) > 0)
        self.assertEqual(results[0].technique_id, "T1490")
        self.assertEqual(results[0].tactic, "Impact")

    def test_agent_end_to_end_triage(self):
        sample_path = os.path.join(self.samples_dir, "wazuh_ssh_bruteforce.json")
        with open(sample_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        report = self.agent.triage_alert(data)

        self.assertIsNotNone(report.incident_id)
        self.assertEqual(report.severity, "HIGH")
        self.assertTrue(report.risk_score >= 70)
        self.assertEqual(report.primary_mitre_technique.technique_id, "T1110.001")
        self.assertEqual(len(report.reasoning_trace), 5)
        self.assertIn("iptables", report.remediation.firewall_command)
        self.assertIn("attack.t1110001", report.remediation.sigma_rule_yaml.lower())


if __name__ == "__main__":
    unittest.main()
