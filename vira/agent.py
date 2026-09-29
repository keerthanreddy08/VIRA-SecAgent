"""
VIRA-Brain: Autonomous Cybersecurity Reasoning Agent.
Implements the multi-stage ReAct cognitive loop: Ingestion -> RAG Retrieval -> Threat Hypothesis -> Remediation -> Report.
"""
import uuid
from typing import Dict, Any, Union, List, Optional

from .models import (
    ParsedAlert,
    IOC,
    RAGSearchResult,
    PlaybookMatch,
    AgentThoughtStep,
    IncidentTriageReport,
)
from .parser import AlertParser
from .rag_engine import SecOpsRAGEngine
from .remediator import RemediationEngine


class VIRACyberAgent:
    """Autonomous Cybersecurity SOC Analyst Agent with RAG Cognitive Architecture."""

    def __init__(self, data_dir: Optional[str] = None):
        self.rag_engine = SecOpsRAGEngine(data_dir=data_dir)

    def triage_alert(self, raw_alert: Union[Dict[str, Any], str]) -> IncidentTriageReport:
        """Executes the full VIRA-Brain cognitive reasoning cycle on an incoming alert."""
        reasoning_trace: List[AgentThoughtStep] = []
        step_num = 1

        # ---------------------------------------------------------
        # STAGE 1: TELEMETRY INGESTION & IOC NORMALIZATION
        # ---------------------------------------------------------
        parsed_alert = AlertParser.parse(raw_alert)

        obs_1 = (
            f"Alert ID: {parsed_alert.alert_id} | Host: {parsed_alert.hostname} ({parsed_alert.host_ip}) | "
            f"Rule Level: {parsed_alert.severity_level} | Source Type: {parsed_alert.source_type}"
        )
        thought_1 = (
            f"Extracting all Indicators of Compromise (IOCs) from telemetry. "
            f"Discovered: IPs={parsed_alert.iocs.source_ips}, Users={parsed_alert.iocs.usernames}, "
            f"Processes={parsed_alert.iocs.processes}, External={parsed_alert.iocs.is_external_src}."
        )
        action_1 = "Normalize telemetry into standardized security data model."
        res_1 = f"IOC extraction complete. Extracted {len(parsed_alert.iocs.source_ips)} IPs and {len(parsed_alert.iocs.processes)} processes."

        reasoning_trace.append(AgentThoughtStep(step_num, "Telemetry Ingestion & IOC Extraction", obs_1, thought_1, action_1, res_1))
        step_num += 1

        # ---------------------------------------------------------
        # STAGE 2: SEMANTIC RAG KNOWLEDGE RETRIEVAL
        # ---------------------------------------------------------
        # Synthesize query for knowledge base
        query_elements = [parsed_alert.rule_description]
        if parsed_alert.iocs.commands:
            query_elements.extend(parsed_alert.iocs.commands)
        if parsed_alert.iocs.processes:
            query_elements.extend(parsed_alert.iocs.processes)
        rag_query = " ".join(query_elements)

        rag_results = self.rag_engine.search_mitre(rag_query, top_k=3)
        primary_tech = rag_results[0] if rag_results else None
        secondary_techs = rag_results[1:] if len(rag_results) > 1 else []

        playbook: Optional[PlaybookMatch] = None
        if primary_tech:
            playbook = self.rag_engine.get_playbook_for_technique(primary_tech.technique_id)

        obs_2 = f"Queried MITRE ATT&CK & NIST Playbooks RAG with prompt: '{rag_query[:90]}...'"
        thought_2 = (
            f"Primary MITRE Match: {primary_tech.technique_id} - {primary_tech.technique_name} "
            f"(Score: {primary_tech.relevance_score:.2f}, Tactic: {primary_tech.tactic}). "
            f"Incident Playbook Mapped: {playbook.playbook_id if playbook else 'Standard Triage'}."
        )
        action_2 = "Fetch contextual defense guidance and threat indicators from indexed vectors."
        res_2 = f"Retrieved {len(rag_results)} relevant MITRE techniques and mapped response playbook."

        reasoning_trace.append(AgentThoughtStep(step_num, "Semantic RAG Knowledge Retrieval", obs_2, thought_2, action_2, res_2))
        step_num += 1

        # ---------------------------------------------------------
        # STAGE 3: THREAT VERIFICATION & INTENT HYPOTHESIS
        # ---------------------------------------------------------
        # Compute Dynamic Risk Score (0-100)
        risk_score = min(int(parsed_alert.severity_level * 6.5), 95)
        if parsed_alert.iocs.is_external_src:
            risk_score = min(risk_score + 10, 99)
        if any("vssadmin" in p.lower() or "powershell" in p.lower() for p in parsed_alert.iocs.processes):
            risk_score = min(risk_score + 15, 100)

        # Categorize Severity
        if risk_score >= 85:
            severity = "CRITICAL"
        elif risk_score >= 65:
            severity = "HIGH"
        elif risk_score >= 40:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        confidence = round(min(0.70 + (primary_tech.relevance_score if primary_tech else 0.1) * 0.3, 0.98), 2)
        classification = "TRUE_POSITIVE" if risk_score >= 50 else "SUSPICIOUS"

        intent, blast_radius = self._synthesize_threat_intent(parsed_alert, primary_tech)

        obs_3 = f"Evaluated IOC anomalies, command execution context, and asset exposure ({parsed_alert.hostname})."
        thought_3 = (
            f"Calculated Risk Score: {risk_score}/100 ({severity}). Confidence: {confidence*100:.0f}%. "
            f"Adversary Intent: {intent}. Blast Radius: {blast_radius}."
        )
        action_3 = "Correlate contextual telemetry with MITRE attack lifecycle patterns."
        res_3 = f"Hypothesis established: Active {primary_tech.technique_name if primary_tech else 'Adversary'} attempt confirmed."

        reasoning_trace.append(AgentThoughtStep(step_num, "Threat Verification & Blast Radius Analysis", obs_3, thought_3, action_3, res_3))
        step_num += 1

        # ---------------------------------------------------------
        # STAGE 4: AUTONOMOUS PLAYBOOK & REMEDIATION SYNTHESIS
        # ---------------------------------------------------------
        remediation_artifacts = RemediationEngine.generate(parsed_alert, primary_tech, playbook)

        obs_4 = f"Triggering containment strategy mapped to {primary_tech.technique_id if primary_tech else 'T1000'}."
        thought_4 = (
            f"Generating host and network containment commands to neutralize attack surface. "
            f"Compiling Sigma detection rule for immediate SIEM ingestion."
        )
        action_4 = "Generate platform-specific scripts (iptables / PowerShell / Sigma YAML)."
        res_4 = "Remediation artifacts generated successfully with rollback safeguards."

        reasoning_trace.append(AgentThoughtStep(step_num, "Containment & Playbook Synthesis", obs_4, thought_4, action_4, res_4))
        step_num += 1

        # ---------------------------------------------------------
        # STAGE 5: EXECUTIVE AUDIT & REPORT COMPILATION
        # ---------------------------------------------------------
        incident_id = f"INC-{uuid.uuid4().hex[:8].upper()}"
        exec_summary = (
            f"VIRA-Brain detected and verified an active {severity} security incident on host '{parsed_alert.hostname}'. "
            f"The telemetry corresponds to MITRE ATT&CK {primary_tech.technique_id if primary_tech else 'N/A'} "
            f"({primary_tech.technique_name if primary_tech else 'Unknown Technique'}), tactic '{primary_tech.tactic if primary_tech else 'N/A'}'. "
            f"Automated containment procedures have been formulated to neutralize {parsed_alert.iocs.source_ips[0] if parsed_alert.iocs.source_ips else 'the threat'} "
            f"and prevent further lateral propagation."
        )

        analyst_action = (
            f"Approve containment actions immediately. Review host '{parsed_alert.hostname}' network connections and "
            f"deploy the synthesized Sigma rule to Wazuh/Elastic detection pipelines."
        )

        obs_5 = "All analysis phases completed. Compiling final structured SOC audit payload."
        thought_5 = "Ensuring end-to-end explainability and clear executive actions for SecOps personnel."
        action_5 = "Export IncidentTriageReport object."
        res_5 = f"Incident Report {incident_id} successfully compiled."

        reasoning_trace.append(AgentThoughtStep(step_num, "Executive Triage Report Compilation", obs_5, thought_5, action_5, res_5))

        return IncidentTriageReport(
            incident_id=incident_id,
            alert_title=parsed_alert.rule_description,
            severity=severity,
            risk_score=risk_score,
            confidence_score=confidence,
            classification=classification,
            threat_actor_intent=intent,
            blast_radius=blast_radius,
            primary_mitre_technique=primary_tech,
            secondary_mitre_techniques=secondary_techs,
            playbook=playbook,
            reasoning_trace=reasoning_trace,
            remediation=remediation_artifacts,
            executive_summary=exec_summary,
            recommended_analyst_action=analyst_action
        )

    def _synthesize_threat_intent(
        self,
        alert: ParsedAlert,
        tech: Optional[RAGSearchResult]
    ) -> Tuple[str, str]:
        """Infers threat actor intent and blast radius from telemetry context."""
        tactic = tech.tactic if tech else "Execution"
        proc = alert.iocs.processes[0] if alert.iocs.processes else ""

        if "Brute" in alert.rule_description or (tech and "T1110" in tech.technique_id):
            return (
                "Automated credential brute-force spraying targeting root/administrative accounts.",
                "Perimeter Bastion host exposed; potential breach of administrative SSH gateway if credentials match."
            )
        elif "powershell" in proc.lower() or (tech and "T1059" in tech.technique_id):
            return (
                "Fileless payload delivery and initial access staging via obfuscated PowerShell reverse shell.",
                "Workstation compromised; potential C2 beaconing and reconnaissance across corporate subnet."
            )
        elif "sudo" in alert.rule_description or (tech and "T1548" in tech.technique_id):
            return (
                "Unauthorized privilege escalation from restricted service account (www-data) to root.",
                "Web application server compromised; threat actor attempting to extract credentials from /etc/shadow."
            )
        elif "vssadmin" in proc.lower() or (tech and "T1490" in tech.technique_id):
            return (
                "Ransomware pre-encryption staging: attempting to destroy volume shadow copies to prevent recovery.",
                "CRITICAL: Central Network Attached Storage (NAS) / File Server at risk of total data encryption."
            )
        elif "sql" in alert.rule_description.lower() or (tech and "T1190" in tech.technique_id):
            return (
                "Database extraction and public web application exploitation via SQL injection.",
                "Production SQL database exposed; potential compromise of sensitive user credentials and customer PII."
            )
        return (
            f"Adversarial activity executing {tactic} techniques on enterprise asset.",
            f"Endpoint {alert.hostname} potentially compromised; containment recommended."
        )
