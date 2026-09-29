"""
Data models and schemas for VIRA-SecAgent.
"""
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Any


@dataclass
class IOC:
    """Extracted Indicators of Compromise."""
    source_ips: List[str] = field(default_factory=list)
    dest_ips: List[str] = field(default_factory=list)
    usernames: List[str] = field(default_factory=list)
    processes: List[str] = field(default_factory=list)
    parent_processes: List[str] = field(default_factory=list)
    hashes: List[str] = field(default_factory=list)
    commands: List[str] = field(default_factory=list)
    ports: List[str] = field(default_factory=list)
    is_external_src: bool = False


@dataclass
class ParsedAlert:
    """Normalized security alert structure."""
    alert_id: str
    timestamp: str
    source_type: str  # 'wazuh', 'windows_event', 'syslog', 'generic'
    severity_level: int  # 1-15 (Wazuh scale)
    rule_description: str
    hostname: str
    host_ip: str
    iocs: IOC
    raw_log: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RAGSearchResult:
    """Matched MITRE ATT&CK knowledge base entry."""
    technique_id: str
    technique_name: str
    tactic: str
    relevance_score: float  # 0.0 to 1.0
    description: str
    detection_guidance: str
    mitigation_guidance: str
    matched_keywords: List[str] = field(default_factory=list)


@dataclass
class PlaybookMatch:
    """Matched Incident Response Playbook."""
    playbook_id: str
    name: str
    severity_baseline: str
    containment_steps: List[str]
    verification_query: str
    automated_action_type: str


@dataclass
class AgentThoughtStep:
    """Single step in VIRA-Brain's cognitive chain-of-thought."""
    step_number: int
    title: str
    observation: str
    thought: str
    action_taken: str
    result: str


@dataclass
class RemediationArtifacts:
    """Generated containment scripts and detection rules."""
    firewall_command: str
    powershell_remediation: str
    linux_remediation: str
    sigma_rule_yaml: str
    recommended_sop: List[str] = field(default_factory=list)


@dataclass
class IncidentTriageReport:
    """Comprehensive Incident Triage Report produced by VIRA-Brain."""
    incident_id: str
    alert_title: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL, EMERGENCY
    risk_score: int  # 0 - 100
    confidence_score: float  # 0.0 - 1.0
    classification: str  # TRUE_POSITIVE, SUSPICIOUS, FALSE_POSITIVE_LIKELY
    threat_actor_intent: str
    blast_radius: str
    primary_mitre_technique: Optional[RAGSearchResult]
    secondary_mitre_techniques: List[RAGSearchResult]
    playbook: Optional[PlaybookMatch]
    reasoning_trace: List[AgentThoughtStep]
    remediation: RemediationArtifacts
    executive_summary: str
    recommended_analyst_action: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
