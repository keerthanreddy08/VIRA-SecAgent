# VIRA-SecAgent: Autonomous Cybersecurity Incident Response & Threat Hunting Agent (RAG + SIEM)

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://python.org)
[![Framework](https://img.shields.io/badge/Architecture-Agentic%20RAG%20%7C%20ReAct-cyan.svg)]()
[![SIEM](https://img.shields.io/badge/SIEM-Wazuh%20%7C%20Elastic%20%7C%20Sysmon-orange.svg)]()
[![Knowledge-Base](https://img.shields.io/badge/Standards-MITRE%20ATT%26CK%20%7C%20NIST%20SP%20800--61-red.svg)]()
[![Tests](https://img.shields.io/badge/Tests-5%2F5%20Passing-brightgreen.svg)]()

> **Engineered for HITH's VIRA-Brain Cognitive Cyber Defense Architecture**  
> Direct architectural synergy: Bridging SIEM log telemetry (Wazuh, Elastic, Sysmon) with an autonomous reasoning agent and a semantic RAG knowledge base.

---

## 🎯 Architectural Overview

Modern Security Operations Centers (SOCs) are burdened by extreme alert fatigue: thousands of raw SIEM alerts stream daily across Windows Event Logs, Linux syslogs, and network sensors. 

**VIRA-SecAgent** functions as an **Autonomous SOC Copilot** that ingests raw telemetry, applies semantic RAG over curated **MITRE ATT&CK** matrices and **NIST SP 800-61** playbooks, performs multi-step cognitive reasoning (ReAct loop), and synthesizes active containment scripts (iptables / PowerShell) and universal **Sigma detection rules**.

```
                   ┌──────────────────────────────────────┐
                   │    Heterogeneous Telemetry Stream    │
                   │  (Wazuh JSON, Sysmon, Linux Syslog)  │
                   └──────────────────┬───────────────────┘
                                      │
                                      ▼
                   ┌──────────────────────────────────────┐
                   │   Stage 1: IOC Parser & Normalizer   │
                   │   (IPs, Users, Hashes, Processes)    │
                   └──────────────────┬───────────────────┘
                                      │
               ┌──────────────────────┴──────────────────────┐
               ▼                                             ▼
  ┌─────────────────────────┐                   ┌─────────────────────────┐
  │  MITRE ATT&CK Vectors   │ ◄─── Hybrid ────► │  NIST SP 800-61 SOPs    │
  │ (Tactics & Techniques)  │      RAG Search   │ (Containment Playbooks) │
  └─────────────────────────┘                   └─────────────────────────┘
               │                                             │
               └──────────────────────┬──────────────────────┘
                                      │
                                      ▼
                   ┌──────────────────────────────────────┐
                   │    Stage 2: VIRA-Brain Agent Loop    │
                   │   - Dynamic Risk Scoring (0-100)     │
                   │   - Adversary Intent & Blast Radius  │
                   │   - Confidence Verification          │
                   └──────────────────┬───────────────────┘
                                      │
                                      ▼
                   ┌──────────────────────────────────────┐
                   │    Stage 3: Automated Containment    │
                   │  • Linux iptables/ufw block script   │
                   │  • Windows NetFirewall / AD Lockout  │
                   │  • Auto-Generated Sigma Detection    │
                   │  • Executive SOC Audit Trail         │
                   └──────────────────────────────────────┘
```

---

## 🚀 Key Technical Capabilities

1. **Heterogeneous Telemetry Normalization**:
   - Parses complex Wazuh alert JSON (`rule`, `data`, `agent`, `full_log`).
   - Extracts Windows Security Events (Event ID 4688 / Sysmon Event 1) with CommandLine capture and Base64 encoded payload detection.
   - Detects external vs internal IP origins using RFC 1918 classification.

2. **Sub-Millisecond Hybrid RAG Knowledge Engine**:
   - TF-IDF + Cosine Similarity semantic search combined with exact technique ID and keyword boosting.
   - Direct mapping to MITRE ATT&CK techniques (e.g. `T1110.001`, `T1059.001`, `T1490`, `T1548.003`, `T1190`).
   - Automated retrieval of NIST SP 800-61 incident containment playbooks.

3. **ReAct Cognitive Agent Loop**:
   - Maintains an explainable chain-of-thought (`Observation` $\to$ `Thought` $\to$ `Action` $\to$ `Result`).
   - Calculates dynamic risk scores (0–100) factoring in IOC severity, asset exposure, and attack technique.
   - Identifies threat actor intent and blast radius across the enterprise subnet.

4. **Active Remediation & Defense-in-Depth Synthesis**:
   - Generates executable Linux `iptables` / `ufw` containment commands.
   - Generates Windows PowerShell containment (`New-NetFirewallRule`, `Disable-ADAccount`, process tree termination).
   - Generates production-ready **Sigma Detection Rules** (YAML) for immediate deployment into Wazuh / Elastic.

5. **Dual Interface: Web SOC Dashboard & Fast CLI**:
   - High-tech, dark-themed SOC operations interface.
   - Command-line interface with batch evaluation benchmarks.

---

## 📊 Benchmark Results

Running the automated benchmark suite across 5 realistic attack scenarios (`python cli.py evaluate`):

| Telemetry Scenario | Severity | Risk Score | MITRE Technique | Tactic | Confidence |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `wazuh_ssh_bruteforce.json` | **HIGH** | 75 / 100 | **T1110.001** (Password Guessing) | Credential Access | **98%** |
| `win_encoded_powershell.json`| **CRITICAL** | 100 / 100 | **T1059.001** (PowerShell) | Execution | **98%** |
| `priv_escalation_sudo.json` | **HIGH** | 71 / 100 | **T1548.003** (Sudo Abuse) | Privilege Escalation | **98%** |
| `ransomware_shadowcopy.json` | **CRITICAL** | 100 / 100 | **T1490** (Inhibit Recovery) | Impact | **98%** |
| `web_sqli_exfiltration.json` | **HIGH** | 71 / 100 | **T1190** (Exploit Public App) | Initial Access | **87%** |

*Result: 100% resolution accuracy, zero external API latency, 0.04s execution time.*

---

## 🛠️ Quick Start

### 1. Run Interactive Web SOC Dashboard
```bash
python run_demo.py
# Open your browser at: http://127.0.0.1:5000
```

### 2. Run CLI Automated Triage
```bash
# Triage a specific alert:
python cli.py triage data/sample_alerts/wazuh_ssh_bruteforce.json

# Query the MITRE ATT&CK RAG Knowledge Base:
python cli.py search-kb "powershell encoded command reverse shell"

# Run batch benchmark evaluation:
python cli.py evaluate
```

### 3. Run Test Suite
```bash
python -m unittest tests/test_vira_agent.py
```

---

## 📁 Repository Structure

```
VIRA-SecAgent/
├── cli.py                     # Interactive CLI for triage & benchmarks
├── run_demo.py                # Web dashboard runner
├── requirements.txt           # Python dependencies
├── data/
│   ├── mitre_attack_kb.json   # Indexed MITRE ATT&CK knowledge base
│   ├── incident_playbooks.json# NIST SP 800-61 incident response playbooks
│   └── sample_alerts/         # Realistic Wazuh & Sysmon attack logs
├── vira/
│   ├── models.py              # Normalized dataclass schemas
│   ├── parser.py              # Telemetry ingestion & IOC extraction
│   ├── rag_engine.py          # TF-IDF + BM25 hybrid semantic retriever
│   ├── agent.py               # VIRA-Brain cognitive ReAct reasoning agent
│   ├── remediator.py          # Script & Sigma rule generator
│   └── web_server.py          # Flask SOC dashboard & REST API
├── templates/
│   └── dashboard.html         # Modern cyber SOC dashboard UI
└── tests/
    └── test_vira_agent.py     # Unit and integration test suite
```
