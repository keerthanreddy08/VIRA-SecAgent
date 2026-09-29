"""
Automated Remediation & Containment Engine.
Generates Linux/Windows firewall containment commands, PowerShell scripts, and Sigma detection rules.
"""
from typing import Optional, List
from .models import ParsedAlert, RAGSearchResult, PlaybookMatch, RemediationArtifacts


class RemediationEngine:
    """Synthesizes containment scripts, firewall commands, and Sigma detection rules."""

    @classmethod
    def generate(
        cls,
        alert: ParsedAlert,
        mitre_tech: Optional[RAGSearchResult],
        playbook: Optional[PlaybookMatch]
    ) -> RemediationArtifacts:
        """Constructs executable containment artifacts tailored to the alert context."""
        src_ip = alert.iocs.source_ips[0] if alert.iocs.source_ips else "198.51.100.1"
        target_user = alert.iocs.usernames[0] if alert.iocs.usernames else "unknown_user"
        target_proc = alert.iocs.processes[0] if alert.iocs.processes else "suspicious_process.exe"

        # 1. Linux Containment
        if alert.iocs.is_external_src or src_ip != "127.0.0.1":
            linux_cmd = (
                f"# Immediate IP drop on Linux Gateway / Host\n"
                f"sudo iptables -I INPUT -s {src_ip} -j DROP\n"
                f"sudo ufw insert 1 deny from {src_ip} to any\n"
                f"# Log containment audit trail\n"
                f"logger -t VIRA_AGENT 'Blocked malicious IP {src_ip} in response to {alert.alert_id}'"
            )
        elif target_user != "unknown_user" and target_user != "root":
            linux_cmd = (
                f"# Terminate user sessions and lock account\n"
                f"sudo pkill -u {target_user}\n"
                f"sudo passwd -l {target_user}\n"
                f"logger -t VIRA_AGENT 'Locked account {target_user} following privilege escalation alert'"
            )
        else:
            linux_cmd = (
                f"# Network isolation and process kill\n"
                f"sudo pkill -f {target_proc}\n"
                f"sudo systemctl isolate emergency.target"
            )

        # 2. Windows PowerShell Containment
        if alert.iocs.is_external_src:
            ps_cmd = (
                f"# Block malicious ingress IP via Windows Advanced Firewall\n"
                f"New-NetFirewallRule -DisplayName 'VIRA-Block-{src_ip}' -Direction Inbound -Action Block -RemoteAddress {src_ip}\n"
                f"Write-Host '[VIRA] Inbound traffic from {src_ip} isolated successfully.' -ForegroundColor Yellow"
            )
        elif "vssadmin" in target_proc.lower() or "powershell" in target_proc.lower():
            ps_cmd = (
                f"# Terminate rogue process tree & isolate endpoint\n"
                f"Get-Process -Name '{target_proc.replace('.exe', '')}' -ErrorAction SilentlyContinue | Stop-Process -Force\n"
                f"Disable-NetAdapter -Name * -Confirm:$false  # Isolate from LAN\n"
                f"Write-Host '[VIRA] Endpoint isolated and rogue process terminated.' -ForegroundColor Red"
            )
        elif target_user != "unknown_user":
            ps_cmd = (
                f"# Disable Active Directory account\n"
                f"Disable-ADAccount -Identity '{target_user}'\n"
                f"Revoke-AzureADUserAllRefreshToken -ObjectId '{target_user}' -ErrorAction SilentlyContinue\n"
                f"Write-Host '[VIRA] Suspended AD account: {target_user}' -ForegroundColor Green"
            )
        else:
            ps_cmd = (
                f"# Default emergency host network quarantine\n"
                f"Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True\n"
                f"New-NetFirewallRule -DisplayName 'VIRA-Quarantine' -Direction Outbound -Action Block"
            )

        # 3. Universal Sigma Detection Rule
        tech_id = mitre_tech.technique_id if mitre_tech else "T1000"
        tech_name = mitre_tech.technique_name if mitre_tech else "Threat Detection"
        sigma_yaml = cls._build_sigma_rule(alert, tech_id, tech_name, target_proc, src_ip)

        # 4. Standard Operating Procedure (SOP)
        recommended_sop: List[str] = []
        if playbook and playbook.containment_steps:
            recommended_sop = playbook.containment_steps
        else:
            recommended_sop = [
                "1. Confirm IOC presence in perimeter proxy and firewall logs.",
                "2. Isolate affected host from production VLAN.",
                "3. Preserve volatile memory image before host restart.",
                "4. Update SIEM blocklists and trigger credential resets.",
                "5. Conduct post-incident root cause analysis within 24 hours."
            ]

        return RemediationArtifacts(
            firewall_command=f"iptables -I INPUT -s {src_ip} -j DROP" if src_ip else "N/A",
            powershell_remediation=ps_cmd,
            linux_remediation=linux_cmd,
            sigma_rule_yaml=sigma_yaml,
            recommended_sop=recommended_sop
        )

    @classmethod
    def _build_sigma_rule(
        cls,
        alert: ParsedAlert,
        tech_id: str,
        tech_name: str,
        target_proc: str,
        src_ip: str
    ) -> str:
        """Constructs an industry-standard Sigma detection rule (YAML format)."""
        rule_name = f"vira_detect_{tech_id.lower().replace('.', '_')}_{alert.source_type}"
        return f"""title: VIRA Autonomous Detection - {tech_name}
id: 5c861657-vira-{tech_id.lower().replace('.', '')}
status: experimental
description: Auto-generated by VIRA-SecAgent upon triage of alert {alert.alert_id} ({alert.rule_description}).
references:
    - https://attack.mitre.org/techniques/{tech_id.split('.')[0]}/
author: VIRA-Brain Cognitive SOC Agent
date: {alert.timestamp[:10]}
tags:
    - attack.{tech_id.lower().replace('.', '')}
    - attack.{tech_name.lower().replace(' ', '_')}
logsource:
    category: process_creation
    product: { 'windows' if alert.source_type == 'windows_event' else 'linux' }
detection:
    selection:
        CommandLine|contains:
            - '{alert.iocs.commands[0][:40] if alert.iocs.commands else target_proc}'
    condition: selection
falsepositives:
    - Verified Administrative Maintenance Activities
level: high
"""
