"""
SIEM Alert & Telemetry Ingestion Parser.
Handles Wazuh JSON, Windows Security/Sysmon Events, and Raw Syslog strings.
"""
import re
import ipaddress
from typing import Dict, Any, Union
from .models import ParsedAlert, IOC


class AlertParser:
    """Parses heterogeneous security telemetry into normalized ParsedAlert structures."""

    IPV4_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    HASH_SHA256_REGEX = re.compile(r'\b[A-Fa-f0-9]{64}\b')
    HASH_MD5_REGEX = re.compile(r'\b[A-Fa-f0-9]{32}\b')

    @classmethod
    def is_private_ip(cls, ip_str: str) -> bool:
        """Check if an IPv4 address is RFC 1918 private."""
        try:
            return ipaddress.ip_address(ip_str).is_private
        except ValueError:
            return False

    @classmethod
    def parse(cls, raw_data: Union[Dict[str, Any], str]) -> ParsedAlert:
        """Main entry point to parse either a JSON dictionary or a syslog raw string."""
        if isinstance(raw_data, dict):
            return cls._parse_json(raw_data)
        elif isinstance(raw_data, str):
            return cls._parse_raw_string(raw_data)
        else:
            raise ValueError(f"Unsupported data type for alert parsing: {type(raw_data)}")

    @classmethod
    def _parse_json(cls, data: Dict[str, Any]) -> ParsedAlert:
        """Parses structured JSON alerts (e.g. Wazuh / Elastic / Sysmon)."""
        rule = data.get("rule", {})
        rule_desc = rule.get("description", "Security Event Detected")
        rule_level = rule.get("level", 5)
        rule_id = str(rule.get("id", "UNKNOWN_RULE"))

        agent = data.get("agent", {})
        hostname = agent.get("name", "unknown-host")
        host_ip = agent.get("ip", "127.0.0.1")

        win = data.get("win", {})
        event_data = win.get("eventdata", {})
        alert_data = data.get("data", {})

        # Extract IOCs
        iocs = IOC()

        # Check source IP
        src_ip = alert_data.get("srcip") or alert_data.get("src_ip")
        if not src_ip and "full_log" in data:
            matches = cls.IPV4_REGEX.findall(data["full_log"])
            for m in matches:
                if m != host_ip and not m.startswith("127."):
                    src_ip = m
                    break
        if src_ip:
            iocs.source_ips.append(src_ip)
            iocs.is_external_src = not cls.is_private_ip(src_ip)

        # Check dest IP
        dst_ip = alert_data.get("dstip") or alert_data.get("dst_ip") or host_ip
        if dst_ip:
            iocs.dest_ips.append(dst_ip)

        # Usernames
        user = (
            alert_data.get("dstuser")
            or alert_data.get("srcuser")
            or event_data.get("subjectUserName")
            or event_data.get("user")
        )
        if user:
            iocs.usernames.append(user)

        # Processes
        proc = (
            alert_data.get("process")
            or event_data.get("image")
            or event_data.get("newProcessName")
        )
        if proc:
            # Extract just process filename
            clean_proc = proc.replace("\\", "/").split("/")[-1]
            iocs.processes.append(clean_proc)

        parent_proc = (
            alert_data.get("parent_process")
            or event_data.get("parentProcessName")
            or event_data.get("parentImage")
        )
        if parent_proc:
            clean_parent = parent_proc.replace("\\", "/").split("/")[-1]
            iocs.parent_processes.append(clean_parent)

        # Commands
        cmd = (
            alert_data.get("command")
            or event_data.get("commandLine")
            or alert_data.get("request")
        )
        if cmd:
            iocs.commands.append(cmd)
        
        # Check decoded hint if available
        decoded_hint = event_data.get("decodedHint")
        if decoded_hint:
            iocs.commands.append(f"[DECODED]: {decoded_hint}")

        # Hashes
        raw_hash_field = event_data.get("hashes") or alert_data.get("hashes") or ""
        sha_matches = cls.HASH_SHA256_REGEX.findall(str(raw_hash_field))
        md5_matches = cls.HASH_MD5_REGEX.findall(str(raw_hash_field))
        iocs.hashes.extend(sha_matches + md5_matches)

        # Ports
        port = alert_data.get("srcport") or alert_data.get("dstport")
        if port:
            iocs.ports.append(str(port))

        source_type = "wazuh"
        if "win" in data:
            source_type = "windows_event"
        elif "groups" in rule and "syslog" in rule["groups"]:
            source_type = "syslog"

        timestamp = data.get("timestamp", "2026-09-29T00:00:00Z")
        raw_log = data.get("full_log", str(data))

        return ParsedAlert(
            alert_id=f"ALT-{rule_id}-{timestamp[-8:].replace(':', '')}",
            timestamp=timestamp,
            source_type=source_type,
            severity_level=rule_level,
            rule_description=rule_desc,
            hostname=hostname,
            host_ip=host_ip,
            iocs=iocs,
            raw_log=raw_log,
            metadata=data
        )

    @classmethod
    def _parse_raw_string(cls, log_line: str) -> ParsedAlert:
        """Parses a plain text syslog string."""
        iocs = IOC()
        ips = cls.IPV4_REGEX.findall(log_line)
        if ips:
            iocs.source_ips.append(ips[0])
            iocs.is_external_src = not cls.is_private_ip(ips[0])
            if len(ips) > 1:
                iocs.dest_ips.append(ips[1])

        # Infer user
        user_match = re.search(r'(?:user|for)\s+([a-zA-Z0-9_\-\.]+)', log_line, re.IGNORECASE)
        if user_match:
            iocs.usernames.append(user_match.group(1))

        # Infer process/daemon
        daemon_match = re.search(r'([a-zA-Z0-9_\-]+)\[\d+\]:', log_line)
        if daemon_match:
            iocs.processes.append(daemon_match.group(1))

        return ParsedAlert(
            alert_id="ALT-RAW-SYSLOG",
            timestamp="2026-09-29T22:00:00Z",
            source_type="syslog",
            severity_level=8,
            rule_description="Syslog alert: " + log_line[:80],
            hostname="syslog-host",
            host_ip="127.0.0.1",
            iocs=iocs,
            raw_log=log_line,
            metadata={"raw": log_line}
        )
