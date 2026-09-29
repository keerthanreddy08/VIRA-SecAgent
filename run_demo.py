"""
Quick-start showcase runner for VIRA-SecAgent.
Launches the Web Dashboard or runs a sample CLI triage.
"""
import sys
import os

from vira.web_server import start_server

if __name__ == "__main__":
    print("[*] Starting VIRA-Brain Web Dashboard...")
    print("[*] Press Ctrl+C in terminal to stop.")
    start_server(port=5000)
