"""
Web Server for VIRA-SecAgent: Modern SOC Dashboard & REST API.
"""
import os
import json
from flask import Flask, render_template, request, jsonify

from .agent import VIRACyberAgent

app = Flask(
    __name__,
    template_folder=os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates"),
    static_folder=os.path.join(os.path.dirname(os.path.dirname(__file__)), "static")
)

agent = VIRACyberAgent()
data_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
samples_dir = os.path.join(data_dir, "sample_alerts")


def load_sample(filename: str):
    fpath = os.path.join(samples_dir, filename)
    if os.path.exists(fpath):
        with open(fpath, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


@app.route("/")
def index():
    return render_template(
        "dashboard.html",
        sample_ssh=load_sample("wazuh_ssh_bruteforce.json"),
        sample_ps=load_sample("win_encoded_powershell.json"),
        sample_sudo=load_sample("priv_escalation_sudo.json"),
        sample_ransom=load_sample("ransomware_shadowcopy.json"),
        sample_sqli=load_sample("web_sqli_exfiltration.json")
    )


@app.route("/api/triage", methods=["POST"])
def api_triage():
    body = request.get_json(force=True)
    raw_alert = body.get("alert")
    if not raw_alert:
        return jsonify({"error": "No alert provided"}), 400

    report = agent.triage_alert(raw_alert)
    return jsonify(report.to_dict())


@app.route("/api/kb", methods=["GET"])
def api_kb():
    query = request.args.get("q", "")
    if not query:
        return jsonify(agent.rag_engine.mitre_entries)
    results = agent.rag_engine.search_mitre(query, top_k=5)
    return jsonify([r.__dict__ for r in results])


def start_server(port: int = 5000, debug: bool = False):
    print(f"\n[+] VIRA-SecAgent SOC Dashboard running at: http://127.0.0.1:{port}")
    app.run(host="127.0.0.1", port=port, debug=debug)


if __name__ == "__main__":
    start_server()
