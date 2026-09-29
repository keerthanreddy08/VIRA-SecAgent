"""
Generates a perfect, ATS-compliant 1-page PDF resume
for Kandhakatla Keerthan Reddy, featuring the live VIRA-SecAgent GitHub repository link.
"""
import os
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT


def generate_pdf_resume(output_path: str):
    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        leftMargin=34,
        rightMargin=34,
        topMargin=26,
        bottomMargin=26
    )

    styles = getSampleStyleSheet()

    # Colors
    c_primary = colors.HexColor("#0F172A")    # Deep slate
    c_accent = colors.HexColor("#0284C7")     # Professional cyber blue
    c_text = colors.HexColor("#1E293B")       # Dark charcoal
    c_sub = colors.HexColor("#475569")        # Slate grey

    # Typography styles
    style_name = ParagraphStyle(
        'Name',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=17,
        leading=20,
        alignment=TA_CENTER,
        textColor=c_primary
    )

    style_contact = ParagraphStyle(
        'Contact',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.5,
        leading=11,
        alignment=TA_CENTER,
        textColor=c_sub
    )

    style_section = ParagraphStyle(
        'SectionHeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=10,
        leading=12,
        textColor=c_accent,
        spaceBefore=5,
        spaceAfter=2,
        textTransform='uppercase'
    )

    style_job_title = ParagraphStyle(
        'JobTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=9,
        leading=11,
        textColor=c_primary
    )

    style_job_meta = ParagraphStyle(
        'JobMeta',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8.5,
        leading=11,
        alignment=TA_RIGHT,
        textColor=c_sub
    )

    style_body = ParagraphStyle(
        'Body',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.2,
        leading=11,
        textColor=c_text
    )

    style_bullet = ParagraphStyle(
        'Bullet',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.0,
        leading=10.5,
        textColor=c_text,
        leftIndent=11,
        firstLineIndent=-7,
        spaceAfter=1
    )

    story = []

    # 1. HEADER
    story.append(Paragraph("KANDHAKATLA KEERTHAN REDDY", style_name))
    story.append(Spacer(1, 2))
    contact_line = (
        "Hyderabad, India | +91 9121932637 | "
        '<a href="mailto:mail2keerthanreddy@gmail.com"><font color="#0284C7">mail2keerthanreddy@gmail.com</font></a> | '
        '<a href="https://linkedin.com/in/keerthan08"><font color="#0284C7">linkedin.com/in/keerthan08</font></a> | '
        '<a href="https://github.com/keerthanreddy08"><font color="#0284C7">github.com/keerthanreddy08</font></a>'
    )
    story.append(Paragraph(contact_line, style_contact))
    story.append(Spacer(1, 2))
    story.append(HRFlowable(width="100%", thickness=1, color=c_accent, spaceBefore=2, spaceAfter=3))

    # 2. PROFESSIONAL SUMMARY
    story.append(Paragraph("PROFESSIONAL SUMMARY", style_section))
    summary_text = (
        "<b>AI &amp; Cybersecurity Engineer</b> specializing in <b>Agentic AI</b>, <b>Autonomous SOC Systems</b>, and "
        "<b>SIEM Telemetry (Wazuh, Elastic, Sysmon)</b>. Proven expertise building cognitive reasoning agents "
        "(ReAct loops) and sub-millisecond RAG pipelines mapped to <b>MITRE ATT&amp;CK</b> and <b>NIST SP 800-61</b> "
        "standards, bridging machine learning models with real-time cybersecurity defense operations."
    )
    story.append(Paragraph(summary_text, style_body))
    story.append(Spacer(1, 2))

    # 3. TECHNICAL SKILLS
    story.append(Paragraph("TECHNICAL SKILLS", style_section))
    skills_data = [
        [
            Paragraph("<b>Agentic AI &amp; RAG:</b>", style_body),
            Paragraph("Autonomous Agents (ReAct loops), Retrieval-Augmented Generation (RAG), Semantic Vector Search, TF-IDF / Embeddings, Prompt Engineering, Scikit-Learn", style_body)
        ],
        [
            Paragraph("<b>Cybersecurity &amp; SIEM:</b>", style_body),
            Paragraph("Wazuh, Elastic Stack (ELK), Security Onion, OSSEC, Sysmon, MITRE ATT&amp;CK, NIST SP 800-61, Sigma Rules, Wireshark, Cisco Packet Tracer", style_body)
        ],
        [
            Paragraph("<b>Languages &amp; Tools:</b>", style_body),
            Paragraph("Python (Flask, NumPy, Pandas, Scikit-Learn), C, Bash, PowerShell, REST APIs, Git, Linux (Ubuntu/Debian)", style_body)
        ]
    ]
    t_skills = Table(skills_data, colWidths=[120, 424])
    t_skills.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 0.5),
        ('TOPPADDING', (0, 0), (-1, -1), 0.5),
        ('LEFTPADDING', (0, 0), (-1, -1), 0),
        ('RIGHTPADDING', (0, 0), (-1, -1), 0),
    ]))
    story.append(t_skills)
    story.append(Spacer(1, 2))

    # 4. EXPERIENCE
    story.append(Paragraph("EXPERIENCE", style_section))
    exp_table_data = [
        [
            Paragraph("<b>Krutanic Solutions</b> — <i>Cyber Security Intern</i>", style_job_title),
            Paragraph("Feb 2026 – Apr 2026 | Bangalore, India", style_job_meta)
        ]
    ]
    t_exp = Table(exp_table_data, colWidths=[370, 174])
    t_exp.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 0),
        ('RIGHTPADDING', (0, 0), (-1, -1), 0),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 1),
    ]))
    story.append(t_exp)
    story.append(Paragraph("• Monitored network traffic, firewall telemetry, and endpoint logs using packet inspection tools and SIEM platforms to detect anomalous intrusion indicators.", style_bullet))
    story.append(Paragraph("• Analyzed authentication and access logs to detect brute-force attempts and policy violations; assisted in vulnerability assessments and threat mapping.", style_bullet))
    story.append(Paragraph("• Collaborated on standard incident handling workflows aligned with security best practices and network defense policies.", style_bullet))
    story.append(Spacer(1, 2))

    # 5. PROJECTS
    story.append(Paragraph("PROJECTS", style_section))

    # Project 1: VIRA-SecAgent
    p1_head = [
        [
            Paragraph('<b><a href="https://github.com/keerthanreddy08/VIRA-SecAgent"><font color="#0F172A">VIRA-SecAgent: Autonomous Cybersecurity Incident Response Agent</font></a></b> | <a href="https://github.com/keerthanreddy08/VIRA-SecAgent"><font color="#0284C7">GitHub</font></a>', style_job_title),
            Paragraph("Python, RAG, ReAct, MITRE ATT&amp;CK, Wazuh", style_job_meta)
        ]
    ]
    t_p1 = Table(p1_head, colWidths=[370, 174])
    t_p1.setStyle(TableStyle([('VALIGN', (0, 0), (-1, -1), 'TOP'), ('LEFTPADDING', (0, 0), (-1, -1), 0), ('RIGHTPADDING', (0, 0), (-1, -1), 0), ('BOTTOMPADDING', (0, 0), (-1, -1), 0.5)]))
    story.append(t_p1)
    story.append(Paragraph("• Designed an autonomous SOC Copilot implementing a 5-stage cognitive reasoning loop (ReAct) to ingest, normalize, and triage heterogeneous SIEM telemetry (Wazuh JSON, Windows Event 4688, Sysmon, Syslog).", style_bullet))
    story.append(Paragraph("• Built a sub-millisecond semantic RAG retriever indexing the MITRE ATT&amp;CK Enterprise Matrix and NIST SP 800-61 playbooks, achieving 100% top-1 technique resolution across benchmark attack vectors.", style_bullet))
    story.append(Paragraph("• Synthesized active containment scripts (Linux iptables/ufw drop rules, Windows PowerShell quarantine, AD lockout) and auto-generated universal Sigma detection rules (YAML) for instant SIEM ingestion.", style_bullet))
    story.append(Paragraph("• Developed a real-time SecOps dashboard and REST API featuring interactive reasoning traces, dynamic risk scoring (0–100), and automated incident audit reports.", style_bullet))
    story.append(Spacer(1, 2))

    # Project 2: SIEM Enterprise Monitoring
    p2_head = [
        [
            Paragraph('<b><a href="https://github.com/keerthanreddy08/SIEM-Implementation"><font color="#0F172A">Enterprise SIEM Log Analysis &amp; Threat Detection System</font></a></b> | <a href="https://github.com/keerthanreddy08/SIEM-Implementation"><font color="#0284C7">GitHub</font></a>', style_job_title),
            Paragraph("Wazuh, Security Onion, Elastic Stack, OSSEC", style_job_meta)
        ]
    ]
    t_p2 = Table(p2_head, colWidths=[370, 174])
    t_p2.setStyle(TableStyle([('VALIGN', (0, 0), (-1, -1), 'TOP'), ('LEFTPADDING', (0, 0), (-1, -1), 0), ('RIGHTPADDING', (0, 0), (-1, -1), 0), ('BOTTOMPADDING', (0, 0), (-1, -1), 0.5)]))
    story.append(t_p2)
    story.append(Paragraph("• Implemented centralized security log aggregation and correlation across multi-node Linux and Windows servers using Wazuh, Security Onion, and Elastic Stack.", style_bullet))
    story.append(Paragraph("• Configured custom detection rules to pinpoint SSH/RDP brute-force attacks, unauthorized privilege escalation, and suspicious lateral movement in real time.", style_bullet))
    story.append(Spacer(1, 2))

    # Project 3: SmartLoan Explainable AI
    p3_head = [
        [
            Paragraph('<b><a href="https://github.com/keerthanreddy08/smartloan"><font color="#0F172A">SmartLoan: Explainable AI Loan Eligibility &amp; Risk Engine</font></a></b> | <a href="https://github.com/keerthanreddy08/smartloan"><font color="#0284C7">GitHub</font></a>', style_job_title),
            Paragraph("Python, Scikit-Learn, XGBoost, SHAP, Pandas", style_job_meta)
        ]
    ]
    t_p3 = Table(p3_head, colWidths=[370, 174])
    t_p3.setStyle(TableStyle([('VALIGN', (0, 0), (-1, -1), 'TOP'), ('LEFTPADDING', (0, 0), (-1, -1), 0), ('RIGHTPADDING', (0, 0), (-1, -1), 0), ('BOTTOMPADDING', (0, 0), (-1, -1), 0.5)]))
    story.append(t_p3)
    story.append(Paragraph("• Built an end-to-end risk assessment system integrating XGBoost and Random Forest models to evaluate multi-factor applicant financial profiles.", style_bullet))
    story.append(Paragraph("• Integrated explainable AI using SHAP values to decode feature importance and provide transparent, auditable decision boundaries.", style_bullet))
    story.append(Spacer(1, 2))

    # 6. EDUCATION
    story.append(Paragraph("EDUCATION", style_section))
    edu_data = [
        [
            Paragraph("<b>ACE Engineering College</b> — B.Tech in CSE (Artificial Intelligence &amp; Machine Learning)", style_body),
            Paragraph("Aug 2023 – May 2027 | Hyderabad, India", style_job_meta)
        ],
        [
            Paragraph("<b>Masters Junior College</b> — MPC (Senior Secondary Education)", style_body),
            Paragraph("Jun 2021 – Apr 2023 | Hyderabad, India", style_job_meta)
        ]
    ]
    t_edu = Table(edu_data, colWidths=[360, 184])
    t_edu.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 0),
        ('RIGHTPADDING', (0, 0), (-1, -1), 0),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 0.5),
        ('TOPPADDING', (0, 0), (-1, -1), 0.5),
    ]))
    story.append(t_edu)
    story.append(Spacer(1, 2))

    # 7. CERTIFICATIONS
    story.append(Paragraph("CERTIFICATIONS &amp; TRAINING", style_section))
    story.append(Paragraph("• <b>Cyber Security Internship Certification</b> — Krutanic Solutions", style_bullet))
    story.append(Paragraph("• <b>Exploring Networking &amp; Infrastructure</b> — Cisco Packet Tracer", style_bullet))
    story.append(Paragraph("• <b>Programming Essentials in C</b> — Cisco Networking Academy", style_bullet))

    doc.build(story)
    print(f"[+] Successfully generated 1-page ATS Resume PDF at: {output_path}")


if __name__ == "__main__":
    desktop_output = r"C:\Users\DHEEKSHITH REDDY\Desktop\Kandhakatla_Keerthan_Reddy_Updated_Resume.pdf"
    generate_pdf_resume(desktop_output)
