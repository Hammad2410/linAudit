import os
import re
import json
import textwrap
from collections import defaultdict
from dotenv import load_dotenv

import streamlit as st

# PDF generation library (please install: pip install fpdf)
from fpdf import FPDF

# Import LangChain Groq model and helper classes
from langchain_groq import ChatGroq
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain.schema.output_parser import StrOutputParser

load_dotenv()

# ====================================
# Configuration & Model Setup
# ====================================
API_KEY = os.getenv("GROQ_API_KEY")
if not API_KEY:
    st.error("API_KEY must be set in your .env file.")
    st.stop()

# Initialize the ChatGroq model
model = ChatGroq(
    model="llama3-70b-8192",
    temperature=0.3,
    max_tokens=None,
    timeout=15,
    max_retries=5,
    api_key=API_KEY
)

# Adjust these values as needed
LLM_INPUT_LIMIT = 1500
CHUNK_SIZE = 1000
MAX_CHUNKS_PER_ANALYSIS = 2

text_splitter = RecursiveCharacterTextSplitter(
    chunk_size=CHUNK_SIZE,
    chunk_overlap=100,
    length_function=len,
)

# ====================================
# Helper Functions for Log Processing
# ====================================
def split_log_into_sections(file_content, current_filename):
    """
    Splits a very large log file (plain text) into sections.
    This version looks for lines like:
       ===== Section 1 - System Information =====
    or
       ===== Section 5 - Installed Software =====

    If no such marker is found, returns one section named "Full Log".
    """
    # We look for "===== ... =====" with any text in between
    sections = re.split(r'===== (.*?) =====', file_content)
    logs = []

    if len(sections) > 1:
        # sections list structure:
        # [pre_text, section_header1, section_text1, section_header2, section_text2, ...]
        for i in range(1, len(sections), 2):
            section_name = sections[i].strip()
            section_content = sections[i + 1].strip() if (i + 1) < len(sections) else ""
            logs.append({
                "Section": section_name,
                "Data": {"log": section_content},
                "_filename": current_filename
            })
    else:
        # If no sections found, create a single section
        logs.append({
            "Section": "Full Log",
            "Data": {"log": file_content},
            "_filename": current_filename
        })
    return logs

def group_logs_by_section(logs):
    """Group log entries by their 'Section' field."""
    grouped = defaultdict(list)
    for entry in logs:
        section = entry.get("Section", "Unknown")
        grouped[section].append(entry)
    return grouped

def merge_section_data(entries):
    """Merge the 'Data' dictionaries from multiple parts of the same section."""
    merged = {}
    for entry in entries:
        data = entry.get("Data", {})
        merged.update(data)
    return merged

def chunk_large_text(text):
    """Chunk a large text into smaller pieces that fit within the LLM input limit."""
    return text_splitter.split_text(text)

def extract_important_segments(text):
    """
    Extract important segments from the log that may be security or audit related.
    We capture several lines of context around each match to provide minimal context.
    """
    # Expanded set of keywords for security & audit
    keywords = [
        "error", "failed", "denied", "critical", "warning",
        "exception", "fatal", "audit", "security", "vulnerability",
        "unauthorized", "breach", "intrusion", "iptables", "firewall",
        "selinux", "suid", "sgid", "world-writable", "ssh"
    ]

    lines = text.split('\n')
    important_lines = []
    context_lines = 3  # Number of lines before and after the important line

    for i, line in enumerate(lines):
        lower_line = line.lower()
        if any(keyword in lower_line for keyword in keywords):
            start = max(0, i - context_lines)
            end = min(len(lines), i + context_lines + 1)

            # Add header if this is a new segment
            if not important_lines or important_lines[-1] != "...":
                if important_lines:
                    important_lines.append("...")
                important_lines.append(f"--- Context around line {i+1} ---")

            # Add the context lines
            important_lines.extend(lines[start:end])

            # Add a separator if more lines are likely
            if end < len(lines):
                important_lines.append("...")

    if not important_lines:
        # If no important segments found, return a brief summary of the log
        total_lines = len(lines)
        sample_size = min(10, total_lines)

        important_lines.append("--- Log Summary (No critical security/audit issues found) ---")
        important_lines.append(f"Total lines: {total_lines}")
        important_lines.append("First few lines:")
        important_lines.extend(lines[:sample_size])
        if total_lines > sample_size:
            important_lines.append("...")
            important_lines.append("Last few lines:")
            important_lines.extend(lines[-sample_size:])

    return "\n".join(important_lines)

def detailed_analysis(merged_data):
    """
    Simple keyword search to detect potential issues with a focus on security and audit.
    Returns a dict mapping each key to a list of found keywords.
    """
    # Expanded set of keywords for basic detection
    keywords = [
        "error", "failed", "denied", "critical", "warning",
        "audit", "security", "breach", "unauthorized", "vulnerability",
        "intrusion", "exception", "fatal", "iptables", "firewall", 
        "selinux", "suid", "sgid", "world-writable", "ssh"
    ]
    issues = {}
    for key, value in merged_data.items():
        if isinstance(value, str):
            lower_value = value.lower()
            found = [term for term in keywords if term in lower_value]
            if found:
                issues[key] = list(set(found))  # Unique matches
    return issues

def create_master_report(grouped_logs):
    """
    For each section, merge all parts and process the data to handle large logs.
    Returns a dictionary (master report) with statistics and chunked data.
    """
    master_report = {}
    for section, entries in grouped_logs.items():
        merged_data = merge_section_data(entries)
        file_parts = [entry.get("_filename", "unknown") for entry in entries]

        section_info = {
            "total_entries": len(merged_data),
            "keys": list(merged_data.keys()),
            "file_parts": file_parts,
            "detailed_issues": detailed_analysis(merged_data)
        }

        # For each large text field, create chunks and important segments
        for key, value in merged_data.items():
            if isinstance(value, str) and len(value) > LLM_INPUT_LIMIT:
                # Extract important segments
                important_segments = extract_important_segments(value)
                # Create chunks of the full text
                chunks = chunk_large_text(value)

                # Store metadata about the chunking
                merged_data[key] = {
                    "original_length": len(value),
                    "chunks": chunks,
                    "chunk_count": len(chunks),
                    "important_segments": important_segments
                }

        section_info["full_data"] = merged_data
        master_report[section] = section_info

    return master_report

# ====================================
# AI Insights via ChatGroq (LangChain)
# ====================================
def safe_chunk_analysis(chunk, section, key, model, chunk_num, total_chunks):
    """
    Helper to safely analyze a single chunk with a security/audit focus.
    """
    try:
        chunk_prompt = (
            f"You are a system security auditor. Analyze this log segment ({chunk_num}/{total_chunks}) "
            f"focusing on key security or compliance issues:\n\n"
            f"{chunk[:1000]}\n\n"
            "Please keep the response under 100 words."
        )

        messages = [
            {"role": "system", "content": "You are a concise system security auditor providing brief but relevant findings."},
            {"role": "user", "content": chunk_prompt}
        ]

        response = model.invoke(messages)
        return f"Chunk {chunk_num}: {response.content}"
    except Exception as e:
        return f"Chunk {chunk_num}: Analysis failed - {str(e)}"

def generate_section_insights(master_report):
    """
    Enhanced section insights with more detailed, security-audit-focused analysis.
    """
    for section, info in master_report.items():
        try:
            full_data = info.get("full_data", {})
            all_insights = []

            # Analyze only the "important_segments" of chunked data
            for key, value in full_data.items():
                if isinstance(value, dict) and "chunks" in value:
                    important_segments = value.get("important_segments", "")
                    # Optionally chunk the important segments if too large
                    if len(important_segments) > CHUNK_SIZE:
                        important_chunks = text_splitter.split_text(important_segments)
                        important_chunks = important_chunks[:MAX_CHUNKS_PER_ANALYSIS]
                    else:
                        important_chunks = [important_segments]

                    for i, chunk in enumerate(important_chunks, 1):
                        insight = safe_chunk_analysis(chunk, section, key, model, i, len(important_chunks))
                        all_insights.append(insight)

            # Generate a final consolidated analysis for the section
            final_prompt = f"""
You are a security-focused IT auditor reviewing logs. Provide a thorough analysis for section '{section}' using the insights below.

Insights:
{chr(10).join(all_insights[:5])}

Structure your response with:
## Summary
(Brief overview of key security findings)

## Critical Issues
(Prioritized list of serious security or compliance problems)

## Security Assessment
(Focus on vulnerabilities, misconfigurations, unauthorized access, etc.)

## Technical Details
(Any important logs or commands of note)

## Recommendations
(Clear steps to address discovered issues)

Keep the entire answer concise but relevant.
"""
            messages = [
                {"role": "system", "content": "You are a security auditor analyzing system logs."},
                {"role": "user", "content": final_prompt}
            ]

            response = model.invoke(messages)
            master_report[section]["ai_insights"] = response.content

        except Exception as e:
            master_report[section]["ai_insights"] = f"""
## Limited Analysis Available

Reason: {str(e)}
Key points from available data:
{chr(10).join(all_insights[:3])}

## Recommendations
- Break this section into smaller segments
- Focus on reviewing important or suspicious lines
- Perform a manual review for thoroughness
"""

    return master_report

def generate_executive_summary(master_report):
    """
    Generates a top-level executive summary with a strong security/audit focus.
    """
    summary_sections = {
        "overview": [],
        "critical_issues": [],
        "security_concerns": [],
        "recommendations": []
    }

    # Collect stats
    total_sections = len(master_report)
    total_entries = sum(info.get("total_entries", 0) for info in master_report.values())

    for section, info in master_report.items():
        # Overview
        summary_sections["overview"].append(f"- {section}: {info.get('total_entries')} entries")

        # Issues
        if info.get("detailed_issues"):
            for key, issues in info.get("detailed_issues", {}).items():
                # Rough severity mapping
                severity_map = {
                    'critical': ['fatal', 'critical', 'breach', 'intrusion'],
                    'high': ['error', 'security', 'unauthorized', 'vulnerability'],
                    'medium': ['warning', 'failed', 'denied', 'iptables', 'firewall', 'selinux'],
                    'low': ['audit', 'exception', 'suid', 'sgid', 'world-writable', 'ssh']
                }
                for issue in issues:
                    for severity, keywords in severity_map.items():
                        if issue in keywords:
                            context = f"[{severity.upper()}] {section}: {key} - {issue}"
                            if severity in ['critical', 'high']:
                                summary_sections["critical_issues"].append(context)
                            summary_sections["security_concerns"].append(context)

    # Recommendations logic
    if summary_sections["critical_issues"]:
        summary_sections["recommendations"].extend([
            "- Investigate critical findings immediately (breach, intrusion, critical logs)",
            "- Implement stricter firewall/iptables rules and SELinux enforcement if applicable",
            "- Review user privileges and authentication configurations"
        ])
    else:
        summary_sections["recommendations"].extend([
            "- Continue routine security monitoring",
            "- Maintain current security controls",
            "- Schedule periodic system audits and backups"
        ])

    # Format the final executive summary
    executive_summary = f"""
# Executive Summary (Security Audit Focus)

## Overview
Total Sections Analyzed: {total_sections}
Total Log Entries: {total_entries}

{chr(10).join(summary_sections["overview"][:10])}

## Critical Issues ({len(summary_sections["critical_issues"])} total)
{chr(10).join(summary_sections["critical_issues"][:10]) if summary_sections["critical_issues"] else "No critical issues detected."}

## Security Concerns
{chr(10).join(summary_sections["security_concerns"][:15]) if summary_sections["security_concerns"] else "No significant security concerns identified."}

## Key Recommendations
{chr(10).join(summary_sections["recommendations"])}

Note: This summary highlights the most significant findings. Review the detailed analysis for complete information.
"""

    # Optionally refine the summary with the AI
    try:
        enhancement_prompt = f"""
You are a security and compliance expert. Polish this executive summary:
{executive_summary}

Focus on:
1. Risk assessment
2. Potential compliance gaps
3. Actionable recommendations
Keep it concise and well-structured.
"""
        messages = [
            {"role": "system", "content": "You are a specialized security auditor summarizing high-level findings."},
            {"role": "user", "content": enhancement_prompt}
        ]
        response = model.invoke(messages)
        return response.content
    except Exception:
        return executive_summary

# ====================================
# New: Compute Scores for Each File (Security-Focused)
# ====================================
def score_log_file_content(file_content, model):
    """
    Uses AI to score the log file in multiple categories with a security focus:
    1) Security
    2) Vulnerability
    3) Hardening (instead of Performance)
    4) Compliance

    Then provides a cumulative average and a short reason.
    We require EXACT 6 lines of output in the form:

    Security: X
    Vulnerability: X
    Hardening: X
    Compliance: X
    Cumulative: X
    Reason: Short explanation

    Where X = numeric score from 1..10
    """
    truncated_text = file_content[:1000]
    score_prompt = f"""
You are a system security auditor scoring this log file in four categories:
1. Security
2. Vulnerability
3. Hardening
4. Compliance

Then provide:
- Cumulative: (average of the four above)
- Reason: (max 2 sentences about why you assigned these scores)

Output exactly 6 lines, each beginning with:
Security:
Vulnerability:
Hardening:
Compliance:
Cumulative:
Reason:

Example output:
Security: 8
Vulnerability: 7
Hardening: 6
Compliance: 7
Cumulative: 7
Reason: Found some suspicious login attempts but no critical vulnerabilities.

Log file content (truncated):
{truncated_text}
"""
    messages = [
        {"role": "system", "content": "You are an expert security auditor providing numeric scores and short reasons."},
        {"role": "user", "content": score_prompt}
    ]

    try:
        response = model.invoke(messages)
        text = response.content

        scores = {
            "Security": None,
            "Vulnerability": None,
            "Hardening": None,
            "Compliance": None,
            "Cumulative": None,
            "Reason": ""
        }

        for line in text.split("\n"):
            line_lower = line.lower().strip()
            if line_lower.startswith("security:"):
                scores["Security"] = extract_score(line)
            elif line_lower.startswith("vulnerability:"):
                scores["Vulnerability"] = extract_score(line)
            elif line_lower.startswith("hardening:"):
                scores["Hardening"] = extract_score(line)
            elif line_lower.startswith("compliance:"):
                scores["Compliance"] = extract_score(line)
            elif line_lower.startswith("cumulative:"):
                scores["Cumulative"] = extract_score(line)
            elif line_lower.startswith("reason:"):
                reason_part = line.split(":", 1)[1].strip()
                scores["Reason"] += reason_part

        # Fallback if any are missing
        for k, v in scores.items():
            if v is None and k != "Reason":
                scores[k] = 0.0

        # Compute a fallback cumulative if not returned
        if not scores["Cumulative"]:
            s = (scores["Security"] + scores["Vulnerability"] +
                 scores["Hardening"] + scores["Compliance"]) / 4.0
            scores["Cumulative"] = round(s, 1)

        return scores
    except Exception as e:
        return {
            "Security": 0, 
            "Vulnerability": 0, 
            "Hardening": 0,
            "Compliance": 0,
            "Cumulative": 0,
            "Reason": f"Scoring failed: {str(e)}"
        }

def extract_score(line):
    """
    A helper to extract the numeric score from a line like "Security: 8".
    If it fails, returns 0.
    """
    try:
        parts = line.split(":")
        number_part = parts[1].strip()
        # Keep only digits or possible decimal
        match = re.findall(r"[\d\.]+", number_part)
        if match:
            return float(match[0])
        else:
            return 0.0
    except:
        return 0.0

# ====================================
# Generate PDF Report
# ====================================
class PDFReport(FPDF):
    def header(self):
        self.set_font("Arial", "B", 12)
        self.cell(0, 10, "Detailed Security Audit Log Analysis", ln=True, align="C")
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font("Arial", "I", 10)
        self.cell(0, 10, f"Page {self.page_no()}", 0, 0, "C")

def create_pdf_report(master_report, file_scores, executive_summary):
    pdf = PDFReport()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    # Executive Summary at the top
    pdf.multi_cell(0, 5, executive_summary.strip())
    pdf.ln(10)

    # Scores for each file
    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, "File-Level Security Scores:", ln=True)
    pdf.set_font("Arial", size=12)

    for filename, scores in file_scores.items():
        pdf.cell(0, 10, f"Filename: {filename}", ln=True)
        pdf.cell(0, 5, f"  - Security: {scores['Security']}", ln=True)
        pdf.cell(0, 5, f"  - Vulnerability: {scores['Vulnerability']}", ln=True)
        pdf.cell(0, 5, f"  - Hardening: {scores['Hardening']}", ln=True)
        pdf.cell(0, 5, f"  - Compliance: {scores['Compliance']}", ln=True)
        pdf.cell(0, 5, f"  - Cumulative: {scores['Cumulative']}", ln=True)
        pdf.cell(0, 5, f"  - Reason: {scores['Reason']}", ln=True)
        pdf.ln(5)

    pdf.ln(10)
    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, "Detailed Section Analysis:", ln=True)
    pdf.set_font("Arial", size=12)

    # Loop through master_report
    for section, info in master_report.items():
        pdf.ln(5)
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 10, f"Section: {section}", ln=True)
        pdf.set_font("Arial", size=12)
        pdf.cell(0, 5, f"Total Entries: {info.get('total_entries', 0)}", ln=True)
        pdf.cell(0, 5, f"Keys: {', '.join(info.get('keys', []))}", ln=True)
        pdf.cell(0, 5, f"Source Files: {', '.join(info.get('file_parts', []))}", ln=True)
        pdf.ln(5)

        # AI insights (analysis) if available
        ai_insights = info.get("ai_insights", "No AI insights available.")
        pdf.multi_cell(0, 5, ai_insights.strip())
        pdf.ln(5)

    # Return the PDF as bytes
    return pdf.output(dest="S").encode("latin-1")

# ====================================
# Streamlit Interface
# ====================================

# Add this near the top of the file with other imports
from datetime import datetime

# Add this function before the main() function
def add_footer():
    """Adds a disclaimer footer to the Streamlit app"""
    current_year = datetime.now().year
    
    footer_html = f'''
    <style>
        div[data-testid="stToolbar"] {{
            display: none;
        }}
        footer {{
            position: fixed;
            bottom: 0;
            left: 0;
            width: 100%;
            background-color: #f0f2f6;
            padding: 10px;
            text-align: center;
            border-top: 1px solid #e0e0e0;
            font-size: 0.8em;
            z-index: 999;
        }}
        footer p {{
            color: #666;
            margin: 0;
            padding: 2px;
        }}
    </style>
    <footer>
        <p>🔒 <b>Security & Privacy Disclaimer</b></p>
        <p>This tool uses AI-powered analysis through external API calls. All uploaded log data is processed using the Groq API.</p>
        <p>Data Privacy Notice: Log contents are transmitted to external AI services for analysis. Do not upload sensitive or confidential information.</p>
        <p>Results are AI-generated and should be verified by security professionals. Not a replacement for professional security auditing.</p>
        <p>© {current_year} AI Cyber Auditor | Using Groq API</p>
        <p><b>Important:</b> This is an AI-based tool. All data submitted will be processed by online AI models.</p>
    </footer>
    '''
    
    st.markdown(footer_html, unsafe_allow_html=True)


def main():
    st.set_page_config(page_title="Log Analysis with Gelecek AI", layout="wide")

    st.title("🔒 Advanced Security-Focused Log Analysis")
    st.markdown("""
    ### Upload your `.log` or `.txt` files  detailed security and audit assessment.
    """)

    uploaded_files = st.file_uploader("Upload log files", type=["log", "txt"], accept_multiple_files=True)

    all_logs = []
    file_scores = {}  # Will store the top-level security scores for each file

    if uploaded_files:
        with st.spinner("Processing log files..."):
            for uploaded_file in uploaded_files:
                filename = uploaded_file.name
                try:
                    file_content = uploaded_file.read().decode("utf-8")

                    # Split into sections
                    logs = split_log_into_sections(file_content, filename)
                    all_logs.extend(logs)

                    # Compute file-level scores (AI call)
                    scores = score_log_file_content(file_content, model)
                    file_scores[filename] = scores

                    st.success(f"✅ Processed: {filename}")
                except Exception as e:
                    st.error(f"❌ Error processing {filename}: {e}")

    if not all_logs:
        st.info("👆 Please upload your `.log` or `.txt` files to begin analysis.")
        return

    # Display top-level scoreboard for each file
    st.header("📈 File-Level Security Scores")
    for fname, scores in file_scores.items():
        st.subheader(f"File: {fname}")
        col1, col2, col3, col4, col5 = st.columns(5)
        col1.metric("Security", scores["Security"])
        col2.metric("Vulnerability", scores["Vulnerability"])
        col3.metric("Hardening", scores["Hardening"])
        col4.metric("Compliance", scores["Compliance"])
        col5.metric("Cumulative", scores["Cumulative"])
        st.caption(f"**Reason**: {scores['Reason']}")
        st.divider()

    # Group logs by section and create master report
    with st.spinner("Building master report..."):
        grouped_logs = group_logs_by_section(all_logs)
        master_report = create_master_report(grouped_logs)

    st.header("📊 Master Report Summary")

    col1, col2 = st.columns([1, 1])
    with col1:
        st.metric("Total Sections", len(master_report))
    with col2:
        total_issues = sum(len(info.get('detailed_issues', {})) for info in master_report.values())
        st.metric("Sections With Potential Issues", total_issues)

    # Show minimal summary of each section
    for section, info in master_report.items():
        with st.expander(f"Section: {section}", expanded=False):
            st.markdown(f"### 📁 {section}")
            st.markdown(f"**Total Entries:** {info.get('total_entries')}")
            st.markdown("**Keys Present:**")
            st.code(", ".join(info.get("keys", ["None"])))

            st.markdown("**Source Files:**")
            for file in info.get("file_parts", []):
                st.markdown(f"- `{file}`")

            st.markdown("**Potentially Relevant Logs:**")
            for key, value in info.get("full_data", {}).items():
                if isinstance(value, dict) and "chunks" in value:
                    st.markdown(f"- `{key}`: {value['original_length']} characters, split into {value['chunk_count']} chunks")
                    if st.checkbox(f"Show important segments for {key} ({section})", key=f"impseg_{section}_{key}"):
                        st.markdown("#### Important Security Segments:")
                        st.code(value.get("important_segments", "No important segments found."))
                else:
                    if isinstance(value, str):
                        st.markdown(f"- `{key}`: {len(value)} characters (not chunked)")
                    else:
                        st.markdown(f"- `{key}`: {type(value)}")

            # Issues
            if info.get("detailed_issues"):
                st.markdown("**⚠️ Issues Detected (keyword-based):**")
                for k, found_terms in info["detailed_issues"].items():
                    st.markdown(f"- `{k}`: {', '.join(found_terms)}")
            else:
                st.markdown("**Issues Detected:** None 👍")

    st.header("🤖 AI-Powered Security Analysis")
    if st.button("Generate AI Insights", type="primary"):
        with st.spinner("Analyzing logs with AI... Please wait."):
            master_report = generate_section_insights(master_report)
            executive_summary = generate_executive_summary(master_report)

        st.success("✅ Analysis complete!")
        st.subheader("📝 Executive Summary")
        st.markdown(executive_summary)

        st.subheader("📋 Detailed Section Analysis")
        for section, info in master_report.items():
            with st.expander(f"Detailed Analysis: {section}", expanded=False):
                st.markdown(info.get("ai_insights", "No insights available."))

        # Now prepare the PDF
        with st.spinner("Generating PDF report..."):
            pdf_bytes = create_pdf_report(master_report, file_scores, executive_summary)

        st.download_button(
            label="Download Detailed Audit Report (PDF)",
            data=pdf_bytes,
            file_name="security_audit_report.pdf",
            mime="application/pdf"
        )
    st.markdown('<div style="padding-bottom: 100px;"></div>', unsafe_allow_html=True)
    add_footer()
if __name__ == "__main__":
    main()
