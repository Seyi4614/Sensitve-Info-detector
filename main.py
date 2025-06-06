import streamlit as st
from textblob import TextBlob
from docx import Document
import fitz  # PyMuPDF
import io

#  Define sensitive keyword lists
PII_KEYWORDS = ["name", "address", "phone", "email", "social security", "ssn",
                "passport", "driver's license", "dob", "date of birth"]
PHI_KEYWORDS = ["medical", "health", "diagnosis", "treatment", "patient",
                "prescription", "illness", "disease", "clinic", "hospital"]
FIN_KEYWORDS = ["account number", "credit card", "bank", "financial", "invoice",
                "routing number"]

CATEGORY_WEIGHTS = {"PII": 2, "PHI": 3, "Financial": 1}

# Extract Text from Files 
def extract_text(uploaded_file):
    file_name = uploaded_file.name
    if file_name.lower().endswith(".pdf"):
        pdf_bytes = uploaded_file.read()
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        text = ""
        for page in doc:
            text += page.get_text()
        return text
    elif file_name.lower().endswith(".docx"):
        doc = Document(io.BytesIO(uploaded_file.read()))
        full_text = [para.text for para in doc.paragraphs]
        return "\n".join(full_text)
    else:
        return uploaded_file.read().decode("utf-8")

#  Analyze Text from file to detect Sensitive Terms 
def analyze_text(text):
    text_lower = text.lower()
    lines = text_lower.splitlines()

    findings = {"PII": [], "PHI": [], "Financial": []}
    detailed_findings = []
    score = 0

    for i, line in enumerate(lines, start=1):
        for kw in PII_KEYWORDS:
            if kw in line:
                findings["PII"].append(kw)
                detailed_findings.append((i, "PII", kw, line.strip()))
                score += CATEGORY_WEIGHTS["PII"]
        for kw in PHI_KEYWORDS:
            if kw in line:
                findings["PHI"].append(kw)
                detailed_findings.append((i, "PHI", kw, line.strip()))
                score += CATEGORY_WEIGHTS["PHI"]
        for kw in FIN_KEYWORDS:
            if kw in line:
                findings["Financial"].append(kw)
                detailed_findings.append((i, "Financial", kw, line.strip()))
                score += CATEGORY_WEIGHTS["Financial"]

    if score >= 10:
        risk_level = "High Risk"
    elif score >= 5:
        risk_level = "Medium Risk"
    else:
        risk_level = "Low Risk"

    return score, risk_level, findings, detailed_findings

# Generate Text Report
def generate_report(file_name, score, risk_level, findings, detailed_findings):
    report_lines = []
    report_lines.append(f"📄 Report for file: {file_name}")
    report_lines.append(f"Risk Score: {score}")
    report_lines.append(f"Risk Level: {risk_level}")
    report_lines.append("")

    for cat, terms in findings.items():
        if terms:
            report_lines.append(f"{cat} terms found ({len(terms)} occurrences): {', '.join(terms)}")

    report_lines.append("\n--- Detailed Findings ---")
    for line_num, cat, kw, context in detailed_findings:
        report_lines.append(f"Line {line_num} | Category: {cat} | Term: '{kw}' | Context: {context}")

    report_lines.append("\n--- Compliance Guidance ---")
    if findings["PII"]:
        report_lines.append("- GDPR likely applies (PII detected).")
    if findings["PHI"]:
        report_lines.append("- HIPAA rules apply (PHI detected).")
    if findings["Financial"]:
        report_lines.append("- PCI/NIST security controls advised (financial data).")
    if not any(findings.values()):
        report_lines.append("- No sensitive data found. Low risk.")

    return "\n".join(report_lines)

# Streamlit App interface 
st.set_page_config(page_title="Sensitive Data Risk Analyzer", layout="centered")
st.title("🔍 Sensitive Data Risk Analyzer")

uploaded_file = st.file_uploader("Upload a TXT, DOCX, or PDF file", type=["txt", "docx", "pdf"])

if uploaded_file:
    st.success(f"File '{uploaded_file.name}' uploaded successfully.")

    # Step 1: Extract and Analyze
    text = extract_text(uploaded_file)
    score, risk_level, findings, detailed_findings = analyze_text(text)

    # Step 2: Show Risk Metrics
    st.subheader("📊 Analysis Results")
    st.metric("Risk Level", risk_level)
    st.write(f"**Risk Score:** {score}")

    # Step 3: Show Detailed Table
    st.subheader("🧾 Detailed Sensitive Data Findings")
    if detailed_findings:
        for line_num, cat, term, context in detailed_findings:
           st.markdown(f"- **Line {line_num}** | `{cat}` | **Term:** `{term}`  \n_Context:_ `{context}`")

    else:
        st.info("No sensitive terms found.")

    # Step 4: Compliance Recommendations
    st.subheader("📌 Compliance Guidance")
    if findings["PII"]:
        st.write("- Contains **PII** → likely subject to **GDPR**.")
    if findings["PHI"]:
        st.write("- Contains **PHI** → subject to **HIPAA**.")
    if findings["Financial"]:
        st.write("- Contains **Financial Data** → consider **PCI/NIST** standards.")
    if not any(findings.values()):
        st.write("- No sensitive data found.")

    # Step 5: Downloadable Report
    report_text = generate_report(uploaded_file.name, score, risk_level, findings, detailed_findings)
    st.subheader("📥 Download Full Risk Report")
    st.download_button(
        label="Download Risk Report (.txt)",
        data=report_text,
        file_name="risk_report.txt",
        mime="text/plain"
    )
