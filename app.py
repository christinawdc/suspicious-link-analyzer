import streamlit as st
from analyzer import analyze_url

st.set_page_config(page_title="Link-Scan", page_icon="👻")

st.title("👻 Suspicious Link Analyzer")
st.write("Paste a URL to check phishing likelihood")

url = st.text_input("Enter URL")

if st.button("Scan"):
    result = analyze_url(url)

    if not result["valid"]:
        st.error("Invalid URL")
    else:
        risk = result["risk_score"]

        if risk < 30:
            st.success(f"Risk Score: {risk}% (Low)")
        elif risk < 70:
            st.warning(f"Risk Score: {risk}% (Medium)")
        else:
            st.error(f"Risk Score: {risk}% (High)")

        st.divider()

        st.subheader("Analysis Report")

        st.write("**Domain Age:**", result["domain_age"])
        st.write("**Redirects:**", result["redirects"])
        st.write("**Uses IP Address:**", result["uses_ip"])

        st.write("**Suspicious Keywords:**", result["suspicious_keywords"])
        st.write("**Suspicious Parameters:**", result["suspicious_params"])