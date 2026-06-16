"""Trust-Headers Streamlit application."""

from __future__ import annotations

import hashlib
from dataclasses import asdict

import streamlit as st

from trust_headers.analysis import analyze_email
from trust_headers.intel import enrich_sync
from trust_headers.parser import ParseError, parse_email
from trust_headers.report import build_report, build_soc_notes

st.set_page_config(
    page_title="Trust-Headers // SOC Mail Analyzer",
    layout="wide",
    initial_sidebar_state="collapsed",
)


@st.cache_data(ttl=900, show_spinner=False, max_entries=256)
def cached_enrichment(
    ips: tuple[str, ...],
    domains: tuple[str, ...],
    key_fingerprint: str,
    _api_keys: dict[str, str],
) -> list[dict[str, str]]:
    del key_fingerprint
    return enrich_sync(ips, domains, _api_keys)


def load_api_keys() -> dict[str, str]:
    names = (
        "ABUSEIPDB_API_KEY",
        "OTX_API_KEY",
        "VIRUSTOTAL_API_KEY",
        "THREATFOX_API_KEY",
    )
    try:
        return {name: str(st.secrets.get(name, "")) for name in names}
    except Exception:
        return {name: "" for name in names}


def inject_styles() -> None:
    st.markdown(
        """
        <style>
        :root {
          --ink: #101010;
          --paper: #fff8d8;
          --cyan: #00f5ff;
          --magenta: #ff2bb5;
          --lime: #b7ff2a;
          --blue: #1937ff;
        }
        .stApp {
          background-color: var(--paper);
          background-image: linear-gradient(rgba(20,20,20,.045) 1px, transparent 1px),
                            linear-gradient(90deg, rgba(20,20,20,.045) 1px, transparent 1px);
          background-size: 16px 16px;
          color: var(--ink);
        }
        html, body, [class*="css"] { font-family: "Courier New", monospace; }
        .block-container { padding: .75rem 1.2rem 1.5rem; max-width: 1800px; }
        h1, h2, h3 {
          font-family: "Arial Black", Impact, sans-serif !important;
          text-transform: uppercase;
          letter-spacing: -.04em;
        }
        h1 {
          color: var(--blue);
          text-shadow: 3px 3px 0 var(--cyan), 6px 6px 0 var(--magenta);
          margin: 0 0 .15rem !important;
        }
        [data-testid="stVerticalBlockBorderWrapper"] {
          border: 3px solid var(--ink) !important;
          box-shadow: 5px 5px 0 var(--blue);
          background: rgba(255,255,255,.8);
        }
        .stButton > button, .stDownloadButton > button {
          border: 3px outset #fff !important;
          border-right-color: #333 !important;
          border-bottom-color: #333 !important;
          border-radius: 0 !important;
          color: #fff !important;
          background: var(--blue) !important;
          font-family: "Courier New", monospace !important;
          font-weight: bold !important;
          text-transform: uppercase;
        }
        .stButton > button:hover, .stDownloadButton > button:hover {
          color: var(--ink) !important;
          background: var(--lime) !important;
          border-color: var(--ink) !important;
        }
        textarea, [data-testid="stFileUploaderDropzone"], [data-baseweb="input"] {
          border-radius: 0 !important;
          border: 2px solid var(--ink) !important;
          background: #fff !important;
        }
        [data-baseweb="tab-list"] {
          gap: 3px;
          border-bottom: 3px solid var(--ink);
        }
        [data-baseweb="tab"] {
          border: 2px solid var(--ink);
          border-bottom: 0;
          background: #ddd;
          font-weight: bold;
        }
        [aria-selected="true"] { background: var(--cyan) !important; color: var(--ink) !important; }
        [data-testid="stMetric"] {
          border: 2px solid var(--ink);
          background: #fff;
          padding: .35rem .55rem;
          box-shadow: 3px 3px 0 var(--magenta);
        }
        [data-testid="stAlert"] { border: 2px solid var(--ink); border-radius: 0; }
        [data-testid="stStatusWidget"] {
          border: 3px dashed var(--blue);
          border-radius: 0;
          background: var(--cyan);
        }
        .marquee {
          border: 2px solid var(--ink);
          background: var(--ink);
          color: var(--lime);
          padding: .2rem .5rem;
          font-weight: bold;
          white-space: nowrap;
          overflow: hidden;
        }
        .tiny { font-size: .75rem; }
        </style>
        """,
        unsafe_allow_html=True,
    )


def header_rows(groups: dict[str, dict[str, list[str]]]) -> list[dict[str, str]]:
    return [
        {"Group": group, "Header": name, "Value": value}
        for group, headers in groups.items()
        for name, values in headers.items()
        for value in values
    ]


def render_results() -> None:
    result = st.session_state.get("analysis_result")
    if not result:
        st.info("Awaiting header payload. Local checks and intel will appear here.")
        return
    intel = st.session_state.get("intel_results", [])
    parsed = result.parsed
    parsed_urls = getattr(parsed, "urls", [])

    verdict_col, anomaly_col, ip_col, domain_col, attachment_col = st.columns(5)
    verdict_col.metric("VERDICT", result.verdict)
    anomaly_col.metric("ANOMALIES", result.anomaly_count)
    ip_col.metric("PUBLIC IPs", len(parsed.originating_ips))
    domain_col.metric("DOMAINS", len(parsed.domains))
    attachment_col.metric("ATTACHMENTS", len(parsed.attachments))

    findings_tab, artifacts_tab, intel_tab, export_tab = st.tabs(
        ["LOCAL CHECKS", "ARTIFACTS", "THREAT INTEL", "EXPORT"],
        default="EXPORT",
    )
    with findings_tab:
        st.dataframe(
            [asdict(finding) for finding in result.findings],
            width="stretch",
            hide_index=True,
            column_order=("status", "rule", "summary", "evidence"),
        )
    with artifacts_tab:
        st.caption("Only security-relevant headers are retained for analysis.")
        rows = header_rows(
            {
                "Sender": parsed.sender_headers,
                "Routing": parsed.routing_headers,
                "Authentication": parsed.authentication_headers,
            }
        )
        st.dataframe(rows, width="stretch", hide_index=True)
        if parsed.attachments:
            st.dataframe(
                [asdict(item) for item in parsed.attachments],
                width="stretch",
                hide_index=True,
            )
        if parsed_urls:
            st.dataframe(
                [{"URL": url} for url in parsed_urls],
                width="stretch",
                hide_index=True,
            )
    with intel_tab:
        if intel:
            st.dataframe(
                intel,
                width="stretch",
                hide_index=True,
                column_order=("source", "indicator", "kind", "status", "summary"),
            )
        else:
            st.info("No enrichment results. Enable enrichment and provide an email with public indicators.")
    with export_tab:
        soc_notes = build_soc_notes(result, intel)
        report = build_report(result, intel)
        st.caption("SOC-READY COPY: paste this narrative into the investigation notes.")
        st.code(soc_notes, language=None, wrap_lines=True)
        st.download_button(
            "DOWNLOAD SOC-NOTES.TXT",
            data=soc_notes,
            file_name="trust-headers-soc-notes.txt",
            mime="text/plain",
            width="stretch",
        )
        with st.expander("SUPPORTING TECHNICAL REPORT"):
            st.code(report, language=None, wrap_lines=True)
            st.download_button(
                "DOWNLOAD TECHNICAL-REPORT.TXT",
                data=report,
                file_name="trust-headers-technical-report.txt",
                mime="text/plain",
                width="stretch",
            )


def run_analysis(raw_input: bytes | str, filename: str, enrich_enabled: bool) -> None:
    with st.status("INITIALIZING TRUST PIPELINE...", expanded=True) as status:
        status.write("Parsing retained headers and hashing attachments...")
        parsed = parse_email(raw_input, filename)
        result = analyze_email(parsed)
        status.write("Local phishing checks complete.")

        intel: list[dict[str, str]] = []
        if enrich_enabled and (parsed.originating_ips or parsed.domains):
            status.write("Dialing threat-intelligence providers in parallel...")
            keys = load_api_keys()
            fingerprint = hashlib.sha256(
                "|".join(keys[name] for name in sorted(keys)).encode()
            ).hexdigest()
            intel = cached_enrichment(
                tuple(parsed.originating_ips),
                tuple(parsed.domains),
                fingerprint,
                keys,
            )
            status.write("Threat-intelligence calls complete.")
        else:
            status.write("Threat-intelligence enrichment skipped.")

        st.session_state.analysis_result = result
        st.session_state.intel_results = intel
        status.update(label="PIPELINE COMPLETE // RESULTS READY", state="complete", expanded=False)


inject_styles()
st.title("TRUST-HEADERS")
st.markdown(
    '<div class="marquee">SOC MAIL ANALYSIS TERMINAL // HEADER-ONLY PROCESSING // NO LOGGING // NO PERSISTENCE</div>',
    unsafe_allow_html=True,
)

input_col, output_col = st.columns([0.82, 1.35], gap="medium")
with input_col:
    with st.container(border=True):
        st.subheader("01 // INPUT")
        uploaded = st.file_uploader("UPLOAD EMAIL", type=("eml", "msg", "txt"))
        pasted = st.text_area(
            "OR PASTE RAW HEADERS",
            height=315,
            placeholder="From: Example <sender@example.com>\nReturn-Path: <bounce@example.com>\n...",
        )
        enrich_enabled = st.checkbox("QUERY THREAT INTEL APIS", value=False)
        st.caption("Data is processed in memory. Body content is discarded; attachments are counted and hashed.")
        analyze_clicked = st.button("ANALYZE TRANSMISSION", type="primary", width="stretch")
        if analyze_clicked:
            if uploaded is not None:
                payload, name = uploaded.getvalue(), uploaded.name
            else:
                payload, name = pasted, "pasted.txt"
            if not payload:
                st.warning("Paste headers or upload an email first.")
            else:
                try:
                    run_analysis(payload, name, enrich_enabled)
                except ParseError as exc:
                    st.error(str(exc))
                except Exception as exc:
                    st.error(f"Analysis failed safely: {exc}")

with output_col:
    with st.container(border=True):
        st.subheader("02 // ANALYSIS")
        render_results()
