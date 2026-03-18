import streamlit as st
import pandas as pd
from streamlit_mermaid import st_mermaid
import json
import os
import numpy as np
import time
import hashlib # For content hashing

# --- 0. Page Configuration ---
st.set_page_config(
    page_title="Attestation & PUF Dashboard",
    page_icon="🛡️",
    # layout="centered", # Use centered layout as a base for custom width
    initial_sidebar_state="collapsed"
)


LOGO_PATH = "privateer-logo-only.png" # Make sure this file exists or handle its absence

# --- File Paths for JSON Data ---
BASE_DIR = "/home/ipapal/Documents/Projects/PRIVATEER/FPGA_remote_attestation_PQC/remote_attestation_example/"
# BASE_DIR = "/home/ipapal/Dropbox/PRIVATEER_DEMOS/GA_OSLO/remote_attestation_example/"

FILE_PATH_USER_REPORT = BASE_DIR + "user_kernel_report.json"
FILE_PATH_INFRA_REPORT = BASE_DIR + "attestation_service_report.json"

# --- Configuration for Auto-Refresh ---
AUTO_REFRESH_INTERVAL_SECONDS = 5 # Check for file updates every 5 seconds

# --- Helper functions ---
def get_file_mtime_and_hash(file_path):
    """Returns (modification_time, content_hash_hex) for a file."""
    try:
        if os.path.exists(file_path):
            mtime = os.path.getmtime(file_path)
            with open(file_path, 'rb') as f:
                content = f.read()
                hasher = hashlib.md5()
                hasher.update(content)
                content_hash = hasher.hexdigest()
            return mtime, content_hash
    except OSError:
        pass
    except Exception as e:
        st.warning(f"Could not hash {file_path}: {e}")
    return 0, None

def truncate_string(text, max_length=30, suffix="..."): # Adjust max_length as needed
    """Truncates a string if it exceeds max_length and appends a suffix."""
    if not isinstance(text, str):
        return text
    if len(text) > max_length:
        if max_length <= len(suffix): # Ensure space for suffix
            return suffix
        return text[:max_length - len(suffix)] + suffix
    else:
        return text

# --- 1. Data Loading Functions ---
@st.cache_data
def load_single_json_with_hash_check(file_path, _expected_content_hash):
    try:
        if not os.path.exists(file_path):
            st.error(f"Error: JSON file not found at '{file_path}'.")
            return None
        with open(file_path, 'r') as f:
            data = json.load(f)
        return data
    except json.JSONDecodeError:
        st.error(f"Error: Could not decode JSON from '{file_path}'.")
        return None
    except Exception as e:
        st.error(f"An unexpected error occurred: {e}")
        return None

@st.cache_data
def load_and_process_attestation_reports_with_hash(_user_report_hash, _infra_report_hash):
    user_report_data = None
    if _user_report_hash:
        user_report_data = load_single_json_with_hash_check(FILE_PATH_USER_REPORT, _user_report_hash)

    infra_report_data = None
    if _infra_report_hash:
        infra_report_data = load_single_json_with_hash_check(FILE_PATH_INFRA_REPORT, _infra_report_hash)

    if not user_report_data and not infra_report_data:
        st.error("Both JSON report files could not be loaded or are empty.")
        return {}, {}

    ref_values_infra = infra_report_data.get("reference_values", {}) if infra_report_data else {}
    rec_values_infra = infra_report_data.get("received_report", {}) if infra_report_data else {}
    ref_values_user = user_report_data.get("reference_values", {}) if user_report_data else {}
    rec_values_user = user_report_data.get("received_report", {}) if user_report_data else {}

    ref_nonce_att_service = ref_values_infra.get("nonce")
    ref_att_service_checksum = ref_values_infra.get("attestation_service_checksum")
    ref_aes_kernel_checksum = ref_values_infra.get("aes_kernel_checksum")
    ref_nonce_user_app = ref_values_user.get("nonce")
    ref_user_kernel_checksum = ref_values_user.get("user_kernel_checksum")
    ref_puf_response_golden = ref_values_user.get("puf_response")

    rec_nonce_att_service = rec_values_infra.get("nonce")
    rec_att_service_checksum = rec_values_infra.get("attestation_service_checksum")
    rec_aes_kernel_checksum = rec_values_infra.get("aes_kernel_checksum")
    rec_sig_infra = rec_values_infra.get("signature", "N/A")
    rec_nonce_user_app = rec_values_user.get("nonce")
    rec_user_kernel_checksum = rec_values_user.get("user_kernel_checksum")
    rec_puf_response_measured = rec_values_user.get("puf_response")
    rec_puf_hd_list_str = rec_values_user.get("puf_hd_list", "[]")
    rec_sig_user = rec_values_user.get("signature", "N/A")

    try:
        rec_puf_hd_list = json.loads(rec_puf_hd_list_str) if rec_puf_hd_list_str else []
        if not isinstance(rec_puf_hd_list, list): rec_puf_hd_list = []
    except: rec_puf_hd_list = []

    REFERENCE_VALUES_LOADED = {
        "Nonce #1": ref_nonce_att_service,
        "Att. Service Checksum": ref_att_service_checksum,
        "Security Kernel Checksum": ref_aes_kernel_checksum,
        "PUF Response (Golden)": ref_puf_response_golden, # This will be moved to its own section
        "Nonce #2": ref_nonce_user_app,
        "User Bitstream Hash": ref_user_kernel_checksum
    }
    RECEIVED_VALUES_LOADED = {
        "Nonce #1": rec_nonce_att_service,
        "Att. Service Checksum": rec_att_service_checksum,
        "Security Kernel Checksum": rec_aes_kernel_checksum,
        "PUF Response (Measured)": rec_puf_response_measured, # Comparison for the golden PUF
        "Nonce #2": rec_nonce_user_app,
        "User Bitstream Hash": rec_user_kernel_checksum,
        "Signature (Infrastructure Report)": rec_sig_infra,
        "Signature (User App Report)": rec_sig_user,
        "PUF HD List (from User Report)": rec_puf_hd_list,
        "Raw User Report Timestamp": user_report_data.get("timestamp_readable") if user_report_data else None,
        "Raw Infra Report Timestamp": infra_report_data.get("timestamp_readable") if infra_report_data else None,
        "Client Address (User Report)": user_report_data.get("client_address") if user_report_data else None,
        "Client Address (Infra Report)": infra_report_data.get("client_address") if infra_report_data else None
    }
    REFERENCE_VALUES_LOADED = {k: v for k, v in REFERENCE_VALUES_LOADED.items() if v is not None}
    RECEIVED_VALUES_LOADED = {k: v for k, v in RECEIVED_VALUES_LOADED.items() if v is not None}
    return REFERENCE_VALUES_LOADED, RECEIVED_VALUES_LOADED

# --- Define display categories based on the new keys ---
INFRA_METRIC_KEYS = [ # PUF Response moved out
    "Nonce #1",
    "Att. Service Checksum",
    "Security Kernel Checksum"
]
USER_APP_METRIC_KEYS = [
    "Nonce #2",
    "User Bitstream Hash"
]
PUF_ATTESTATION_METRIC_KEYS = [ # New category for PUF attestation
    "PUF Response (Golden)"
]


# --- 3. Initialize Session State for file hashes ---
if 'last_hash_user' not in st.session_state: st.session_state.last_hash_user = None
if 'last_hash_infra' not in st.session_state: st.session_state.last_hash_infra = None
if 'data_loaded_successfully' not in st.session_state: st.session_state.data_loaded_successfully = False

_mtime_user_on_load, current_hash_user_on_load = get_file_mtime_and_hash(FILE_PATH_USER_REPORT)
_mtime_infra_on_load, current_hash_infra_on_load = get_file_mtime_and_hash(FILE_PATH_INFRA_REPORT)

if not current_hash_user_on_load and not current_hash_infra_on_load:
    if not st.session_state.get('_initial_error_shown_no_files', False):
        st.error(f"CRITICAL: Neither JSON file found. Dashboard cannot load initial data.")
        st.session_state._initial_error_shown_no_files = True
    REFERENCE_VALUES_LOADED, RECEIVED_VALUES_LOADED = {}, {}
    st.session_state.data_loaded_successfully = False
else:
    REFERENCE_VALUES_LOADED, RECEIVED_VALUES_LOADED = load_and_process_attestation_reports_with_hash(
        current_hash_user_on_load, current_hash_infra_on_load
    )
    st.session_state.data_loaded_successfully = bool(REFERENCE_VALUES_LOADED or RECEIVED_VALUES_LOADED)
    if '_initial_error_shown_no_files' in st.session_state:
        del st.session_state._initial_error_shown_no_files

# --- 4. Sidebar for Controls ---
st.sidebar.header("⚙️ Attestation Controls")
if st.sidebar.button("🔄 Force Refresh Data from Files", key="force_refresh_attestation_data"):
    st.session_state.last_hash_user = "force_refresh_dummy_hash_user"
    st.session_state.last_hash_infra = "force_refresh_dummy_hash_infra"
    st.sidebar.success("Data refresh requested.")
    load_and_process_attestation_reports_with_hash.clear()
    load_single_json_with_hash_check.clear()
    st.rerun()

st.sidebar.markdown("---")
st.sidebar.subheader("📘 Reference Values")
if st.session_state.data_loaded_successfully and REFERENCE_VALUES_LOADED:
    # Display in sidebar can remain as is, or you can also categorize it here
    infra_ref_sidebar = {k: REFERENCE_VALUES_LOADED[k] for k in INFRA_METRIC_KEYS if k in REFERENCE_VALUES_LOADED}
    user_app_ref_sidebar = {k: REFERENCE_VALUES_LOADED[k] for k in USER_APP_METRIC_KEYS if k in REFERENCE_VALUES_LOADED}
    puf_ref_sidebar = {k: REFERENCE_VALUES_LOADED[k] for k in PUF_ATTESTATION_METRIC_KEYS if k in REFERENCE_VALUES_LOADED}

    if infra_ref_sidebar:
        st.sidebar.markdown("##### Infrastructure (Reference)")
        st.sidebar.json(infra_ref_sidebar)
    if user_app_ref_sidebar:
        st.sidebar.markdown("##### User Application (Reference)")
        st.sidebar.json(user_app_ref_sidebar)
    if puf_ref_sidebar:
        st.sidebar.markdown("##### PUF (Reference)")
        st.sidebar.json(puf_ref_sidebar)
    if not (infra_ref_sidebar or user_app_ref_sidebar or puf_ref_sidebar):
        st.sidebar.caption("No reference data categories available.")
else:
    st.sidebar.warning("Reference data not fully loaded for sidebar.")

# --- 5. Main Application Layout ---
col1_title, col2_title = st.columns([1, 10])
with col1_title:
    if os.path.exists(LOGO_PATH): st.image(LOGO_PATH, width=100)
with col2_title:
    st.title("FPGA Attestation & PUF Dashboard")
    st.caption("Data acquired from FPGA Attestation Server")

if not st.session_state.data_loaded_successfully:
    st.warning("Data not fully loaded. Dashboard may be incomplete.")

# attestation_tab, puf_data_tab = st.tabs(["🔒 Attestation Verification", "📈 PUF Analysis"])
attestation_tab, puf_data_tab, blockchain_tab = st.tabs([
    "🔒 Attestation Verification",
    "📈 PUF Analysis",
    "⛓️ Push Evidence to Blockchain"
])


with attestation_tab:
    st.header("📊 FPGA Remote Attestation Protocol")
    mermaid_code_attestation_conceptual = """
    sequenceDiagram
        autonumber
        participant Edge Node w/ FPGA; participant Attestation Server; participant Blockchain
        Attestation Server-->>Edge Node w/ FPGA: Verify Attestation Service & AES Kernel (Infra Report)
        Attestation Server-->>Edge Node w/ FPGA: Verify User Kernel & PUF (User Report)
        Attestation Server-->>Edge Node w/ FPGA: (If all good) Load FPGA Bitstream / Allow Operation
        Attestation Server-->>Blockchain: (Optionally) Upload Attestation Evidence
    """
    st_mermaid(mermaid_code_attestation_conceptual)
    st.header("🔍 Remote Attestation Values")

    overall_all_match = True # This will now be an aggregate of 3 sections
    
    # Track if all reference values for overall status are present
    all_infra_refs_present_for_overall = True
    all_user_app_refs_present_for_overall = True
    all_puf_refs_present_for_overall = True


    def style_status_column(val_str): # For st.dataframe.style.applymap
        color = 'green' if '✅' in val_str else 'red' if '❌' in val_str else 'black'
        return f'color: {color}; font-weight: bold;'

    # --- Infrastructure Attestation ---
    st.subheader("Attestation Service Attestation")
    infra_refs_exist = any(key in REFERENCE_VALUES_LOADED for key in INFRA_METRIC_KEYS)
    infra_recs_exist = any(RECEIVED_VALUES_LOADED.get(key) for key in INFRA_METRIC_KEYS) # Simpler check

    if not infra_refs_exist and not infra_recs_exist:
        st.info("No infrastructure attestation data available.")
        all_infra_refs_present_for_overall = False # No refs to check
    else:
        infra_comparison_list = []
        infra_all_match_section = True
        missing_infra_refs_section = False
        for key in INFRA_METRIC_KEYS:
            ref_val_orig = REFERENCE_VALUES_LOADED.get(key, "N/A - Ref Missing")
            if ref_val_orig == "N/A - Ref Missing": 
                missing_infra_refs_section = True
                all_infra_refs_present_for_overall = False


            rec_val_orig = RECEIVED_VALUES_LOADED.get(key, "N/A - Rec Missing")
            
            ref_val_display = truncate_string(str(ref_val_orig))
            rec_val_display = truncate_string(str(rec_val_orig))

            is_match = (str(ref_val_orig) == str(rec_val_orig))
            if not is_match and ref_val_orig != "N/A - Ref Missing" and rec_val_orig != "N/A - Rec Missing":
                infra_all_match_section = False; overall_all_match = False
            
            status_icon = "✅" if is_match else "❌"
            infra_comparison_list.append({
                "Metric": key, 
                "Reference Value": ref_val_display,
                "Received Value": rec_val_display,
                "Status": f"{status_icon} {'Match' if is_match else 'Mismatch'}"
            })
        
        if infra_comparison_list:
            df_infra_attestation = pd.DataFrame(infra_comparison_list)
            st.dataframe(
                df_infra_attestation.style.applymap(style_status_column, subset=['Status']),
                use_container_width=True, hide_index=True
            )
        
        if infra_all_match_section and not missing_infra_refs_section: st.success("✅ All Infrastructure Values Match!")
        elif infra_all_match_section and missing_infra_refs_section: st.warning("⚪ Infrastructure: Refs missing, existing match.")
        else: st.error("❌ Infrastructure Mismatch or values missing!")
    
    if RECEIVED_VALUES_LOADED.get("Signature (Infrastructure Report)"):
         st.caption(f"Infra Report Signature: **{RECEIVED_VALUES_LOADED['Signature (Infrastructure Report)']}** (`{RECEIVED_VALUES_LOADED.get('Client Address (Infra Report)', 'N/A')}` @ `{RECEIVED_VALUES_LOADED.get('Raw Infra Report Timestamp', 'N/A')}`)")



    # --- PUF Attestation ---
    st.subheader("PUF Verification")
    puf_refs_exist = any(key in REFERENCE_VALUES_LOADED for key in PUF_ATTESTATION_METRIC_KEYS)
    # PUF measured value is specifically "PUF Response (Measured)"
    puf_recs_exist = bool(RECEIVED_VALUES_LOADED.get("PUF Response (Measured)"))

    if not puf_refs_exist and not puf_recs_exist:
        st.info("No PUF attestation data available.")
        all_puf_refs_present_for_overall = False
    else:
        puf_comparison_list = []
        puf_all_match_section = True
        missing_puf_refs_section = False
        for key in PUF_ATTESTATION_METRIC_KEYS: # Should only be "PUF Response (Golden)"
            ref_val_orig = REFERENCE_VALUES_LOADED.get(key, "N/A - Ref Missing")
            if ref_val_orig == "N/A - Ref Missing":
                missing_puf_refs_section = True
                all_puf_refs_present_for_overall = False
            
            # The received value for "PUF Response (Golden)" is "PUF Response (Measured)"
            rec_val_orig = RECEIVED_VALUES_LOADED.get("PUF Response (Measured)", "N/A - Rec Missing")
            
            ref_val_display = truncate_string(str(ref_val_orig))
            rec_val_display = truncate_string(str(rec_val_orig))

            is_match = (str(ref_val_orig) == str(rec_val_orig))
            if not is_match and ref_val_orig != "N/A - Ref Missing" and rec_val_orig != "N/A - Rec Missing":
                puf_all_match_section = False; overall_all_match = False
            
            status_icon = "✅" if is_match else "❌"
            # Display key for PUF Response can be simpler
            display_metric_name = "PUF Response" # Or key.replace(" (Golden)", "")
            puf_comparison_list.append({
                "Metric": display_metric_name, 
                "Reference Value (Golden)": ref_val_display, # Clarify this is the golden one
                "Received Value (Measured)": rec_val_display,  # Clarify this is the measured one
                "Status": f"{status_icon} {'Match' if is_match else 'Mismatch'}"
            })
        
        if puf_comparison_list:
            df_puf_attestation = pd.DataFrame(puf_comparison_list)
            # Adjust column names if needed for clarity, or use the ones from dict keys
            st.dataframe(
                df_puf_attestation.style.applymap(style_status_column, subset=['Status']),
                use_container_width=True, hide_index=True
            )
        
        if puf_all_match_section and not missing_puf_refs_section: st.success("✅ PUF Response Matches!")
        elif puf_all_match_section and missing_puf_refs_section: st.warning("⚪ PUF: Golden Reference missing, cannot verify.")
        else: st.error("❌ PUF Response Mismatch or values missing!")




    # --- User Accelerated Application Attestation ---
    st.subheader("User Accelerator Bitstream Attestation")
    user_refs_exist = any(key in REFERENCE_VALUES_LOADED for key in USER_APP_METRIC_KEYS)
    user_recs_exist = any(RECEIVED_VALUES_LOADED.get(key) for key in USER_APP_METRIC_KEYS)
    if not user_refs_exist and not user_recs_exist:
        st.info("No user application attestation data available.")
        all_user_app_refs_present_for_overall = False
    else:
        user_app_comparison_list = []
        user_app_all_match_section = True
        missing_user_refs_section = False
        for key in USER_APP_METRIC_KEYS:
            ref_val_orig = REFERENCE_VALUES_LOADED.get(key, "N/A - Ref Missing")
            if ref_val_orig == "N/A - Ref Missing": 
                missing_user_refs_section = True
                all_user_app_refs_present_for_overall = False

            rec_val_orig = RECEIVED_VALUES_LOADED.get(key, "N/A - Rec Missing")
            ref_val_display = truncate_string(str(ref_val_orig))
            rec_val_display = truncate_string(str(rec_val_orig))
            is_match = (str(ref_val_orig) == str(rec_val_orig))
            if not is_match and ref_val_orig != "N/A - Ref Missing" and rec_val_orig != "N/A - Rec Missing":
                user_app_all_match_section = False; overall_all_match = False
            status_icon = "✅" if is_match else "❌"
            user_app_comparison_list.append({
                "Metric": key, 
                "Reference Value": ref_val_display,
                "Received Value": rec_val_display,
                "Status": f"{status_icon} {'Match' if is_match else 'Mismatch'}"
            })
        if user_app_comparison_list:
            df_user_app_attestation = pd.DataFrame(user_app_comparison_list)
            st.dataframe(
                df_user_app_attestation.style.applymap(style_status_column, subset=['Status']),
                use_container_width=True, hide_index=True
            )
        if user_app_all_match_section and not missing_user_refs_section: st.success("✅ All User App Values Match!")
        elif user_app_all_match_section and missing_user_refs_section: st.warning("⚪ User App: Refs missing, existing match.")
        else: st.error("❌ User App Mismatch or values missing!")

    if RECEIVED_VALUES_LOADED.get("Signature (User App Report)"):
        st.caption(f"User App Report Signature: **{RECEIVED_VALUES_LOADED['Signature (User App Report)']}** (`{RECEIVED_VALUES_LOADED.get('Client Address (User Report)', 'N/A')}` @ `{RECEIVED_VALUES_LOADED.get('Raw User Report Timestamp', 'N/A')}`)")

    st.markdown("---")
    # Check if any data was present at all before showing overall status
    any_data_exists = (infra_refs_exist or infra_recs_exist or
                       user_refs_exist or user_recs_exist or
                       puf_refs_exist or puf_recs_exist)
    if any_data_exists:
        all_refs_present_overall = all_infra_refs_present_for_overall and \
                                   all_user_app_refs_present_for_overall and \
                                   all_puf_refs_present_for_overall
                                   
        if overall_all_match and all_refs_present_overall: st.success("🎉 **Overall Attestation: All Values Match!**")
        elif overall_all_match and not all_refs_present_overall : st.warning("⚪ **Overall Attestation: Existing values match, but some reference values were missing.**")
        else: st.error("🚨 **Overall Attestation: Mismatch or Critical Values Missing!**")

    with st.expander("Show All Loaded & Processed Values (Original - Non-Truncated)"):
        st.write("Reference Values (Original):"); st.json(REFERENCE_VALUES_LOADED)
        st.write("Received Values (Original):"); st.json(RECEIVED_VALUES_LOADED)

with puf_data_tab:
    st.header("📈 PUF Data Analysis") # This tab shows the HD list etc.
    puf_hd_list_from_json = RECEIVED_VALUES_LOADED.get("PUF HD List (from User Report)")
    if puf_hd_list_from_json and isinstance(puf_hd_list_from_json, list) and len(puf_hd_list_from_json) > 0:
        st.subheader("Hamming Distance for multiple responses")
        valid_hd_list = [item for item in puf_hd_list_from_json if isinstance(item, (int, float))]
        if not valid_hd_list:
            st.warning("No valid numeric HD values in `puf_hd_list`.")
        else:
            df_puf_hd = pd.DataFrame({'Challenge': range(1, len(valid_hd_list) + 1), 'Hamming Distance': valid_hd_list})
            st.line_chart(df_puf_hd.set_index('Challenge'))
            avg_hd = np.mean(valid_hd_list); max_hd = np.max(valid_hd_list); min_hd = np.min(valid_hd_list)
            col1_met, col2_met, col3_met = st.columns(3)
            with col1_met: st.metric("Average HD", f"{avg_hd:.2f} bits")
            with col2_met: st.metric("Max HD", f"{max_hd} bits")
            with col3_met: st.metric("Min HD", f"{min_hd} bits")
    else:
        st.info("`puf_hd_list` not available or empty in user report.")
        if puf_hd_list_from_json is not None:
             st.write("Raw `puf_hd_list` content:", puf_hd_list_from_json)


# -----------------------------------------------------------------------------------
# -----------------------------------------------------------------------------------
# BLOCKCHAIN
# -----------------------------------------------------------------------------------
# -----------------------------------------------------------------------------------
with blockchain_tab:
    st.header("⛓️ Blockchain Evidence Visualization")

    HISTORY_DIR = BASE_DIR + "blockchain_history/"

    # Ensure directory exists
    os.makedirs(HISTORY_DIR, exist_ok=True)

    # Find all JSON files sorted by datetime in filename
    history_files = sorted(
        [f for f in os.listdir(HISTORY_DIR) if f.endswith(".json")],
        reverse=True
    )

    if len(history_files) == 0:
        st.warning("No blockchain evidence files found in blockchain_history/")
        st.stop()

    # ----------------------------------------------------------
    # 1. LOAD LATEST EVIDENCE (Newest JSON File)
    # ----------------------------------------------------------
    latest_file = os.path.join(HISTORY_DIR, history_files[0])

    with open(latest_file, "r") as f:
        latest_json = json.load(f)

    st.success(f"Loaded latest blockchain evidence: **{history_files[0]}**")

    # Extract base fields
    edge_section = latest_json["EdgeAcceleratorReports"][0]
    attestation_section = latest_json["AttestationServerEvidence"]

    edge_server_id = edge_section["EdgeServerID"]
    fpga_id = edge_section["FPGAID"]

    # Extract claims
    claims = edge_section["attestationReport"]

    att_service_claim = next(c for c in claims if c["claim"] == "edge_accelerator_att_service")
    kernel_claim      = next(c for c in claims if c["claim"] == "edge_accelerator_kernel")
    puf_claim_raw     = next(c for c in claims if c["claim"] == "edge_accelerator_puf_verification")

    # ----------------------------------------------------------
    # BUILD NORMALIZED CURRENT EVIDENCE STRUCTURE
    # ----------------------------------------------------------
    normalized_current = [
        {
            "EdgeServerID": edge_server_id,
            "FPGAID": fpga_id,
            "attestationReport": [
                {
                    "claim": "edge_accelerator_att_service",
                    "timestamp": att_service_claim["timestamp"],
                    "appraisal": att_service_claim["appraisal"],
                },
                {
                    "claim": "edge_accelerator_kernel",
                    "kernel_type": kernel_claim.get("kernel_type", None),
                    "timestamp": kernel_claim["timestamp"],
                    "appraisal": kernel_claim["appraisal"],
                },
                {
                    "claim": "edge_accelerator_puf_verification",
                    "timestamp": puf_claim_raw["timestamp"],
                    "appraisal": puf_claim_raw["appraisal"],
                    "puf": puf_claim_raw.get("puf", None)
                }
            ]
        }
    ]

    # SHOW IT
    st.subheader("Current Evidence (Normalized Structure)")
    st.json(normalized_current)

    st.markdown("---")

    # ----------------------------------------------------------
    # 2. LOAD **ALL** HISTORY FILES → build DataFrame
    # ----------------------------------------------------------
    all_runs = []

    for filename in sorted(history_files):
        filepath = os.path.join(HISTORY_DIR, filename)
        try:
            with open(filepath, "r") as f:
                js = json.load(f)

            edge = js["EdgeAcceleratorReports"][0]
            att = js["AttestationServerEvidence"]
            claims = edge["attestationReport"]

            att_service = next(c for c in claims if c["claim"] == "edge_accelerator_att_service")
            kernel      = next(c for c in claims if c["claim"] == "edge_accelerator_kernel")
            puf_claim   = next(c for c in claims if c["claim"] == "edge_accelerator_puf_verification")

            entry = {
                "timestamp": att["timestamp"],
                "puf_appraisal": int(puf_claim["appraisal"]) if str(puf_claim["appraisal"]).isdigit() else None,
                "puf_status": int(puf_claim["appraisal"]) if str(puf_claim["appraisal"]).isdigit() else None,  # optional internal use
                "kernel_type": kernel.get("kernel_type", None),
                "attestation_service_verification": att_service["appraisal"],
                "bitstream_verification": kernel["appraisal"],
                "fpga_id": edge["FPGAID"]
            }

            all_runs.append(entry)

        except Exception as e:
            st.error(f"Error reading {filename}: {e}")
            continue

    # Convert to DataFrame
    df_history = pd.DataFrame(all_runs)

    # Convert timestamp to datetime
    df_history["timestamp"] = pd.to_datetime(df_history["timestamp"])
    df_history = df_history.sort_values("timestamp").set_index("timestamp")

    # ----------------------------------------------------------
    # HEATMAP (COMPACT VIEW)
    # ----------------------------------------------------------
    st.subheader("📜 Blockchain Evidence History")

    heatmap_df = df_history.copy()
    heatmap_display = heatmap_df.copy()

    # EMOJI COLOR CODING
    heatmap_display["puf_appraisal"] = heatmap_display["puf_appraisal"].replace({1: "🟩", 0: "🟥"})
    heatmap_display["attestation_service_verification"] = heatmap_display["attestation_service_verification"].replace({1: "🟩", 0: "🟥"})
    heatmap_display["bitstream_verification"] = heatmap_display["bitstream_verification"].replace({1: "🟩", 0: "🟥"})
    # kernel_type stays numeric
    # fpga_id stays as label

    # Remove puf_status from display (internal only)
    heatmap_display = heatmap_display.drop(columns=["puf_status"])

    st.dataframe(heatmap_display, use_container_width=True)

    st.info("Showing all runs found in blockchain_history/")

# -----------------------------------------------------------------------------------
# -----------------------------------------------------------------------------------




st.markdown("---")
st.caption(f"ICCS - Task 5.2. Auto-refresh: {AUTO_REFRESH_INTERVAL_SECONDS}s.")

# --- Auto-refresh polling logic based on content HASH ---
_mtime_user_at_end, new_hash_user_at_end = get_file_mtime_and_hash(FILE_PATH_USER_REPORT)
_mtime_infra_at_end, new_hash_infra_at_end = get_file_mtime_and_hash(FILE_PATH_INFRA_REPORT)

user_content_changed = (new_hash_user_at_end is not None and new_hash_user_at_end != st.session_state.last_hash_user)
infra_content_changed = (new_hash_infra_at_end is not None and new_hash_infra_at_end != st.session_state.last_hash_infra)
user_file_appeared = (st.session_state.last_hash_user is None and new_hash_user_at_end is not None)
infra_file_appeared = (st.session_state.last_hash_infra is None and new_hash_infra_at_end is not None)

if user_content_changed or infra_content_changed or user_file_appeared or infra_file_appeared:
    refresh_message = []
    if user_content_changed or user_file_appeared: refresh_message.append(f"{os.path.basename(FILE_PATH_USER_REPORT)} changed.")
    if infra_content_changed or infra_file_appeared: refresh_message.append(f"{os.path.basename(FILE_PATH_INFRA_REPORT)} changed.")
    if refresh_message: st.toast(" ".join(refresh_message) + " Refreshing...")

    st.session_state.last_hash_user = new_hash_user_at_end
    st.session_state.last_hash_infra = new_hash_infra_at_end
    load_and_process_attestation_reports_with_hash.clear()
    load_single_json_with_hash_check.clear()
    time.sleep(0.5)
    st.rerun()
else:
    if current_hash_user_on_load is not None: st.session_state.last_hash_user = current_hash_user_on_load
    if current_hash_infra_on_load is not None: st.session_state.last_hash_infra = current_hash_infra_on_load

if AUTO_REFRESH_INTERVAL_SECONDS > 0:
    time.sleep(AUTO_REFRESH_INTERVAL_SECONDS)
    st.rerun()