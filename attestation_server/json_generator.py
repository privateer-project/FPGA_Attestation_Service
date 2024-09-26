# ---------------------------------------------------
# Auxiliary file to generate the json structures for the attestation reports
#
# Ilias Papalamprou
# ---------------------------------------------------
import json

# Json structure of the Edge Accelerator Report
def generate_att_report_json(
    edge_server_id, fpga_id, 
    att_service_claim, att_service_timestamp, att_service_appraisal,
    kernel_claim, kernel_type, kernel_timestamp, kernel_appraisal,
):
    
    data = [
        {
            "EdgeServerID" :        edge_server_id,         # "Edge-Server-1"
            "FPGAID" :              fpga_id,                # "FPGA-1"
            "attestationReport": [
                {
                    "claim":        att_service_claim,      # "edge_accelerator_att_service",
                    "timestamp":    att_service_timestamp,  # timestamp1,
                    "appraisal":    att_service_appraisal,  # 1
                },
                {
                    "claim":        kernel_claim,           # "edge_accelerator_kernel",
                    "kernel_type" : kernel_type,            # 0,
                    "timestamp":    kernel_timestamp,       # timestamp2,
                    "appraisal":    kernel_appraisal       # 0
                }
            ]
        }
    ]

    json_data = data
    
    return json_data


# Json structure of the Attestation Server Evidence
# Note: This includes the attestation report from the Edge Accelerator
def generate_att_server_evidence_json(
    att_evidence_timestamp, att_evidence_nonce, att_evidence_signature_type, att_evidence_signature, att_evidence_keyref
):
    # Calculate the input JSON structure checksum to include it in the evidence
    data = {
        "timestamp" :               att_evidence_timestamp,         
        "nonce" :                   att_evidence_nonce,             
        "signatureAlgorithmType":   att_evidence_signature_type,    
        "signature" :               att_evidence_signature,         
        "keyRef"    :               att_evidence_keyref             
    }

    # Convert the dictionary to a JSON string
    # json_data = json.dumps(data)
    json_data = data
    
    return json_data
