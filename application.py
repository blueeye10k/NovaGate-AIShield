import sys
import os
import time
import logging
import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

# Anchoring root execution folder path environments
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from core.normalizer import AdvancedPayloadNormalizer
    from core.evaluator import VectorThreatEvaluator
    from ui.dashboard import EnterpriseSOCDashboard
except ModuleNotFoundError as err:
    print(f"\n❌ System Module Dependency Failure: {err}")
    sys.exit(1)

logging.basicConfig(
    filename='security_audit.log',
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] SECURITY_EVENT: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

app = FastAPI(
    title="NovaGate-AIShield Enterprise Proxy Gateway", 
    version="2.0",
    docs_url="/docs"
)

CLIENT_TRAFFIC_LOGS = {}

class PromptPayload(BaseModel):
    user_prompt: str = Field(..., max_length=10000)

# ----------------------------------------------------------------------
# 🔥 NEW VISUAL PORTAL ROUTE: Serves the Eye-Catching Frontend Panel Layout
# ----------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
async def load_interactive_web_portal():
    template_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ui", "dashboard.html")
    try:
        with open(template_path, "r", encoding="utf-8") as file:
            html_content = file.read()
        return HTMLResponse(content=html_content, status_code=200)
    except FileNotFoundError:
        return HTMLResponse(content="<h3>Error: html file missing inside ui/ directory</h3>", status_code=404)

@app.post("/api/v1/inspect")
async def inspect_incoming_prompt(payload: PromptPayload, request: Request):
    client_ip = request.client.host
    current_time = time.time()
    
    # 1. HTTP 429 - Rate Limiting Mitigation Layer
    if client_ip in CLIENT_TRAFFIC_LOGS:
        last_request_time = CLIENT_TRAFFIC_LOGS[client_ip]
        if current_time - last_request_time < 0.5:
            CLIENT_TRAFFIC_LOGS[client_ip] = current_time
            logging.warning(f"IP={client_ip} TARGET=/inspect STATUS=429 THREAT=RATE_LIMIT_EXCEEDED")
            raise HTTPException(status_code=429, detail={"status": "RATE_LIMIT_EXCEEDED"})
    CLIENT_TRAFFIC_LOGS[client_ip] = current_time

    # 2. HTTP 400 - Malformed Data Intercept
    cleaned_input = payload.user_prompt.strip()
    if not cleaned_input:
        logging.warning(f"IP={client_ip} TARGET=/inspect STATUS=400 THREAT=MALFORMED_PAYLOAD")
        raise HTTPException(status_code=400, detail={"status": "MALFORMED_PAYLOAD"})

    # 3. Normalization Pipeline Extraction
    norm_report = AdvancedPayloadNormalizer.execute_normalization_pipeline(payload.user_prompt)
    
    # 4. Contextual Risk Metrics Aggregation
    is_blocked, triage_metrics = VectorThreatEvaluator.evaluate_threat_vector(
        norm_report["processed_string"]
    )
    
    # 5. Render live terminal logging dashboard update stream
    EnterpriseSOCDashboard.render_triage_packet(payload.user_prompt, norm_report, triage_metrics)
    
    # 6. HTTP 403 - Malicious Intrusion Intercept Layer
    if is_blocked:
        logging.critical(
            f"IP={client_ip} TARGET=/inspect STATUS=403 THREAT=SECURITY_ACCESS_VIOLATION "
            f"RISK={triage_metrics['calculated_risk_index']} EXTRACTED='{norm_report['processed_string']}'"
        )
        raise HTTPException(status_code=403, detail={"status": "SECURITY_ACCESS_VIOLATION"})
        
    # 7. HTTP 422 - Structural Anomaly Flag Layer
    if triage_metrics["entropy_score"] >= 5.8:
        logging.warning(f"IP={client_ip} TARGET=/inspect STATUS=422 THREAT=ANOMALOUS_PAYLOAD_STRUCTURE")
        raise HTTPException(status_code=422, detail={"status": "ANOMALOUS_PAYLOAD_STRUCTURE"})

    # 8. HTTP 200 - Safe Packet Validation Clear
    logging.info(f"IP={client_ip} TARGET=/inspect STATUS=200 THREAT=NONE VERDICT=PASS")
    return {
        "status": "PROCESSED_SUCCESSFULLY",
        "normalization": norm_report,
        "telemetry": triage_metrics
    }

def main():
    EnterpriseSOCDashboard.print_gateway_header()
    print("[+] Starting Web Reverse Proxy Infrastructure daemon...")
    print("[+] Enforcing active network inspection on: http://127.0.0.1:8000")
    print("[+] Enterprise visual interactive web panel live at -> http://localhost:8000")
    
    uvicorn.run("application:app", host="0.0.0.0", port=8000, log_level="info", reload=False)

if __name__ == "__main__":
    main()

