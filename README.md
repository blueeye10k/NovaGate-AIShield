# 🛰️ NovaGate-AIShield: Advanced AI Prompt Firewall & Security Dashboard

NovaGate-AIShield is an enterprise-grade **AI Prompt Firewall** and Web Application Firewall (AI-WAF) designed to safeguard downstream Large Language Models (LLMs) from adversarial vulnerabilities, injection vectors, and structural system exploits. 

Operating as an asynchronous security layer proxy, it inspects inbound traffic stream parameters *before* they strike the cloud model APIs, enforcing safety parameters dynamically across multi-tier HTTP mitigation profiles.

---

## 🌟 Core Shield Pillars

*   **Inline Security Proxy Gateway:** Leverages FastAPI and Uvicorn frameworks to intercept, inspect, and evaluate data buffers globally on port `8000`.
*   **Recursive 4-Pass Normalization:** Built-in de-obfuscation pipeline that strips nested Base64, Hexadecimal configurations, URL encodings, and Leetspeak bypass signatures live.
*   **Heuristic Risk Evaluation:** Combines real-time **Shannon Entropy Analysis** (character randomness footprinting) and semantic jailbreak vector distance anchor scans.
*   **Multi-Tier HTTP Adaptive Mitigation:** Standardized enterprise protocol architecture mapping out dynamic network traffic drop codes:
    *   `200 OK`: Safe query validated and unlocked to pass downstream.
    *   `400 Bad Request`: Captures empty string data arguments or malformed request payloads.
    *   `403 Forbidden`: Instantly drops active malicious injections and system takeover vectors.
    *   `422 Unprocessable`: Blocks high-entropy structural anomalies clearing basic signatures.
    *   `429 Too Many Requests`: Deploys automated anti-flood rate-limiting IP monitoring.
*   **High-Visibility Telemetry Triage Dashboard:** Real-time color-coded console rendering and dynamic browser portal console tracking risk matrices live.
*   **Compliance File Auditor:** Automatically compiles an immutable text-based incident log database (`security_audit.log`) on disk for historical threat analytics.

---

## 🚀 Quick Local Sandbox Deployment

Deploy the AI Prompt Firewall locally on your subsystem in under a minute:

```bash
# 1. Clone the repository framework
git clone https://github.com
cd NovaGate-AIShield

# 2. Initialize your sandboxed environment and dependencies
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt

# 3. Boot the active defensive reverse proxy server
python3 application.py
```

---

## 📡 Dynamic Application Integration

AI Developers can instantly plug NovaGate into their production workflows as an inline gatekeeper shield layer by forwarding inputs to the inspect API endpoint:

```python
import httpx

def chat_pipeline(user_input):
    # Route untrusted input to the AI Prompt Firewall gateway first
    response = httpx.post(
        "http://127.0.0", 
        json={"user_prompt": user_input}
    )
    
    if response.status_code == 200:
        # Clear Pass -> Send payload downstream to LLM API
        return "AI Response Generation"
    elif response.status_code == 403:
        # Attack Blocked -> Drop request instantly
        return "Access Denied: Malicious injection parameters intercepted."
```

---

## 📊 Live Interactive Threat Testing

Once your application server is running, navigate to `http://localhost:8000` to access the graphical **Executive Cyber-Threat Control Sandbox**. Use the preset blueprints to stream verification matrix loops, test anti-flood burst rules, or execute base64 evasion payloads to watch the analytics matrix calculate dynamic threat scores in real time!
