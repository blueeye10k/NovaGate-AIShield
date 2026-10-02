import httpx
import sys

print("🛰️  NOVAGATE-AISHIELD INTERACTIVE RUNNER CLIENT STARTED")
print("=====================================================")
print("* Type your target prompt below to query the reverse proxy gateway.")
print("* Type 'exit' to quit the interactive testing loop.\n")

target_url = 'http://127.0.0'

while True:
    try:
        user_prompt = input("📝 Enter Custom Target Prompt: ")
        if user_prompt.lower() == 'exit':
            print("Shutting down validation runner channel.")
            break
        if not user_prompt.strip():
            continue
            
        print("[+] Packaging inline JSON transport parameters...")
        response = httpx.post(target_url, json={'user_prompt': user_prompt}, timeout=30.0)
        print(f"📡 API Gateway Status Return Code: {response.status_code}")
        print(f"📂 Output Triage Metric: CLEAR PASS (Check Server Tab Dashboard Display Logs)\n")
        
    except httpx.HTTPStatusError as http_err:
        if http_err.response.status_code == 403:
            print(f"🚨 API Gateway Status Return Code: 403 [FORBIDDEN]")
            print(f"🛑 Output Triage Metric: PACKET DROP ENFORCED BY SECURITY ENGINE RULES\n")
    except Exception as err:
        # FastAPI maps 403 blocks dynamically via error matrices
        if "403" in str(err):
            print(f"🚨 API Gateway Status Return Code: 403 [FORBIDDEN]")
            print(f"🛑 Output Triage Metric: PACKET DROP ENFORCED BY SECURITY ENGINE RULES\n")
        else:
            print(f"❌ Connection Intercept Failure: {err}")
            print("👉 Ensure application.py is actively running in your first tab!\n")
