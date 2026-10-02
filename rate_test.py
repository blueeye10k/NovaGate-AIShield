import httpx
import time

url = "http://0.0.0"
payload = {"user_prompt": "Standard conversational message checking parameters."}

print("⚡ Injecting high-frequency network burst target...")

with httpx.Client() as client:
    for i in range(1, 4):
        try:
            # Fire requests with absolutely zero delay between loop cycles
            response = client.post(url, json=payload)
            print(f"[+] Request #{i} Result -> HTTP Code: {response.status_code}")
        except Exception as e:
            print(f"[-] Request #{i} Failed: {e}")
