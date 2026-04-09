import os
import json
import time
import hashlib
import requests
import threading
from pathlib import Path
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

app = Flask(__name__, static_folder='static')
CORS(app)

VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3"
UPLOAD_FOLDER = "/tmp/vt_scanner_uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

scan_results_cache = {}


def get_file_hash(filepath):
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def check_hash_virustotal(file_hash, api_key):
    headers = {"x-apikey": api_key}
    response = requests.get(
        f"{VIRUSTOTAL_API_URL}/files/{file_hash}",
        headers=headers,
        timeout=30
    )
    if response.status_code == 200:
        return response.json()
    return None


def upload_file_virustotal(filepath, api_key):
    headers = {"x-apikey": api_key}
    file_size = os.path.getsize(filepath)

    if file_size > 32 * 1024 * 1024:  # > 32MB use large file upload
        upload_url_resp = requests.get(
            f"{VIRUSTOTAL_API_URL}/files/upload_url",
            headers=headers,
            timeout=30
        )
        if upload_url_resp.status_code != 200:
            return None, "Failed to get upload URL for large file"
        upload_url = upload_url_resp.json().get("data")
    else:
        upload_url = f"{VIRUSTOTAL_API_URL}/files"

    with open(filepath, "rb") as f:
        files = {"file": (os.path.basename(filepath), f)}
        response = requests.post(upload_url, headers=headers, files=files, timeout=120)

    if response.status_code == 200:
        return response.json().get("data", {}).get("id"), None
    return None, f"Upload failed: {response.status_code} - {response.text}"


def poll_analysis(analysis_id, api_key, max_wait=120):
    headers = {"x-apikey": api_key}
    start = time.time()
    while time.time() - start < max_wait:
        resp = requests.get(
            f"{VIRUSTOTAL_API_URL}/analyses/{analysis_id}",
            headers=headers,
            timeout=30
        )
        if resp.status_code == 200:
            data = resp.json()
            status = data.get("data", {}).get("attributes", {}).get("status")
            if status == "completed":
                return data
        time.sleep(5)
    return None


def parse_vt_result(vt_data):
    attrs = vt_data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    results = attrs.get("last_analysis_results", {})

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    undetected = stats.get("undetected", 0)
    harmless = stats.get("harmless", 0)
    total = malicious + suspicious + undetected + harmless

    # Gather malware categories/names
    threat_names = []
    threat_categories = set()
    for engine, result in results.items():
        if result.get("category") in ("malicious", "suspicious"):
            if result.get("result"):
                threat_names.append(result["result"])
            if result.get("category"):
                threat_categories.add(result["category"])

    # Determine primary malware type
    malware_type = detect_malware_type(threat_names)

    return {
        "malicious": malicious,
        "suspicious": suspicious,
        "undetected": undetected,
        "harmless": harmless,
        "total": total,
        "threat_names": list(set(threat_names))[:10],
        "malware_type": malware_type,
        "file_name": attrs.get("meaningful_name", "Unknown"),
        "file_type": attrs.get("type_description", "Unknown"),
        "file_size": attrs.get("size", 0),
        "sha256": attrs.get("sha256", ""),
        "md5": attrs.get("md5", ""),
        "first_seen": attrs.get("first_submission_date", 0),
        "last_seen": attrs.get("last_analysis_date", 0),
    }


def detect_malware_type(threat_names):
    names_lower = " ".join(threat_names).lower()
    if any(x in names_lower for x in ["ransom", "crypt", "lock", "wanna", "petya"]):
        return "ransomware"
    elif any(x in names_lower for x in ["trojan", "rat", "backdoor", "remote"]):
        return "trojan"
    elif any(x in names_lower for x in ["worm", "spread", "propagat"]):
        return "worm"
    elif any(x in names_lower for x in ["virus", "infect", "polymorphic"]):
        return "virus"
    elif any(x in names_lower for x in ["spyware", "keylog", "steal", "spy"]):
        return "spyware"
    elif any(x in names_lower for x in ["adware", "pup", "unwanted", "advert"]):
        return "adware"
    elif any(x in names_lower for x in ["rootkit", "kernel", "stealth", "hook"]):
        return "rootkit"
    elif any(x in names_lower for x in ["miner", "coinminer", "crypto", "monero"]):
        return "cryptominer"
    elif any(x in names_lower for x in ["botnet", "bot", "zombie", "ddos"]):
        return "botnet"
    elif threat_names:
        return "malware"
    return "unknown"


def get_ai_remediation(scan_data, ai_endpoint, ai_model):
    """Call the local Open WebUI AI model for remediation steps."""
    malware_type = scan_data.get("malware_type", "unknown")
    threat_names = scan_data.get("threat_names", [])
    file_name = scan_data.get("file_name", "Unknown")
    score = f"{scan_data.get('malicious', 0)}/{scan_data.get('total', 0)}"

    prompt = f"""You are a cybersecurity expert. A file scan has detected a potentially malicious file.

File: {file_name}
VirusTotal Score: {score} engines flagged this file
Malware Type: {malware_type}
Detected Threats: {', '.join(threat_names[:5]) if threat_names else 'Unknown'}

Please provide:
1. A brief explanation of what this type of malware does (2-3 sentences)
2. Step-by-step removal instructions (numbered, clear steps)
3. Network safety measures to protect the rest of the network (numbered steps)
4. Prevention tips to avoid future infections (3-4 bullet points)

Format your response with clear section headers using markdown bold (**Section Name**).
Be specific, actionable, and concise."""

    try:
        payload = {
            "model": ai_model,
            "messages": [{"role": "user", "content": prompt}],
            "stream": False
        }
        resp = requests.post(
            f"{ai_endpoint.rstrip('/')}/api/chat",
            json=payload,
            timeout=60
        )
        if resp.status_code == 200:
            data = resp.json()
            return data.get("message", {}).get("content", "") or \
                   data.get("choices", [{}])[0].get("message", {}).get("content", "")
    except Exception as e:
        pass

    # Fallback: try OpenAI-compatible endpoint
    try:
        payload = {
            "model": ai_model,
            "messages": [{"role": "user", "content": prompt}],
            "stream": False
        }
        resp = requests.post(
            f"{ai_endpoint.rstrip('/')}/v1/chat/completions",
            json=payload,
            timeout=60
        )
        if resp.status_code == 200:
            data = resp.json()
            return data.get("choices", [{}])[0].get("message", {}).get("content", "")
    except Exception as e:
        pass

    return get_fallback_remediation(malware_type)


def get_fallback_remediation(malware_type):
    remediations = {
        "ransomware": """**What This Malware Does**
Ransomware encrypts your files and demands payment for decryption keys. It can spread across network shares and backup drives, making recovery extremely difficult without proper backups.

**Removal Steps**
1. Immediately disconnect the infected machine from the network (unplug ethernet, disable WiFi)
2. Do NOT pay the ransom — it does not guarantee file recovery
3. Boot from a clean USB/CD with an antivirus tool (Kaspersky Rescue Disk, Malwarebytes)
4. Run a full system scan and quarantine/delete all detected files
5. Check for persistence in startup entries, scheduled tasks, and registry run keys
6. Restore files from clean, offline backups (verify backups are not also encrypted)
7. Reinstall the OS if full removal cannot be confirmed

**Network Safety Measures**
1. Isolate all machines on the same network segment immediately
2. Scan all shared network drives for encrypted files (look for unusual extensions)
3. Check and revoke any compromised credentials used on the network
4. Block the machine's MAC address at the switch level until cleared
5. Review firewall logs for C2 communication and block identified IPs/domains
6. Alert your IT security team or incident response provider

**Prevention Tips**
- Maintain offline/air-gapped backups tested regularly
- Apply the 3-2-1 backup rule (3 copies, 2 media types, 1 offsite)
- Keep all systems and software fully patched
- Implement least-privilege access and disable unnecessary network shares""",

        "trojan": """**What This Malware Does**
Trojans disguise themselves as legitimate software while providing attackers unauthorized access. They can steal credentials, download additional malware, or create backdoors for persistent access.

**Removal Steps**
1. Disconnect from the internet to prevent data exfiltration
2. Boot into Safe Mode to prevent the trojan from running
3. Run Malwarebytes or Windows Defender Offline scan
4. Check Task Manager / Process Explorer for suspicious processes
5. Review startup programs (msconfig, Task Manager startup tab)
6. Check scheduled tasks and registry run keys for persistence
7. Delete quarantined files and clear temporary folders
8. Change all passwords from a clean, separate device

**Network Safety Measures**
1. Review firewall logs for outbound connections to unknown IPs
2. Block suspicious external IPs/domains at the perimeter firewall
3. Check for lateral movement — review login attempts on other machines
4. Reset all shared credentials that may have been compromised
5. Monitor network traffic for unusual outbound data transfers

**Prevention Tips**
- Only download software from official, verified sources
- Keep antivirus/EDR solutions updated with real-time protection
- Enable application whitelisting where possible
- Train users to recognize social engineering attacks""",

        "cryptominer": """**What This Malware Does**
Cryptominers use your system's CPU/GPU resources to mine cryptocurrency for attackers, causing performance degradation, hardware wear, and increased electricity costs.

**Removal Steps**
1. Identify the mining process using Task Manager or Process Explorer (look for high CPU usage)
2. Note the process name and file location before terminating
3. Run a full antivirus scan with Malwarebytes or similar tool
4. Remove persistence mechanisms (startup, scheduled tasks, services)
5. Delete the miner executable and associated files
6. Clear browser extensions if browser-based mining is suspected
7. Reset browser settings to default

**Network Safety Measures**
1. Block known mining pool domains/IPs at your firewall (e.g., *.minexmr.com, *.nanopool.org)
2. Monitor for unusual outbound traffic on ports 3333, 4444, 5555, 7777
3. Check for other infected machines showing high CPU usage
4. Review DNS logs for mining pool resolution attempts

**Prevention Tips**
- Use DNS filtering to block known mining pool domains
- Enable browser extensions that block in-browser miners (uBlock Origin)
- Monitor CPU/GPU usage baselines and alert on anomalies
- Keep systems patched to prevent exploitation-based installation"""
    }
    return remediations.get(malware_type, remediations.get("trojan"))


@app.route("/")
def index():
    return send_from_directory("static", "index.html")


@app.route("/api/scan/file", methods=["POST"])
def scan_file():
    api_key = request.form.get("api_key", "").strip()
    ai_endpoint = request.form.get("ai_endpoint", "http://localhost:11434").strip()
    ai_model = request.form.get("ai_model", "llama3").strip()

    if not api_key:
        return jsonify({"error": "VirusTotal API key is required"}), 400

    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files["file"]
    if not file.filename:
        return jsonify({"error": "Empty filename"}), 400

    # Save uploaded file
    safe_name = Path(file.filename).name
    filepath = os.path.join(UPLOAD_FOLDER, safe_name)
    file.save(filepath)

    try:
        result = process_single_file(filepath, safe_name, api_key, ai_endpoint, ai_model)
        return jsonify(result)
    finally:
        if os.path.exists(filepath):
            os.remove(filepath)


@app.route("/api/scan/path", methods=["POST"])
def scan_path():
    data = request.get_json()
    api_key = data.get("api_key", "").strip()
    ai_endpoint = data.get("ai_endpoint", "http://localhost:11434").strip()
    ai_model = data.get("ai_model", "llama3").strip()
    scan_path = data.get("path", "").strip()

    if not api_key:
        return jsonify({"error": "VirusTotal API key is required"}), 400
    if not scan_path:
        return jsonify({"error": "File or folder path is required"}), 400
    if not os.path.exists(scan_path):
        return jsonify({"error": f"Path does not exist: {scan_path}"}), 400

    target = Path(scan_path)
    if target.is_file():
        files_to_scan = [target]
    elif target.is_dir():
        files_to_scan = [f for f in target.rglob("*") if f.is_file()]
    else:
        return jsonify({"error": "Invalid path"}), 400

    if len(files_to_scan) > 50:
        return jsonify({"error": "Too many files. Limit to 50 files per scan."}), 400

    results = []
    for f in files_to_scan:
        result = process_single_file(str(f), f.name, api_key, ai_endpoint, ai_model)
        results.append(result)
        time.sleep(1)  # Respect API rate limits

    return jsonify({"results": results, "total": len(results)})


def process_single_file(filepath, filename, api_key, ai_endpoint, ai_model):
    file_hash = get_file_hash(filepath)

    # Check cache first
    if file_hash in scan_results_cache:
        cached = scan_results_cache[file_hash]
        cached["from_cache"] = True
        return cached

    # Try to get existing VT report by hash
    vt_data = check_hash_virustotal(file_hash, api_key)

    if vt_data is None:
        # Upload file for fresh scan
        analysis_id, error = upload_file_virustotal(filepath, api_key)
        if error:
            return {"filename": filename, "error": error, "sha256": file_hash}

        # Poll for results
        vt_data = poll_analysis(analysis_id, api_key)
        if not vt_data:
            return {"filename": filename, "error": "Analysis timed out", "sha256": file_hash}

        # Fetch the file report using hash
        time.sleep(2)
        vt_data = check_hash_virustotal(file_hash, api_key) or vt_data

    scan_data = parse_vt_result(vt_data)
    scan_data["filename"] = filename

    # Get AI remediation if file is suspicious
    remediation = None
    if scan_data["malicious"] > 0 or scan_data["suspicious"] > 2:
        remediation = get_ai_remediation(scan_data, ai_endpoint, ai_model)

    result = {
        "filename": filename,
        "sha256": scan_data.get("sha256", file_hash),
        "md5": scan_data.get("md5", ""),
        "file_type": scan_data.get("file_type", "Unknown"),
        "file_size": scan_data.get("file_size", 0),
        "malicious": scan_data["malicious"],
        "suspicious": scan_data["suspicious"],
        "undetected": scan_data["undetected"],
        "harmless": scan_data["harmless"],
        "total": scan_data["total"],
        "threat_names": scan_data["threat_names"],
        "malware_type": scan_data["malware_type"],
        "is_malicious": scan_data["malicious"] > 0,
        "is_suspicious": scan_data["suspicious"] > 2,
        "remediation": remediation,
        "from_cache": False,
        "vt_link": f"https://www.virustotal.com/gui/file/{scan_data.get('sha256', file_hash)}"
    }

    scan_results_cache[file_hash] = result
    return result


@app.route("/api/models", methods=["POST"])
def get_models():
    data = request.get_json()
    endpoint = data.get("endpoint", "http://localhost:11434").strip()

    models = []
    # Try Ollama API
    try:
        resp = requests.get(f"{endpoint.rstrip('/')}/api/tags", timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            models = [m["name"] for m in data.get("models", [])]
            return jsonify({"models": models, "type": "ollama"})
    except:
        pass

    # Try OpenAI-compatible
    try:
        resp = requests.get(f"{endpoint.rstrip('/')}/v1/models", timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            models = [m["id"] for m in data.get("data", [])]
            return jsonify({"models": models, "type": "openai"})
    except:
        pass

    return jsonify({"models": [], "error": "Could not connect to AI endpoint"})


if __name__ == "__main__":
    print("🛡️  VirusTotal File Scanner starting on http://localhost:5000")
    app.run(debug=True, host="0.0.0.0", port=5000)
