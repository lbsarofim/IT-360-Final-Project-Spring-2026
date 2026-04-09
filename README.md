# SENTINEL — VirusTotal File Threat Scanner

A local web application that scans files against VirusTotal and uses a local AI model (via Open WebUI / Ollama) to generate step-by-step remediation instructions.

---

## Features

- **Drag-and-drop or file picker** upload for single/multiple files
- **Path-based scanning** for files or entire folders (server-side)
- **VirusTotal integration** — checks existing hash reports, uploads new files
- **Malware type detection** — ransomware, trojan, worm, spyware, rootkit, cryptominer, botnet, adware
- **AI-powered remediation** via your local Open WebUI / Ollama model
- **Fallback remediation** if AI is unavailable (built-in expert guidance)
- Hash-based **result caching** to avoid redundant API calls
- Large file support (>32MB via VT upload URL API)

---

## Setup

### 1. Install dependencies

```bash
cd virustotal_scanner
pip install -r requirements.txt
```

### 2. Get a VirusTotal API key

- Sign up at https://www.virustotal.com
- Go to your profile → API key
- Free tier: 4 requests/minute, 500/day

### 3. Set up your local AI (choose one)

**Ollama (recommended):**
```bash
# Install Ollama from https://ollama.ai
ollama pull llama3        # or mistral, phi3, gemma, etc.
ollama serve              # starts at http://localhost:11434
```

**Open WebUI:**
```bash
docker run -d -p 3000:8080 --add-host=host.docker.internal:host-gateway \
  -v open-webui:/app/backend/data --name open-webui \
  ghcr.io/open-webui/open-webui:main
# Then point the app to: http://localhost:3000
```

### 4. Run the scanner

```bash
python app.py
```

Open your browser to: **http://localhost:5000**

---

## Usage

### File Upload Mode
1. Enter your VirusTotal API key in the Config panel
2. Set your local AI endpoint (default: `http://localhost:11434`)
3. Enter your AI model name or click `↺` to auto-detect
4. Drag and drop files onto the upload zone (or click to browse)
5. Click **INITIATE SCAN**

### Path Scan Mode
1. Click the **PATH SCAN** zone
2. Enter an absolute path to a file or folder:
   - Single file: `/home/user/suspicious.exe`
   - Folder: `/home/user/Downloads`
3. Click **INITIATE SCAN** (max 50 files per folder)

---

## Result Interpretation

| Score | Meaning |
|-------|---------|
| 0/X engines | Clean — no detections |
| 1-3/X engines | Low risk — possible false positive |
| 4-10/X engines | Suspicious — investigate further |
| 10+/X engines | High risk — likely malicious |

---

## Architecture

```
virustotal_scanner/
├── app.py              # Flask backend + VT API logic + AI integration
├── requirements.txt    # Python dependencies
├── README.md
└── static/
    └── index.html      # Full frontend (HTML/CSS/JS, single file)
```

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/scan/file` | Upload and scan a file (multipart/form-data) |
| POST | `/api/scan/path` | Scan a server-side file or folder (JSON) |
| POST | `/api/models` | Fetch available models from AI endpoint |

---

## Notes

- VirusTotal free API: 4 lookups/min. The app adds 1-second delays between files
- Files are temporarily saved to `/tmp/vt_scanner_uploads/` and deleted after scanning
- Results are cached in memory (by SHA256) for the session duration
- The AI model is prompted with malware type, detections, and threat names to generate contextual remediation
- If AI is unreachable, built-in expert remediation guides are used for common malware types
