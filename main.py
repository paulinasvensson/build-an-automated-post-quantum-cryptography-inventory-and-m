from fastapi import FastAPI, Depends
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from entitlements import require_pro
from scanner import scan_text, build_roadmap, Finding

app = FastAPI(title="PQC Crypto Inventory Scanner")


class ScanRequest(BaseModel):
    code: str


def _findings_to_dicts(findings: list[Finding]) -> list[dict]:
    return [f.__dict__ for f in findings]


@app.post("/api/scan")
async def api_scan(req: ScanRequest):
    """Free feature: find quantum-vulnerable crypto usage in pasted text."""
    findings = scan_text(req.code)
    summary = {
        "total_findings": len(findings),
        "critical": sum(1 for f in findings if f.severity == "critical"),
        "high": sum(1 for f in findings if f.severity == "high"),
        "medium": sum(1 for f in findings if f.severity == "medium"),
    }
    return JSONResponse({"summary": summary, "findings": _findings_to_dicts(findings)})


@app.post("/api/roadmap")
async def api_roadmap(req: ScanRequest, _license=Depends(require_pro)):
    """Paid feature: full prioritized PQC migration roadmap."""
    findings = scan_text(req.code)
    roadmap = build_roadmap(findings)
    return JSONResponse({"roadmap": roadmap, "total_algorithms": len(roadmap)})


@app.get("/", response_class=HTMLResponse)
async def root():
    return HTMLResponse("""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PQC Crypto Inventory Scanner</title>
<script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-50 text-slate-800 font-sans">
<div class="max-w-3xl mx-auto p-4">

  <div class="mb-3">
    <h1 class="text-lg font-semibold text-slate-900">Post-Quantum Crypto Inventory</h1>
    <p class="text-sm text-slate-500">Paste code, config, or dependency manifests to find quantum-vulnerable crypto and get a prioritized migration roadmap.</p>
  </div>

  <div class="bg-white border border-slate-200 rounded-lg shadow-sm p-4 mb-3">
    <label class="block text-xs font-medium text-slate-600 mb-1">License Key (for full roadmap)</label>
    <div class="flex gap-2">
      <input id="licenseKey" type="text" placeholder="PQC-PRO-2024"
        class="flex-1 rounded-lg border border-slate-300 px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500">
      <button onclick="saveLicense()" class="rounded-lg bg-slate-800 text-white text-sm px-3 py-1.5 hover:bg-slate-700">Save</button>
    </div>
    <p id="licenseStatus" class="text-xs text-slate-400 mt-1"></p>
  </div>

  <div class="bg-white border border-slate-200 rounded-lg shadow-sm p-4">
    <label class="block text-xs font-medium text-slate-600 mb-1">Paste code / TLS config / dependency file</label>
    <textarea id="codeInput" rows="6" placeholder="e.g. RSA.generate(2048), hashlib.md5(...), ECDSA signature..."
      class="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-indigo-500"></textarea>

    <div class="flex gap-2 mt-3">
      <button onclick="runScan()" class="rounded-lg bg-indigo-600 text-white text-sm font-medium px-4 py-2 hover:bg-indigo-700">
        Scan for vulnerable crypto (free)
      </button>
      <button onclick="runRoadmap()" class="rounded-lg bg-emerald-600 text-white text-sm font-medium px-4 py-2 hover:bg-emerald-700">
        Generate migration roadmap (pro)
      </button>
    </div>

    <div id="result" class="mt-3 text-sm"></div>
  </div>
</div>

<script>
function saveLicense() {
  const key = document.getElementById('licenseKey').value.trim();
  localStorage.setItem('pqc_license_key', key);
  document.getElementById('licenseStatus').textContent = key ? "License key saved." : "License key cleared.";
}

window.onload = () => {
  const saved = localStorage.getItem('pqc_license_key');
  if (saved) {
    document.getElementById('licenseKey').value = saved;
    document.getElementById('licenseStatus').textContent = "Saved license key loaded.";
  }
};

function severityColor(sev) {
  if (sev === 'critical') return 'text-red-600 bg-red-50 border-red-200';
  if (sev === 'high') return 'text-orange-600 bg-orange-50 border-orange-200';
  if (sev === 'medium') return 'text-amber-600 bg-amber-50 border-amber-200';
  return 'text-slate-600 bg-slate-50 border-slate-200';
}

async function runScan() {
  const code = document.getElementById('codeInput').value;
  const resultEl = document.getElementById('result');
  resultEl.innerHTML = '<p class="text-slate-400">Scanning...</p>';
  try {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({code})
    });
    const data = await res.json();
    if (!res.ok) {
      resultEl.innerHTML = `<p class="text-red-600">Error: ${data.detail || 'scan failed'}</p>`;
      return;
    }
    if (data.findings.length === 0) {
      resultEl.innerHTML = '<p class="text-emerald-600">No legacy crypto primitives detected.</p>';
      return;
    }
    let html = `<p class="mb-2 font-medium">${data.summary.total_findings} finding(s) — ${data.summary.critical} critical, ${data.summary.high} high, ${data.summary.medium} medium</p>`;
    html += '<div class="space-y-1.5 max-h-48 overflow-y-auto pr-1">';
    data.findings.forEach(f => {
      html += `<div class="border rounded-lg px-3 py-2 text-xs ${severityColor(f.severity)}">
        <span class="font-semibold">${f.algorithm}</span> (line ${f.line}, ${f.severity}) — <code class="opacity-80">${f.snippet}</code>
      </div>`;
    });
    html += '</div>';
    resultEl.innerHTML = html;
  } catch (e) {
    resultEl.innerHTML = `<p class="text-red-600">Network error: ${e}</p>`;
  }
}

async function runRoadmap() {
  const code = document.getElementById('codeInput').value;
  const licenseKey = localStorage.getItem('pqc_license_key') || '';
  const resultEl = document.getElementById('result');
  resultEl.innerHTML = '<p class="text-slate-400">Generating roadmap...</p>';
  try {
    const res = await fetch('/api/roadmap', {
      method: 'POST',
      headers: {'Content-Type': 'application/json', 'X-License-Key': licenseKey},
      body: JSON.stringify({code})
    });
    const data = await res.json();
    if (res.status === 402) {
      resultEl.innerHTML = `<div class="border border-amber-300 bg-amber-50 text-amber-800 rounded-lg p-3 text-sm">
        <strong>License required.</strong> ${data.detail} Enter your license key above and click Save, then try again.
      </div>`;
      return;
    }
    if (!res.ok) {
      resultEl.innerHTML = `<p class="text-red-600">Error: ${data.detail || 'roadmap failed'}</p>`;
      return;
    }
    if (data.roadmap.length === 0) {
      resultEl.innerHTML = '<p class="text-emerald-600">No migration items — nothing quantum-vulnerable found.</p>';
      return;
    }
    let html = `<p class="mb-2 font-medium">Migration roadmap — ${data.total_algorithms} algorithm(s), ranked by priority</p>`;
    html += '<div class="space-y-1.5 max-h-56 overflow-y-auto pr-1">';
    data.roadmap.forEach(r => {
      html += `<div class="border rounded-lg px-3 py-2 text-xs ${severityColor(r.severity)}">
        <div class="flex justify-between">
          <span class="font-semibold">#${r.priority_rank} ${r.algorithm}</span>
          <span>score ${r.priority_score}</span>
        </div>
        <div class="opacity-90 mt-1">${r.occurrences} occurrence(s), lines: ${r.lines.join(', ')}</div>
        <div class="opacity-90 mt-1">Risk: ${r.risk}</div>
        <div class="mt-1 font-medium">→ Migrate to: ${r.pqc_recommendation} (effort: ${r.effort})</div>
      </div>`;
    });
    html += '</div>';
    resultEl.innerHTML = html;
  } catch (e) {
    resultEl.innerHTML = `<p class="text-red-600">Network error: ${e}</p>`;
  }
}
</script>
</body>
</html>
""")
