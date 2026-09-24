import re
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel

from entitlements import require_pro

app = FastAPI(title="PQC Crypto Inventory Scanner")

STATIC_DIR = Path(__file__).parent / "static"

# ---------------------------------------------------------------------------
# Detection engine
# ---------------------------------------------------------------------------

Severity = Literal["Critical", "High", "Medium", "Low"]

# Each rule: (name, regex, category, severity, quantum_vulnerable, pqc_recommendation)
RULES = [
    (
        "RSA key generation / usage",
        re.compile(r"\bRSA\.(generate|new)\b|\brsa\.generate_private_key\b|\bBEGIN RSA PRIVATE KEY\b|\bRSAPrivateKey\b|\bgenrsa\b", re.I),
        "Public-key encryption",
        "Critical",
        True,
        "ML-KEM (Kyber) for key exchange; ML-DSA (Dilithium) or SLH-DSA for signatures",
    ),
    (
        "Elliptic Curve Cryptography (ECC/ECDSA/ECDH)",
        re.compile(r"\bECDSA\b|\bECDH\b|\bEllipticCurve\b|\bsecp256\w*\b|\bprime256v1\b|\becdsa\.\w+\b", re.I),
        "Public-key encryption",
        "Critical",
        True,
        "ML-DSA (Dilithium) for signatures; ML-KEM (Kyber) for key exchange",
    ),
    (
        "Diffie-Hellman key exchange",
        re.compile(r"\bDiffieHellman\b|\bDH\.generate\b|\bdhparam\b", re.I),
        "Key exchange",
        "Critical",
        True,
        "ML-KEM (Kyber) key encapsulation",
    ),
    (
        "X.509 certificate / private key material",
        re.compile(r"BEGIN CERTIFICATE|BEGIN PRIVATE KEY|BEGIN EC PRIVATE KEY", re.I),
        "PKI / certificates",
        "High",
        True,
        "Reissue with hybrid classical+PQC or pure ML-DSA certificate chain",
    ),
    (
        "MD5 hash usage",
        re.compile(r"\bMD5\b|\bmd5\(", re.I),
        "Hashing",
        "High",
        False,
        "Migrate to SHA-256 / SHA-3 (collision-resistance, not quantum-broken but deprecated)",
    ),
    (
        "SHA-1 hash usage",
        re.compile(r"\bSHA1\b|\bsha1\(", re.I),
        "Hashing",
        "Medium",
        False,
        "Migrate to SHA-256 / SHA-3",
    ),
    (
        "3DES / DES cipher",
        re.compile(r"\b3?DES\b|\bTripleDES\b", re.I),
        "Symmetric encryption",
        "High",
        False,
        "Migrate to AES-256-GCM (quantum-resistant with sufficient key size)",
    ),
    (
        "RC4 stream cipher",
        re.compile(r"\bRC4\b", re.I),
        "Symmetric encryption",
        "High",
        False,
        "Migrate to AES-256-GCM or ChaCha20-Poly1305",
    ),
    (
        "Small RSA/DH key size (<= 2048 bit)",
        re.compile(r"\b(512|1024)\s*[-_]?\s*bit\b|key_?size\s*=\s*(512|1024)\b", re.I),
        "Key strength",
        "Critical",
        True,
        "Increase to 3072/4096-bit as interim step, then migrate fully to PQC",
    ),
]


class Finding(BaseModel):
    rule: str
    category: str
    severity: Severity
    quantum_vulnerable: bool
    pqc_recommendation: str
    line_number: int
    snippet: str


def scan_text(text: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = text.splitlines()
    for idx, line in enumerate(lines, start=1):
        for name, pattern, category, severity, qvuln, rec in RULES:
            if pattern.search(line):
                findings.append(
                    Finding(
                        rule=name,
                        category=category,
                        severity=severity,
                        quantum_vulnerable=qvuln,
                        pqc_recommendation=rec,
                        line_number=idx,
                        snippet=line.strip()[:160],
                    )
                )
    return findings


SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
SEVERITY_TO_PHASE = {
    "Critical": "Phase 1 — Immediate (0-6 months)",
    "High": "Phase 2 — Near-term (6-12 months)",
    "Medium": "Phase 3 — Mid-term (12-24 months)",
    "Low": "Phase 4 — Long-term (24-36 months)",
}
SEVERITY_EFFORT = {
    "Critical": "High effort — likely requires protocol/library redesign",
    "High": "Medium-high effort — library swap + testing",
    "Medium": "Medium effort — config/parameter change",
    "Low": "Low effort — configuration update",
}


class ScanRequest(BaseModel):
    code: str


class ScanResponse(BaseModel):
    findings: list[Finding]
    summary: dict


@app.post("/api/scan", response_model=ScanResponse)
def scan(req: ScanRequest):
    """Free tier: scan pasted code/config and list crypto findings."""
    findings = scan_text(req.code)
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        counts[f.severity] += 1
    summary = {
        "total_findings": len(findings),
        "by_severity": counts,
        "quantum_vulnerable_count": sum(1 for f in findings if f.quantum_vulnerable),
    }
    return ScanResponse(findings=findings, summary=summary)


class RoadmapItem(BaseModel):
    rule: str
    severity: Severity
    phase: str
    effort: str
    occurrences: int
    pqc_recommendation: str


class RoadmapResponse(BaseModel):
    crypto_debt_score: int
    roadmap: list[RoadmapItem]
    narrative: str


@app.post("/api/roadmap", response_model=RoadmapResponse, dependencies=[Depends(require_pro)])
def roadmap(req: ScanRequest):
    """Paid tier: full prioritized PQC migration roadmap."""
    findings = scan_text(req.code)

    grouped: dict[str, dict] = {}
    for f in findings:
        g = grouped.setdefault(
            f.rule,
            {
                "severity": f.severity,
                "occurrences": 0,
                "pqc_recommendation": f.pqc_recommendation,
            },
        )
        g["occurrences"] += 1

    items = [
        RoadmapItem(
            rule=rule,
            severity=data["severity"],
            phase=SEVERITY_TO_PHASE[data["severity"]],
            effort=SEVERITY_EFFORT[data["severity"]],
            occurrences=data["occurrences"],
            pqc_recommendation=data["pqc_recommendation"],
        )
        for rule, data in grouped.items()
    ]
    items.sort(key=lambda i: (SEVERITY_ORDER[i.severity], -i.occurrences))

    weight = {"Critical": 25, "High": 12, "Medium": 5, "Low": 1}
    debt_score = min(100, sum(weight[i.severity] * i.occurrences for i in items))

    if not items:
        narrative = (
            "No quantum-vulnerable or legacy cryptographic primitives were detected "
            "in the submitted material. Continue periodic re-scanning as code and "
            "dependencies evolve."
        )
    else:
        narrative = (
            f"Detected {len(items)} distinct crypto risk categories across "
            f"{sum(i.occurrences for i in items)} occurrences. Crypto-debt score: "
            f"{debt_score}/100. Prioritize Phase 1 items immediately to align with "
            f"NSA CNSA 2.0 and NIST PQC migration timelines ahead of 2030-2035 deadlines."
        )

    return RoadmapResponse(crypto_debt_score=debt_score, roadmap=items, narrative=narrative)


@app.get("/", response_class=HTMLResponse)
def index():
    return FileResponse(STATIC_DIR / "index.html")
