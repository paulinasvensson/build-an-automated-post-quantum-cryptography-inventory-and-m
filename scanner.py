"""
Core detection logic for cryptographic primitives that are vulnerable to
quantum attacks (or already deprecated), plus prioritized PQC migration
guidance mapped to NIST FIPS 203/204/205 and NSA CNSA 2.0.
"""
import re
from dataclasses import dataclass, asdict
from typing import List, Dict

@dataclass
class Rule:
    name: str
    pattern: str
    family: str
    quantum_vulnerable: bool
    risk: str  # critical | high | medium | low
    recommendation: str
    standard_ref: str


RULES: List[Rule] = [
    Rule("RSA key generation", r"\bRSA\b.{0,40}(generate|GenerateKey|new\s*\(\s*RSA)|rsa\.generate_private_key",
         "RSA", True, "critical",
         "Replace with ML-KEM (FIPS 203) for key exchange and ML-DSA (FIPS 204) for signatures.",
         "NIST FIPS 203/204, CNSA 2.0 (2030 deadline)"),
    Rule("RSA reference", r"\bRSA-?\d{3,4}\b|RSAPrivateKey|RSAPublicKey|PKCS1|rsa\.PublicKey",
         "RSA", True, "high",
         "Migrate signature/exchange logic to ML-DSA / ML-KEM.",
         "NIST FIPS 203/204"),
    Rule("Elliptic curve crypto", r"\bECDSA\b|\bECDH\b|EllipticCurve|secp256r1|secp384r1|prime256v1|NIST P-256|P-384",
         "ECC", True, "critical",
         "Replace ECDSA/ECDH with ML-DSA (signatures) and ML-KEM (key exchange).",
         "NIST FIPS 203/204, CNSA 2.0 (2030 deadline)"),
    Rule("Diffie-Hellman", r"\bDiffieHellman\b|\bDHParameterSpec\b|\bDHKeyPair\b",
         "DH", True, "high",
         "Replace classical DH with ML-KEM (FIPS 203) for key establishment.",
         "NIST FIPS 203"),
    Rule("Hash-based signature gap", r"\bDSA\b(?!ML)",
         "DSA", True, "high",
         "Migrate DSA signatures to ML-DSA (FIPS 204) or SLH-DSA (FIPS 205).",
         "NIST FIPS 204/205"),
    Rule("Deprecated symmetric cipher", r"\bDES\b|\b3DES\b|DESede|\bRC4\b",
         "Symmetric", False, "high",
         "Retire in favor of AES-256-GCM (still quantum-resistant with sufficient key size).",
         "NIST SP 800-131A"),
    Rule("Weak hash function", r"\bMD5\b|\bSHA1\b|\bSHA-1\b",
         "Hash", False, "medium",
         "Migrate to SHA-256/SHA-3; required before adopting ML-DSA hash-and-sign flows.",
         "NIST SP 800-131A"),
    Rule("Certificate / key material", r"\.pem\b|\.p12\b|\.pfx\b|\.crt\b|BEGIN (RSA |EC )?PRIVATE KEY",
         "PKI", True, "medium",
         "Inventory issuing CA and re-issue certificate chain using ML-DSA once CA supports it.",
         "CNSA 2.0 PKI transition guidance"),
    Rule("TLS legacy key exchange", r"TLS_RSA_|TLS_ECDHE_|kx=RSA|kx=ECDHE",
         "TLS", True, "medium",
         "Enable hybrid PQC key exchange (X25519MLKEM768) in TLS 1.3 configuration.",
         "IETF hybrid PQC TLS draft"),
]

_COMPILED = [(r, re.compile(r.pattern, re.IGNORECASE)) for r in RULES]

RISK_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def scan_text(text: str) -> List[Dict]:
    findings = []
    lines = text.splitlines()
    for i, line in enumerate(lines, start=1):
        for rule, compiled in _COMPILED:
            if compiled.search(line):
                findings.append({
                    "line": i,
                    "snippet": line.strip()[:120],
                    "algorithm": rule.name,
                    "family": rule.family,
                    "quantum_vulnerable": rule.quantum_vulnerable,
                    "risk": rule.risk,
                    "recommendation": rule.recommendation,
                    "standard_ref": rule.standard_ref,
                })
    findings.sort(key=lambda f: RISK_ORDER.get(f["risk"], 9))
    return findings


def summarize(findings: List[Dict]) -> Dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    quantum_vulnerable_count = 0
    for f in findings:
        counts[f["risk"]] = counts.get(f["risk"], 0) + 1
        if f["quantum_vulnerable"]:
            quantum_vulnerable_count += 1
    return {
        "total_findings": len(findings),
        "quantum_vulnerable_count": quantum_vulnerable_count,
        "by_risk": counts,
    }


def build_roadmap(findings: List[Dict]) -> List[Dict]:
    """Group findings by algorithm family and produce a prioritized,
    time-boxed migration plan aligned with CNSA 2.0 phase deadlines."""
    families: Dict[str, List[Dict]] = {}
    for f in findings:
        families.setdefault(f["family"], []).append(f)

    phase_map = {
        "critical": ("Phase 1: 2025-2027", "Immediate — public-key exchange & signatures exposed to harvest-now-decrypt-later attacks."),
        "high": ("Phase 2: 2027-2030", "High priority — must be remediated before CNSA 2.0 2030 checkpoint."),
        "medium": ("Phase 3: 2030-2033", "Medium priority — schedule alongside routine cert/library rotation."),
        "low": ("Phase 4: 2033-2035", "Low priority — remediate opportunistically."),
    }

    roadmap = []
    for family, items in sorted(
        families.items(),
        key=lambda kv: min(RISK_ORDER.get(i["risk"], 9) for i in kv[1]),
    ):
        top_risk = min(items, key=lambda i: RISK_ORDER.get(i["risk"], 9))["risk"]
        phase, phase_desc = phase_map.get(top_risk, phase_map["low"])
        recommendations = sorted(set(i["recommendation"] for i in items))
        standards = sorted(set(i["standard_ref"] for i in items))
        roadmap.append({
            "family": family,
            "occurrences": len(items),
            "priority": top_risk,
            "phase": phase,
            "phase_description": phase_desc,
            "recommendations": recommendations,
            "standards": standards,
            "example_lines": [i["line"] for i in items][:5],
        })
    return roadmap
