"""
Core detection logic: scans arbitrary text (source code, TLS/cert configs,
dependency manifests) for classical cryptographic primitives that are
vulnerable to quantum attacks (Shor's / Grover's algorithm) or otherwise
weak, and maps them to NIST-approved post-quantum replacements.
"""
import re
from dataclasses import dataclass, asdict

SEVERITY_WEIGHT = {"critical": 3, "high": 2, "medium": 1}

PQC_RECOMMENDATION = {
    "RSA": "ML-KEM (CRYSTALS-Kyber) for key exchange + ML-DSA (CRYSTALS-Dilithium) for signatures",
    "ECC/ECDSA/ECDH": "ML-KEM (Kyber) for exchange, ML-DSA (Dilithium) or SLH-DSA (SPHINCS+) for signatures",
    "DSA": "ML-DSA (CRYSTALS-Dilithium)",
    "Diffie-Hellman": "ML-KEM (CRYSTALS-Kyber) key encapsulation",
    "Weak RSA key size": "Retire immediately — migrate to ML-KEM/ML-DSA, do not re-key with larger RSA",
    "MD5": "SHA-3 (SHA3-256/512) or SHA-256 with HMAC",
    "SHA1": "SHA-3 (SHA3-256/512) or SHA-256",
    "DES/3DES": "AES-256-GCM",
    "RC4": "AES-256-GCM or ChaCha20-Poly1305",
}

PATTERNS = [
    {"name": "RSA", "regex": r"\bRSA\b|rsa\.generate|RSAPrivateKey|RSAPublicKey|PKCS1",
     "category": "asymmetric-encryption", "quantum_vulnerable": True, "severity": "critical"},
    {"name": "Weak RSA key size", "regex": r"RSA[^\n]{0,40}?\b(512|768|1024)\b",
     "category": "key-size", "quantum_vulnerable": True, "severity": "critical"},
    {"name": "ECC/ECDSA/ECDH", "regex": r"\bECDSA\b|\bECDH\b|EllipticCurve|secp256|secp384|prime256v1|P-256|P-384",
     "category": "asymmetric-encryption", "quantum_vulnerable": True, "severity": "critical"},
    {"name": "DSA", "regex": r"(?<![A-Za-z])DSA(?![A-Za-z])",
     "category": "signatures", "quantum_vulnerable": True, "severity": "high"},
    {"name": "Diffie-Hellman", "regex": r"Diffie-?Hellman|(?<![A-Za-z])DH(?![A-Za-z])",
     "category": "key-exchange", "quantum_vulnerable": True, "severity": "critical"},
    {"name": "MD5", "regex": r"\bMD5\b", "category": "hash",
     "quantum_vulnerable": False, "severity": "medium"},
    {"name": "SHA1", "regex": r"\bSHA-?1\b", "category": "hash",
     "quantum_vulnerable": False, "severity": "medium"},
    {"name": "DES/3DES", "regex": r"\b3?DES\b", "category": "symmetric-cipher",
     "quantum_vulnerable": False, "severity": "medium"},
    {"name": "RC4", "regex": r"\bRC4\b", "category": "symmetric-cipher",
     "quantum_vulnerable": False, "severity": "medium"},
]

_COMPILED = [(p, re.compile(p["regex"], re.IGNORECASE)) for p in PATTERNS]


@dataclass
class Finding:
    algorithm: str
    category: str
    severity: str
    quantum_vulnerable: bool
    line: int
    snippet: str
    recommendation: str


def scan_text(text: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = text.splitlines()
    for i, line in enumerate(lines, start=1):
        seen_here = set()
        for meta, rx in _COMPILED:
            if rx.search(line) and meta["name"] not in seen_here:
                seen_here.add(meta["name"])
                findings.append(Finding(
                    algorithm=meta["name"],
                    category=meta["category"],
                    severity=meta["severity"],
                    quantum_vulnerable=meta["quantum_vulnerable"],
                    line=i,
                    snippet=line.strip()[:160],
                    recommendation=PQC_RECOMMENDATION.get(meta["name"], "Review against NIST SP 800-208 / FIPS 203-205"),
                ))
    return findings


def findings_to_dicts(findings: list[Finding]) -> list[dict]:
    return [asdict(f) for f in findings]


def build_roadmap(findings: list[Finding]) -> dict:
    by_algo: dict[str, list[Finding]] = {}
    for f in findings:
        by_algo.setdefault(f.algorithm, []).append(f)

    ranked = []
    for algo, items in by_algo.items():
        weight = SEVERITY_WEIGHT.get(items[0].severity, 1)
        qv_multiplier = 2 if items[0].quantum_vulnerable else 1
        score = len(items) * weight * qv_multiplier
        ranked.append({
            "algorithm": algo,
            "occurrences": len(items),
            "severity": items[0].severity,
            "quantum_vulnerable": items[0].quantum_vulnerable,
            "priority_score": score,
            "recommendation": items[0].recommendation,
            "sample_lines": [it.line for it in items[:5]],
        })
    ranked.sort(key=lambda x: x["priority_score"], reverse=True)

    phase1 = [r for r in ranked if r["quantum_vulnerable"] and r["severity"] == "critical"]
    phase2 = [r for r in ranked if r["quantum_vulnerable"] and r["severity"] != "critical"]
    phase3 = [r for r in ranked if not r["quantum_vulnerable"]]

    return {
        "total_findings": len(findings),
        "distinct_algorithms": len(ranked),
        "priority_ranking": ranked,
        "phases": [
            {
                "phase": 1,
                "name": "Immediate — Quantum-Break Critical",
                "timeline": "0–6 months",
                "items": phase1,
                "rationale": "These primitives (RSA/ECC/DH) are directly broken by Shor's algorithm. "
                              "CNSA 2.0 and NIST timelines prioritize these first.",
            },
            {
                "phase": 2,
                "name": "Near-Term — Quantum-Exposed Signatures",
                "timeline": "6–12 months",
                "items": phase2,
                "rationale": "Remaining quantum-vulnerable signature/exchange usage not yet remediated.",
            },
            {
                "phase": 3,
                "name": "Hardening — Symmetric & Hash Upgrades",
                "timeline": "12–24 months",
                "items": phase3,
                "rationale": "Grover's algorithm halves effective symmetric security; upgrade key "
                              "sizes and retire deprecated hashes/ciphers as part of crypto-agility hygiene.",
            },
        ],
    }
