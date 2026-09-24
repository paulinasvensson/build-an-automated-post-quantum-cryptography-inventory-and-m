"""
Core cryptographic-inventory scanning logic.

Given a blob of source code / config / dependency-manifest text, find
usages of legacy (quantum-vulnerable) cryptographic primitives and map
each finding to a NIST-approved post-quantum replacement.
"""

import re
from dataclasses import dataclass, field

# algorithm -> (regex, severity, quantum_risk, pqc_recommendation, effort)
PATTERNS: dict[str, dict] = {
    "RSA": {
        "regex": re.compile(r"\bRSA\b|rsa\.generate_private_key|RSA_generate_key|new\s+RSACryptoServiceProvider", re.I),
        "severity": "critical",
        "risk": "Broken by Shor's algorithm on a cryptographically relevant quantum computer.",
        "pqc": "ML-KEM (Kyber) for key exchange + ML-DSA (Dilithium) for signatures",
        "effort": "High",
    },
    "ECC/ECDSA/ECDH": {
        "regex": re.compile(r"\bECDSA\b|\bECDH\b|EllipticCurve|SECP256|prime256v1|\bECC\b", re.I),
        "severity": "critical",
        "risk": "Broken by Shor's algorithm; equally vulnerable to RSA under quantum attack.",
        "pqc": "ML-DSA (Dilithium) or SLH-DSA (SPHINCS+) for signatures; ML-KEM for exchange",
        "effort": "High",
    },
    "DH (classic Diffie-Hellman)": {
        "regex": re.compile(r"\bDiffieHellman\b|\bDH_generate_key\b|\bDHParameterSpec\b", re.I),
        "severity": "high",
        "risk": "Discrete-log based; broken by Shor's algorithm.",
        "pqc": "ML-KEM (Kyber) hybrid key exchange",
        "effort": "Medium",
    },
    "DES/3DES": {
        "regex": re.compile(r"\bDES\b|3DES|TripleDES|DESede", re.I),
        "severity": "high",
        "risk": "Weak block cipher; effective security further reduced by Grover's algorithm.",
        "pqc": "AES-256 (symmetric, quantum-resistant with sufficient key length)",
        "effort": "Low",
    },
    "MD5": {
        "regex": re.compile(r"\bMD5\b|hashlib\.md5|CryptoJS\.MD5", re.I),
        "severity": "medium",
        "risk": "Cryptographically broken hash; collision-prone regardless of quantum threat.",
        "pqc": "SHA-3 / SHA-256 or higher",
        "effort": "Low",
    },
    "SHA-1": {
        "regex": re.compile(r"\bSHA-?1\b|hashlib\.sha1|CryptoJS\.SHA1", re.I),
        "severity": "medium",
        "risk": "Deprecated hash function; halved security margin under Grover's algorithm.",
        "pqc": "SHA-256/SHA-3 family",
        "effort": "Low",
    },
    "RC4": {
        "regex": re.compile(r"\bRC4\b|ARCFOUR", re.I),
        "severity": "high",
        "risk": "Broken stream cipher, independent of quantum threat but flagged for CNSA 2.0 compliance.",
        "pqc": "ChaCha20-Poly1305 / AES-256-GCM",
        "effort": "Low",
    },
}

SEVERITY_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1}


@dataclass
class Finding:
    algorithm: str
    severity: str
    line: int
    snippet: str
    risk: str
    pqc_recommendation: str
    effort: str


def scan_text(text: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = text.splitlines()
    for lineno, line in enumerate(lines, start=1):
        for name, spec in PATTERNS.items():
            if spec["regex"].search(line):
                findings.append(
                    Finding(
                        algorithm=name,
                        severity=spec["severity"],
                        line=lineno,
                        snippet=line.strip()[:160],
                        risk=spec["risk"],
                        pqc_recommendation=spec["pqc"],
                        effort=spec["effort"],
                    )
                )
    return findings


def build_roadmap(findings: list[Finding]) -> list[dict]:
    """Prioritize findings into a migration roadmap, ranked by risk score."""
    grouped: dict[str, dict] = {}
    for f in findings:
        g = grouped.setdefault(
            f.algorithm,
            {
                "algorithm": f.algorithm,
                "occurrences": 0,
                "severity": f.severity,
                "risk": f.risk,
                "pqc_recommendation": f.pqc_recommendation,
                "effort": f.effort,
                "lines": [],
            },
        )
        g["occurrences"] += 1
        g["lines"].append(f.line)

    roadmap = list(grouped.values())
    for item in roadmap:
        weight = SEVERITY_WEIGHT.get(item["severity"], 1)
        item["priority_score"] = round(weight * (1 + 0.1 * item["occurrences"]), 2)

    roadmap.sort(key=lambda x: x["priority_score"], reverse=True)
    for idx, item in enumerate(roadmap, start=1):
        item["priority_rank"] = idx
    return roadmap
