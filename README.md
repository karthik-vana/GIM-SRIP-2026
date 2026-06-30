# BSAAP: Blockchain-Integrated Secure Agent-to-Agent Authentication Protocol for Multi-Agent AI Systems

[![Journal](https://img.shields.io/badge/Journal-Systems%20Architecture-blue)](https://www.sciencedirect.com/journal/journal-of-systems-architecture)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.12%2B-blue.svg)](https://www.python.org/)

## Overview

**BSAAP** is a six-stage cryptographic protocol providing mutual authentication, capability-scoped access control, forward-secret session key establishment, and auditable accountability for autonomous AI agent interactions. It is designed to address the critical security vacuum in multi-agent AI systems where existing authentication frameworks (PKI, OAuth 2.0, JWT) are architecturally ill-suited to the dynamic, ephemeral, and autonomous nature of modern multi-agent systems (MAS).

This repository contains the LaTeX source for the research paper submitted to the **Journal of Systems Architecture (Elsevier)** and the prototype implementation.

## Key Features

| Feature | Description |
|---------|-------------|
| **On-chain Agent DID Registry** | Agent identity anchored on Hyperledger Fabric via W3C DID Core (prototype in simulation) |
| **Capability-scoped X.509 Certificates** | Custom OID extensions encode each agent's allowed task scope |
| **ECDH Forward-Secret Session Keys** | Ephemeral X25519 key exchange with HKDF-SHA-256 derivation |
| **Smart-Contract Revocation** | Immediate credential revocation via Fabric chaincode (simulation) |
| **Merkle-Chained Audit Trail** | Every session record is Merkle-linked for tamper-evident accountability |

## Protocol Stages

```
Stage 1: Agent Registration with On-Chain DID
Stage 2: Authentication Request (signed, with ephemeral key)
Stage 3: Challenge-Response Verification (mutual ECDSA)
Stage 4: Ephemeral Session Key Establishment (X25519 + HKDF)
Stage 5: Secure Authenticated Communication (AES-256-GCM + HMAC)
Stage 6: Session Termination and Blockchain Audit Logging
```

## Cryptographic Primitives

- **ECDSA P-256** — Long-term identity signatures
- **X25519** — Ephemeral Diffie-Hellman for forward-secret session keys
- **AES-256-GCM** — Authenticated payload encryption
- **HKDF-SHA-256** — Key derivation
- **SHA-256** — Hashing and Merkle chain construction

## Performance Results

Empirical evaluation over 100 repeated trials on standard hardware:

| Metric | Result |
|--------|--------|
| Full authentication latency | 1.118 ± 0.279 ms |
| Certificate verification | 0.154 ± 0.024 ms |
| AES-256-GCM encryption (256 B) | 0.005 ± 0.002 ms |
| Attack detection rate | 100% (all 5 threat classes) |
| Pytest test cases | 31/31 passing |

## Security Analysis

- **4 Formal Theorems**: Mutual Authentication, ROR Session Key Indistinguishability, Perfect Forward Secrecy, Replay Resistance
- **ROR Bound**: Adv ≤ 2·Adv^ECDDH + q_h/2^256
- **AVISPA/HLPSL Verification**: Stages 2–3 verified SAFE under Dolev-Yao model
- **5 Attack Classes Tested**: Replay, Impersonation, Expired credential, Tampered message, Capability escalation

## Repository Structure

```
GIM-SRIP-2026/
├── README.md                # This file
├── BSAAP_Paper.tex          # LaTeX source for the research paper
└── bsaap/                   # Prototype implementation (coming soon)
    ├── protocol/            # Six protocol stages
    ├── crypto/              # Cryptographic utilities
    ├── ca/                  # Authentication Authority
    ├── blockchain/          # Fabric gateway (simulation)
    ├── audit/               # Merkle-chained audit log
    └── tests/               # 31 pytest test cases
```

## Building the Paper

```bash
# Requires a LaTeX distribution (TeX Live, MiKTeX, or Overleaf)
pdflatex BSAAP_Paper.tex
pdflatex BSAAP_Paper.tex  # Run twice for cross-references
```

## Tech Stack

- **Language**: Python 3.12.3
- **Cryptography**: `cryptography` 42.0 (ECDSA, X25519, AES-GCM, HKDF)
- **API Framework**: FastAPI 0.111
- **ASGI Server**: Uvicorn 0.29
- **Blockchain**: Hyperledger Fabric (simulated client)
- **Testing**: pytest

## Citation

If you use this work in your research, please cite:

```bibtex
@article{karthik2026bsaap,
  title={Blockchain-Integrated Secure Agent-to-Agent Authentication Protocol 
         for Multi-Agent AI Systems (BSAAP)},
  author={Karthik V.},
  journal={Journal of Systems Architecture},
  year={2026},
  publisher={Elsevier},
  note={SRIP-2026 Big Data Analytics Research Fellow, 
        Goa Institute of Management}
}
```

## Author

**Karthik V.**
Goa Institute of Management, Sanquelim, Goa 403505, India
M.Tech AI/ML, SRIP-2026 Big Data Analytics Research Fellow

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

## Acknowledgements

This work was conducted as part of a Summer Research Internship at the Goa Institute of Management under the SRIP-2026 Big Data Analytics Research Fellowship.