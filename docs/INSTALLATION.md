# Installation

## Actual environment used for development and validation

- Windows 11 with Docker Desktop (WSL2 backend). Kernel observed during testing: `6.18.33.2-microsoft-standard-WSL2`.
- Containers: Debian bookworm base images. Gateways run strongSwan 5.9.8 (swanctl/vici) with standard/extra/charon plugin packages for GCM and AH support.
- Python: **3.11** (official `python:3.11` Docker image) is used for all analysis steps. A host Python is not required; every documented command runs through Docker.

## Prerequisites

1. Docker Desktop (WSL2 backend enabled).
2. No other software is mandatory. All analysis uses the pinned `python:3.11` image plus the packages below.

## Python dependencies

`requirements.txt` lists exactly the packages the project imports:

```text
numpy
scipy
scikit-learn
joblib
scapy
```

Install inside the analysis container (the pattern used throughout the docs):

```bash
docker run --rm -v "${PWD}:/work" -w /work python:3.11 \
  sh -c "pip install -r requirements.txt && <command>"
```

Or on any machine with Python 3.11:

```bash
pip install -r requirements.txt
```

No web framework is required: the dashboard uses only the Python standard library.

## Testbed requirements

- The gateway image builds from `testbed/images/gateway/Dockerfile` (installs `libstrongswan-standard-plugins`, `libstrongswan-extra-plugins`, `libcharon-extra-plugins` for AES-GCM and AH).
- Gateways run privileged for XFRM SA/policy installation.
- A PSK is configured in `testbed/config/gateway-*/swanctl.conf` for testbed use only.

## Verify the installation

```bash
docker compose -f testbed/compose/testbed.yml up -d
powershell -File testbed/scripts/check-testbed.ps1
docker run --rm -v "${PWD}:/work" -w /work python:3.11 python -m unittest discover -s security/tests
docker run --rm -v "${PWD}:/work" -w /work python:3.11 python -m unittest discover -s integration/tests
```
