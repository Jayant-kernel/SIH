# Demo Guide (5-10 minutes)

Run from the repository root. Either execute `scripts/demo.ps1` for the automated flow, or run the steps manually with the commands below (prefix each Python command with `docker run --rm -v "${PWD}:/work" -w /work python:3.11` if using the container).

## Demo 1 — Strong ESP configuration (T04)

```bash
python integration/analyze.py --run dataset_v3_5_v2_full/T04/20260903-143933-601 --summary
python reports/generate_report.py --input <(python integration/analyze.py --run dataset_v3_5_v2_full/T04/20260903-143933-601) --out reports/results  # or via --output file
```

Show: ESP tunnel, AES-GCM (AEAD), MODP3072, PFS enabled, risk 0/100 (low), traffic ML prediction with confidence.

## Demo 2 — Security weakness: PFS disabled (T03)

```bash
python integration/analyze.py --run dataset_v3_5_v2_full/T03/20260903-143508-869 --summary
```

Show: PFS `false` from Child-SA evidence, threat-matrix entry "historical decryption impact", recommendation "Enable a Child-SA DH group", and the policy-dependent finding status.

## Demo 3 — AH has no confidentiality (T08)

```bash
python integration/analyze.py --run dataset_v3_5_v2_full/T08/20260903-145854-163 --summary
```

Show: protocol AH, encryption `none`, high-severity confidentiality finding, risk 50/100 (moderate), and rekey `no_rekey` derived from runtime swanctl before/after comparison.

## Demo 4 — Passive-only analysis (PCAP only)

```bash
python integration/analyze.py --pcap dataset_v3_5_v2_full/T15/20260903-173651-525/capture.pcap --output /tmp/passive.json
python reports/generate_report.py --input /tmp/passive.json --out reports/results
```

Show: ESP observed, traffic ML prediction works, AES key size / cipher / mode / PFS / replay remain `Unknown`, evidence completeness drops (~0.25), and the visible passive-only warning. No fabricated values.

## Demo 5 — Corrected T15 (IPv6 protected, clean ESP)

```bash
python integration/analyze.py --run dataset_v3_5_v2_full/T15/20260903-173651-525 --summary
```

Show: ESP tunnel with IPv6 traffic selectors `fd77:77:23::/64 <-> fd77:77:24::/64`, AES-CBC-192, PFS disabled, clean ESP-only transit capture, working traffic prediction, deterministic assessment.

## Live dashboard (optional, ~2 minutes)

```bash
python app/app.py
```

Open `http://127.0.0.1:8501/` and paste run/PCAP paths for the scenarios above. Point out the evidence badges (Observed / Derived / ML Inferred / Unknown) and that ML confidence is displayed as a model estimate.

## Talking points

- Deterministic runtime evidence is authoritative; ML is used only for traffic-type behavior.
- Unknown is displayed, never guessed.
- T15 shows the corrected dataset (no plaintext contamination).
- T14 (optional): the rekey scenario with genuine runtime SPI transition (`rekey_observed`).
