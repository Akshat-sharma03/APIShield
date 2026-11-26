# `APIShield` — Differential API Security Testing

<p align="center">

```text
     _    ____ ___ ____  _     _      _     _
    / \  |  _ \_ _/ ___|| |__ (_) ___| | __| |
   / _ \ | |_) | |\___ \| '_ \| |/ _ \ |/ _` |
  / ___ \|  __/| | ___) | | | | |  __/ | (_| |
 /_/   \_\_|  |___|____/|_| |_|_|\___|_|\__,_|

       DIFFERENTIAL API SECURITY TESTING
              BOLA / IDOR DETECTION
```

**Detect. Compare. Verify.**

[Python](https://www.python.org/) · [OWASP crAPI](https://github.com/OWASP/crAPI) · [pytest](https://pytest.org/) · SQLite · Jinja2

</p>

---

## 01 — Project Overview

**APIShield** is a modular Python tool designed to detect **Broken Object-Level Authorization (BOLA / IDOR)** vulnerabilities in authenticated APIs through differential security testing.

Developed as part of an MSc Cybersecurity and Penetration Testing coursework project, APIShield was designed and tested against a local OWASP crAPI laboratory.

Unlike general-purpose vulnerability scanners, APIShield focuses on one specific security problem:

> Does an API correctly enforce object-level authorization when authenticated users attempt to access resources belonging to someone else?

It answers this by comparing legitimate, cross-account and unauthenticated requests against an endpoint's expected authorization policy.

## 02 — How It Works

APIShield uses a five-case differential testing matrix for every configured endpoint.

| Case | Requester | Resource | Purpose |
|---|---|---|---|
| B01 | User A | User A | Legitimate baseline |
| B02 | User B | User B | Legitimate baseline |
| B03 | User A | User B | Cross-account probe |
| B04 | User B | User A | Cross-account probe |
| B05 | Anonymous | User B | Authentication control |

Cross-account responses are compared against the resource owner's legitimate baseline.

APIShield evaluates evidence such as:

- Whether the request obtained access.
- Whether owner identity fields match.
- Whether the response matches the owner's baseline.
- Whether the requested object is returned with ownership or sensitive-field context.
- Whether the endpoint behaves according to its configured authorization policy.

### Classification results

| Classification | Meaning |
|---|---|
| `CONFIRMED` | Differential evidence supports unauthorized object access. |
| `SUSPECTED` | Access was obtained, but ownership or exposure could not be verified sufficiently. |
| `INCONCLUSIVE` | Testing could not establish a reliable conclusion. |
| `NO_ISSUE` | The tested access controls behaved as expected. |

**Important:** An HTTP 200 response alone is never considered proof of BOLA. APIShield requires additional differential evidence before confirming a finding.

## 03 — Architecture

```text
                 ┌──────────────────────┐
                 │      CLI / User      │
                 └──────────┬───────────┘
                            │
                 ┌──────────▼───────────┐
                 │ Configuration Loader│
                 └──────────┬───────────┘
                            │
                 ┌──────────▼───────────┐
                 │    Target Validator  │
                 └──────────┬───────────┘
                            │
                 ┌──────────▼───────────┐
                 │   Endpoint Loader    │
                 └──────────┬───────────┘
                            │
                 ┌──────────▼───────────┐
                 │    BOLA Engine       │
                 │      B01–B05         │
                 └──────────┬───────────┘
                            │
                 ┌──────────▼───────────┐
                 │  Response Analyzer  │
                 └──────────┬───────────┘
                            │
                 ┌──────────▼───────────┐
                 │ Evidence Classifier │
                 └──────────┬───────────┘
                            │
                 ┌──────────▼───────────┐
                 │   SQLite Database   │
                 └──────────┬───────────┘
                            │
                 ┌──────────▼───────────┐
                 │   Report Generator  │
                 │     JSON / HTML     │
                 └─────────────────────┘
```

### Project Structure

```text
APIShield/
│
├── main.py
│
├── config/
│   ├── settings.json
│   └── endpoints.json
│
├── apishield/
│   ├── __init__.py
│   ├── config.py
│   ├── authentication.py
│   ├── target_validator.py
│   ├── request_handler.py
│   ├── endpoint_loader.py
│   ├── bola_engine.py
│   ├── response_analyzer.py
│   ├── classifier.py
│   ├── evidence.py
│   ├── database.py
│   └── reporting.py
│
├── templates/
│   └── report.html
│
├── tests/
│
├── evidence/       # Local database; gitignored
├── reports/        # Generated reports; gitignored
│
├── requirements.txt
├── requirements-dev.txt
├── .env.example
├── .gitignore
└── README.md
```

## 04 — Security Controls

APIShield includes safety restrictions designed to prevent accidental testing outside the intended laboratory.

| Control | Implementation |
|---|---|
| Target restriction | Literal loopback IP addresses only: `127.0.0.0/8` and `::1` |
| DNS protection | Hostnames, including `localhost`, are rejected |
| Redirect protection | Redirects disabled by default; off-loopback destinations rejected |
| Proxy isolation | Environment proxy settings ignored using `trust_env=False` |
| Request budget | Default maximum of 50 requests per scan |
| Request timeout | 10 seconds |
| Response size | Streamed responses capped at 1 MB |
| HTTP methods | GET requests only |
| Evidence protection | Raw response bodies and credentials are not persisted |
| Identifier protection | Resource identifiers stored as SHA-256 fingerprints |
| Database security | Parameterised SQLite statements |

## 05 — Installation

### Requirements

- Python 3.10 or newer
- pip
- An isolated laboratory environment
- OWASP crAPI for the intended integration-testing environment

Developed and tested using Python 3.13.

### Clone the repository

```bash
git clone https://github.com/Akshat-sharma03/APIShield.git
cd APIShield
```

### Create a virtual environment

**Linux / Kali Linux / macOS**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

**Windows PowerShell**

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

### Install dependencies

```bash
pip install -r requirements.txt
```

For development and testing:

```bash
pip install -r requirements-dev.txt
```

## 06 — Configuration

APIShield uses environment variables to configure the target and test identities.

First, copy the example environment file:

**Linux / Kali Linux / macOS**

```bash
cp .env.example .env
```

**Windows PowerShell**

```powershell
Copy-Item .env.example .env
```

Configure the following values in `.env`:

```env
APISHIELD_BASE_URL=http://127.0.0.1:8888

APISHIELD_USER_A_TOKEN=<token for user A>
APISHIELD_USER_B_TOKEN=<token for user B>

APISHIELD_USER_A_VEHICLE_ID=<resource id owned by user A>
APISHIELD_USER_B_VEHICLE_ID=<resource id owned by user B>
```

### Configuration files

| File | Purpose |
|---|---|
| `.env` | Local credentials and target configuration |
| `config/settings.json` | Request limits and runtime settings |
| `config/endpoints.json` | Endpoint definitions and authorization policies |

Endpoint definitions can be extended through `config/endpoints.json` without changing the core application code.

**Never commit `.env` or real authentication tokens to GitHub.**

## 07 — Usage

Run the following commands from the project root.

### Validate configuration

```bash
python3 main.py check
```

```bash
python3 main.py validate-config
```

### List configured endpoints

```bash
python3 main.py list-endpoints
```

### Run a complete scan

```bash
python3 main.py scan
```

### Scan a specific endpoint

```bash
python3 main.py scan --endpoint vehicle_location
```

### View previous results

```bash
python3 main.py results
```

### Generate reports

**JSON**

```bash
python3 main.py report --format json
```

**HTML**

```bash
python3 main.py report --format html
```

**Report a specific run**

```bash
python3 main.py report --run <run-id> --format html
```

Scans persist redacted evidence in a local SQLite database. Reports are generated from the stored results and are saved in the `reports/` directory by default.

## 08 — Testing & Results

APIShield includes automated unit tests using mocked HTTP responses and synthetic test data.

Run the test suite:

```bash
python3 -m pytest tests -q
```

### Development test results

| Metric | Result |
|---|---:|
| Reported automated tests passed | 191 |
| Test execution time | 0.55 seconds |
| Live target contacted by unit tests | No |
| HTTP testing approach | Mocked responses |

The 191-test result is from the reported final development test run. It should not be interpreted as proof of successful live integration testing.

### Integration testing

Integration testing is intended to be performed against the local OWASP crAPI laboratory.

The integration environment is separate from the automated mocked unit-test environment.

A successful unit-test run does not replace live integration testing.

## 09 — Ethical Testing: Do's & Don'ts

APIShield is designed for controlled and authorised security testing.

### DO

- Obtain explicit permission before testing an API.
- Use an isolated laboratory or an explicitly authorised target.
- Create synthetic test accounts and test resources.
- Use separate identities to verify object ownership.
- Keep request volumes within configured limits.
- Review findings manually before reporting them.
- Protect credentials and local evidence.
- Document the testing scope, methodology and results.
- Reset laboratory data safely when required.

### DON'T

- Do not test public APIs or third-party systems without permission.
- Do not use real users' credentials or personal data.
- Do not attempt to access resources outside your authorised scope.
- Do not bypass the target restrictions.
- Do not increase request limits to perform uncontrolled testing.
- Do not modify or delete production data.
- Do not publish authentication tokens, personal information or raw sensitive responses.
- Do not treat HTTP 200 alone as proof of a vulnerability.
- Do not present suspected or inconclusive results as confirmed findings.

## 10 — Limitations

Current limitations include:

- Only GET requests are supported.
- Write-based authorization vulnerabilities are outside the current scope.
- Identity, ownership and sensitive-field hints in endpoint configuration remain provisional until verified against actual target responses.
- The differential matrix uses one pair of test identities.
- The analyzer focuses on JSON response objects.
- Nondeterministic response bodies may complicate baseline comparisons.
- APIShield is intended for authorised laboratory testing, not unrestricted internet scanning.

## 11 — Future Improvements

Potential future development includes:

- OpenAPI specification import.
- Additional identity and role combinations.
- More advanced ownership and response-schema analysis.
- Support for selected write-based authorization checks in safely resettable labs.
- Improved handling of dynamic and nondeterministic API responses.
- More detailed historical comparisons and reporting.
- Optional graphical dashboard.

These are proposed improvements, not features currently claimed as implemented.

## 12 — Disclaimer

APIShield is an educational cybersecurity project developed for MSc coursework and authorised penetration-testing practice.

The developer does not encourage or authorise unauthorised access, data extraction, disruption or testing of systems.

Users are responsible for ensuring that they have appropriate permission and legal authority before using the tool.

**Use responsibly. Test ethically. Document everything.**

---

<p align="center">

**APIShield — Built for learning, designed for controlled testing.**

</p>
