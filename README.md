# APIShield

APIShield is a modular Python tool for detecting **Broken Object-Level
Authorization (BOLA / IDOR)** in authenticated APIs through
**differential security testing**. It was built as an MSc Cybersecurity
and Penetration Testing coursework project against a local OWASP crAPI
laboratory, and is designed to run safely inside an isolated lab
environment.

APIShield is deliberately **not** a general-purpose vulnerability
scanner. It does one thing with high confidence: it determines whether
an API endpoint enforces object-level authorization, by comparing how
an endpoint responds to legitimate, cross-account and unauthenticated
requests.

## How It Works

For each configured endpoint, APIShield executes a five-case
differential matrix:

| Case | Requester | Resource | Purpose |
|------|-----------|----------|---------|
| B01  | User A    | User A   | Legitimate baseline |
| B02  | User B    | User B   | Legitimate baseline |
| B03  | User A    | User B   | Cross-account probe |
| B04  | User B    | User A   | Cross-account probe |
| B05  | Anonymous | User B   | Authentication control |

Cross-account responses are compared against the resource owner's own
baseline response. Outcomes are classified as **CONFIRMED**,
**SUSPECTED**, **INCONCLUSIVE** or **NO_ISSUE** against the endpoint's
configured authorization policy. A successful HTTP response alone is
never treated as proof of BOLA - confirmation requires differential
evidence (owner identity fields, identical baseline bodies, or the
requested object returned with ownership/sensitive context).

## Safety Controls

- **Loopback-only targets** - the base URL must be a literal loopback
  IP (`127.0.0.0/8` or `::1`). Hostnames such as `localhost` are
  rejected, eliminating DNS resolution and DNS-rebinding risk.
- **Redirect guard** - redirects are disabled by default; if enabled,
  responses redirected off loopback are discarded.
- **Proxy isolation** - environment proxy variables are ignored
  (`trust_env` disabled).
- **Request budget** - per-scan limit (default 50 requests) with
  graceful exhaustion handling.
- **Response limits** - 10-second timeout; bodies are streamed and
  capped at 1 MB; malformed or interrupted responses are handled
  safely.
- **Read-only** - GET requests only.
- **Redacted evidence** - bearer tokens, credentials, raw response
  bodies, personal data and coordinates are never stored, logged or
  reported. Resource identifiers are kept only as SHA-256 fingerprints.
- **Parameterised SQL** - all SQLite statements are parameterised.

## Project Structure

```
APIShield/
├── main.py                     # CLI entry point
├── config/
│   ├── settings.json           # request limits and runtime paths
│   └── endpoints.json          # endpoint definitions and policies
├── apishield/
│   ├── config.py               # secure environment configuration
│   ├── authentication.py       # test identities (labels + tokens)
│   ├── target_validator.py     # literal-loopback target validation
│   ├── request_handler.py      # constrained HTTP client
│   ├── endpoint_loader.py      # endpoint configuration loader
│   ├── bola_engine.py          # B01-B05 differential engine
│   ├── response_analyzer.py    # response observation and comparison
│   ├── classifier.py           # evidence-driven classification
│   ├── evidence.py             # redacted evidence records
│   ├── database.py             # SQLite persistence
│   └── reporting.py            # JSON and HTML report generation
├── templates/report.html       # HTML report template (Jinja2)
├── tests/                      # pytest unit tests (mocked HTTP)
├── evidence/                   # SQLite database (gitignored)
└── reports/                    # generated reports (gitignored)
```

## Installation

Requires Python 3.10+ (developed and tested on 3.13).

```bash
python3 -m venv .venv
source .venv/bin/activate        # Linux/macOS
pip install -r requirements.txt
```

For development (tests):

```bash
pip install -r requirements-dev.txt
```

## Configuration

Copy `.env.example` to `.env` and fill in the values for your lab:

```
APISHIELD_BASE_URL=http://127.0.0.1:8888
APISHIELD_USER_A_TOKEN=<token for user A>
APISHIELD_USER_B_TOKEN=<token for user B>
APISHIELD_USER_A_VEHICLE_ID=<resource id owned by user A>
APISHIELD_USER_B_VEHICLE_ID=<resource id owned by user B>
```

The base URL must be a literal loopback IP address. Endpoints under
test are defined in `config/endpoints.json`, including each endpoint's
expected authorization policy; adding an endpoint requires no code
changes. Never commit the real `.env` file.

## Usage

```bash
python3 main.py check                 # validate target and configuration
python3 main.py validate-config       # validate environment variables
python3 main.py list-endpoints        # show configured endpoints
python3 main.py scan                  # run the B01-B05 matrix
python3 main.py scan --endpoint vehicle_location
python3 main.py results               # list recorded runs
python3 main.py report --format json  # export latest run as JSON
python3 main.py report --format html  # export latest run as HTML
python3 main.py report --run <run-id> --format html
```

Scans persist redacted evidence to a local SQLite database and reports
are generated from that database. Report locations default to the
`reports/` directory.

## Testing

All unit tests run against mocked HTTP responses and synthetic data -
no live target is contacted:

```bash
python3 -m pytest tests -q
```

Integration testing against a live crAPI laboratory must be performed
inside the isolated lab environment (see `docs/` for the lab setup and
integration test guide). Unit test results never substitute for
integration test results.

## Limitations

- Only GET requests are supported; write-based authorization flaws are
  out of scope.
- Identity, ownership and sensitive field names in
  `config/endpoints.json` are provisional until verified against real
  target responses.
- A single pair of test users is used for the differential matrix.
- The tool is intended for authorized lab testing only.

## License

None declared yet - the project owner will choose a licence before
publication.
