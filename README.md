# TransNova SOC

**A modular Security Operations Center for collecting security telemetry, detecting suspicious activity, and investigating evidence-backed alerts.**

TransNova SOC is a defensive security monitoring platform designed to collect, process, monitor and analyze security events in real time. It integrates multiple honeypots, security monitoring components, and AI-powered analysis to help identify potential threats and provide actionable security insights.

The platform features centralized event ingestion, threat monitoring, an interactive security dashboard, automated processing, and AI-assisted security explanations. Its modular architecture supports scalability, extensibility, and easier integration of additional security tools and services.

> **Note:** This project is intended for controlled and authorized security testing and demonstrations. Keep honeypots isolated from production systems and untrusted networks.

---

## 🚀 Key Features

- **Multi-source Telemetry:** Collects security events from Web, MariaDB, and SSH honeypots.
- **Centralized Event Collection:** Validates, normalizes, deduplicates, and stores incoming events.
- **Threat Detection:** Evaluates suspicious activities using configurable detection rules.
- **Alert Management:** Enables analysts to investigate alerts, review evidence, and update their status.
- **Interactive SOC Dashboard:** Provides centralized visibility into security events, alerts, and monitoring activities.
- **Source Investigation:** Displays activity timelines and observations grouped by source address.
- **Sensor Monitoring:** Tracks sensor activity and ingestion health.
- **MITRE ATT&CK Integration:** Maps supported detections to relevant attack techniques.
- **OWASP Mapping:** Organizes observed web security activities using OWASP references.
- **AI-Assisted Analysis:** Uses the Anthropic API for optional AI-powered security explanations.
- **Docker-Based Deployment:** Supports containerized deployment using Docker Compose.

---

## 🏗️ System Architecture

```text
                  HONEYPOT ENVIRONMENT
        ┌─────────────────────────────────────┐
        │                                     │
        │    Web        MariaDB       SSH     │
        │  Honeypot    Honeypot    Honeypot   │
        │     │           │           │       │
        │     ▼           ▼           ▼       │
        │   Web        Database     Cowrie    │
        │  Events      Sensor       Sensor    │
        └─────┬───────────┬───────────┬───────┘
              │           │           │
              └───────────┴───────────┘
                          │
                          ▼
                ┌─────────────────────┐
                │   SOC Collector     │
                │                     │
                │  Event Ingestion    │
                │  Validation         │
                │  Event Storage      │
                │  Detection Rules    │
                │  Alert Generation   │
                └──────────┬──────────┘
                           │
                           ▼
                ┌─────────────────────┐
                │  Console Backend    │
                │      FastAPI        │
                └──────────┬──────────┘
                           │
                           ▼
                ┌─────────────────────┐
                │    Web Console      │
                │ React + TypeScript  │
                └─────────────────────┘
```

### Event Processing Workflow

1. Activity occurs against a honeypot in the isolated lab.
2. The corresponding sensor captures and structures the activity.
3. Events are forwarded to the centralized SOC collector.
4. The collector validates and stores incoming events.
5. Detection rules evaluate the events and identify suspicious patterns.
6. Qualifying detections generate alerts.
7. Analysts investigate the alerts through the SOC dashboard.
8. AI-assisted explanations can provide additional context for security investigations.

**An event is not automatically an alert.** TransNova SOC separates event collection, detection, and alert management to provide better visibility into security incidents.

---

## 🛠️ Technology Stack

| Component | Technologies |
|---|---|
| Frontend | React, TypeScript, Vite |
| Backend | Python, FastAPI, Uvicorn |
| Database | SQLite, MariaDB |
| Honeypots | Custom Web Decoy, MariaDB Decoy, Cowrie |
| AI Integration | Anthropic API |
| Deployment | Docker, Docker Compose |
| Testing | Pytest, Vitest, Testing Library |
| Development Tools | Git, Node.js, npm |

---

## 📂 Project Structure

```text
TransNova-SOC/
│
├── collector/              # Centralized event ingestion and detection
│
├── console/                # SOC console backend and authentication
│
├── dashboard/              # Streamlit dashboard
│
├── frontend/               # React + TypeScript frontend
│
├── services/
│   ├── web/                # Web honeypot
│   ├── database/            # MariaDB honeypot and sensor
│   ├── ssh/                 # Cowrie SSH honeypot and sensor
│   ├── mainsite/             # Main-site application
│   └── anonintel/            # Supporting intelligence service
│
├── scripts/                 # Setup and utility scripts
│
├── docs/                    # Technical documentation
│
├── docker-compose.yml       # Main Docker configuration
├── .env.example             # Example environment variables
├── .gitignore
└── README.md
```

---

## ⚙️ Installation and Setup

### Prerequisites

Make sure you have installed:

- [Docker Desktop](https://www.docker.com/products/docker-desktop/)
- [Git](https://git-scm.com/)
- [Python 3](https://www.python.org/)
- [Node.js](https://nodejs.org/)

### 1. Clone the Repository

```bash
git clone https://github.com/joelljoy/TRANSNOVA-SOC.git
```

Navigate into the project:

```bash
cd TRANSNOVA-SOC
```

### 2. Configure Environment Variables

Create a local environment file.

**Windows PowerShell:**

```powershell
Copy-Item .env.example .env
```

**Linux / macOS:**

```bash
cp .env.example .env
```

Update the environment variables with your local configuration.

### 3. Generate Application Secrets

Run the following command from the project root:

```bash
python scripts/make_secrets.py
```

This generates the local secrets required by the Docker deployment, including collector tokens and console account credentials.

Keep generated credentials private.

### 4. Build and Start the Application

Run:

```bash
docker compose up --build -d
```

Check the running containers:

```bash
docker compose ps
```

### 5. Access the SOC Dashboard

Open your browser:

```text
http://127.0.0.1:8501
```

Sign in using the initial credentials generated during setup.

### 6. Stop the Application

```bash
docker compose down
```

To remove containers and their persisted volumes:

```bash
docker compose down -v
```

**Warning:** The second command deletes persisted lab data.

---

## 🧪 Generating Test Activity

The project includes optional attacker containers for generating controlled test traffic.

Start the web and database attacker containers:

```bash
docker compose --profile attacker up -d db-attacker web-attacker
```

Example web honeypot request:

```bash
docker compose exec web-attacker curl -sk -X POST \
  -d "username=test-user&password=incorrect" \
  https://web-decoy:8080/login
```

Run SSH demonstration scenarios:

```bash
docker compose --profile attacker run --rm ssh-attacker full
```

These scenarios help generate sample security events for testing the ingestion pipeline and alert detection functionality.

Only run these tests within the authorized lab environment.

---

## 📊 Dashboard Modules

| Module | Description |
|---|---|
| Overview | Displays security activity and SOC statistics. |
| All Events | Provides searchable and filterable security events. |
| Alerts | Supports alert investigation and management. |
| Sources | Displays activity timelines grouped by source. |
| Sensors | Monitors sensor activity and ingestion health. |
| MITRE ATT&CK | Displays supported attack technique mappings. |
| OWASP | Organizes observed web security activities. |
| Response | Provides configured response and block-management functionality. |
| Settings | Provides account and system configuration information. |

---

## 🔌 API Overview

The centralized collector exposes REST APIs under:

```text
/api/v2/
```

Some of the available endpoints include:

| Endpoint | Description |
|---|---|
| `GET /api/v2/summary` | Retrieves SOC summary information. |
| `GET /api/v2/events` | Retrieves security events. |
| `GET /api/v2/events/{id}` | Retrieves individual event details. |
| `GET /api/v2/alerts` | Retrieves security alerts. |
| `GET /api/v2/alerts/{id}` | Retrieves individual alert details. |
| `GET /api/v2/sources` | Retrieves observed sources. |
| `GET /api/v2/sensors` | Retrieves sensor information. |
| `GET /api/v2/mitre` | Retrieves MITRE ATT&CK mappings. |
| `GET /api/v2/owasp` | Retrieves OWASP mapping information. |

Authentication is required for protected endpoints. Refer to the implementation for the applicable authentication headers and request formats.

---

## 💻 Development

### Frontend Development

Navigate to the frontend directory:

```bash
cd frontend
```

Install dependencies:

```bash
npm install
```

Start the development server:

```bash
npm run dev
```

### Frontend Testing

```bash
npm run lint
npm run typecheck
npm test
npm run build
```

### Backend Testing

Run the collector and console tests:

```bash
python -m pytest collector/tests console/tests
```

Run selected service tests:

```bash
python -m pytest services/database/tests/test_collector.py services/ssh/tests/integration
```

---

## 🔐 Security and Configuration

TransNova SOC uses environment variables and Docker secrets to manage sensitive configuration.

Important configuration variables include:

| Variable | Purpose |
|---|---|
| `MARIADB_ROOT_PASSWORD` | MariaDB root password. |
| `CONTROLLER_DB_PASSWORD` | Database sensor controller password. |
| `DECOY_DB_PASSWORD` | Decoy database account password. |
| `ANTHROPIC_API_KEY` | Optional Anthropic API integration. |
| `SOC_AI_MODEL` | AI model configuration. |
| `SOC_COOKIE_SECURE` | Enables secure session cookies over HTTPS. |

### Security Recommendations

- Never commit API keys, passwords, tokens, or `.env` files.
- Keep generated secrets outside version control.
- Use isolated Docker networks for honeypot services.
- Do not expose internal management interfaces publicly without proper security controls.
- Rotate credentials immediately if they are accidentally exposed.
- Keep AI API keys on the backend.
- Treat collected honeypot data as untrusted input.

---

## ⚠️ Known Limitations

- Console sessions are stored in memory and are cleared when the console restarts.
- Sensor health information depends on the telemetry reported by individual sensors.
- MITRE ATT&CK and OWASP mappings cover the techniques implemented in the project, not the complete frameworks.
- AI explanations are supplementary and should not replace evidence-based security analysis.
- Some ingestion paths have different authentication and network configurations. Review these before changing deployment exposure.

---

**Built for security monitoring, threat visibility, and defensive cybersecurity research.**

**TransNova SOC**
