# Legacy Streamlit dashboard (not deployed)

The TransNova SOC console replaced this dashboard: `console/` (FastAPI backend) and `frontend/` (React). The team compose no longer starts it.

It is kept because `services/database/requirements-dev.txt` still installs its requirements for the database team's native runs. It reads only the collector's legacy routes (`/api/events`, `/api/alerts`, ...), which still exist. With read authentication on, it sends the token from `SOC_READ_TOKEN_FILE`.

Every feature it had now has a home in the console:

| Streamlit tab | Console page |
|---|---|
| Overview | Overview |
| Live Events | All events (paginated, filtered on the server) |
| Alerts | Alerts and alert detail (workflow, history, XAI) |
| Attackers | Sources and source profile |
| Database Honeypot | Sensors (db-01 sessions, heartbeat details), All events filtered to the database decoy, MITRE |
| Adaptive Deception | Sensors → Adaptive deception |
