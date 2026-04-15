# Security Dashboard Builder

A simple drag-and-drop web app for building customizable security dashboards quickly.

## What you can do

- Drag and drop dashboard widgets (alerts, incidents, metrics, logs, maps, uptime).
- Reorder widgets by dragging cards in the canvas.
- Configure each widget from the GUI.
- Configure connection settings (SIEM/API/DB/Webhook) from the GUI.
- Import/export full dashboard config as JSON.
- Download a deployment bundle (`.zip`) that includes your config and a ready-to-run `docker-compose.yml`.
- Switch themes (Red/Black default, plus Midnight Blue, Matrix Green, Clean Light).

## Run locally

```bash
cd dashboard_builder
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Then open: http://localhost:8000

## Typical deployment in under 1-2 hours

1. Build dashboard in the UI.
2. Click **Download Deployment Bundle**.
3. Copy extracted folder to your server.
4. Fill `.env` from `.env.example`.
5. Run `docker compose up -d`.

You now have a working baseline that you can integrate into your existing monitoring or SIEM workflows.
