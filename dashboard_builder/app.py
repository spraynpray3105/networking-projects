from __future__ import annotations

import io
import json
import textwrap
import zipfile
from datetime import datetime, timezone

from flask import Flask, jsonify, render_template, request, send_file

app = Flask(__name__)


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/export_bundle")
def export_bundle():
    payload = request.get_json(silent=True) or {}
    config = payload.get("config", {})

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    config_json = json.dumps(config, indent=2)

    deployment_readme = textwrap.dedent(
        f"""
        # Security Dashboard Deployment Bundle

        Generated: {generated}

        ## Quick start (10-15 minutes)

        1. Copy this folder to your server.
        2. Add your keys and endpoints to `.env` using `.env.example`.
        3. Place your dashboard config in `dashboard-config.json`.
        4. Run:

           ```bash
           docker compose up -d
           ```

        5. Open `http://<server-ip>:8000`.

        ## Notes

        - This bundle is intentionally minimal and easy to customize.
        - Mount `dashboard-config.json` into your own app/service if you want deeper integrations.
        - You can re-export any time from the dashboard editor.
        """
    ).strip()

    compose_yaml = textwrap.dedent(
        """
        services:
          security-dashboard:
            image: python:3.12-slim
            container_name: security-dashboard
            working_dir: /app
            command: bash -lc "pip install -r requirements.txt && python app.py"
            volumes:
              - ./:/app
            ports:
              - "8000:8000"
            env_file:
              - .env
            restart: unless-stopped
        """
    ).strip()

    env_example = textwrap.dedent(
        """
        # Example connector secrets
        API_TOKEN=replace_me
        SIEM_ENDPOINT=https://siem.example.local
        SIEM_USERNAME=admin
        SIEM_PASSWORD=change_me
        """
    ).strip()

    requirements = "flask==3.1.0\n"

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("README.md", deployment_readme)
        zf.writestr("dashboard-config.json", config_json)
        zf.writestr("docker-compose.yml", compose_yaml)
        zf.writestr(".env.example", env_example)
        zf.writestr("requirements.txt", requirements)

    zip_buffer.seek(0)
    return send_file(
        zip_buffer,
        mimetype="application/zip",
        as_attachment=True,
        download_name="security-dashboard-bundle.zip",
    )


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
