# Momos

Momos is a self-hosted, AI-assisted penetration testing platform. It coordinates LLM-driven agents (orchestrator, scouting, pentesting and reporting roles) that enumerate services on a target, test candidate attack vectors using real tools inside disposable Kali Linux containers, and turn confirmed findings into structured vulnerability reports with CVSS v4 scoring.

## Legal notice

Momos is intended for authorized security testing only. Only run it against systems, networks, or applications that you own or for which you have explicit, documented permission to test. Using this tool against any target without proper authorization may violate local, national, or international law.

The authors and contributors of this project accept no liability for misuse of this software. You are solely responsible for ensuring you have the legal right to test any target before use.

## Usage

Momos runs as a set of Docker containers: a dashboard, a backend API, a PostgreSQL database (with pgvector), and an Ollama instance for local LLM inference.

Requirements:

- Docker and Docker Compose
- (Optional, recommended) an NVIDIA GPU with the NVIDIA Container Toolkit installed, for faster local model inference via Ollama

Start the stack from the project root:

```bash
sudo docker compose up
```

Once the containers are up, open the dashboard at `http://localhost:8080`. The dashboard talks to the backend API and websocket endpoints through its own nginx proxy, so no other ports need to be exposed for normal use.

If you have an NVIDIA GPU available, uncomment the GPU reservation block for the `ollama` service in `docker-compose.yml` before starting the stack to enable hardware acceleration.

Database credentials and the Ollama connection are configured via `backend/.env`; sensible defaults are provided for a local, single-host setup.

### Development

For local development, use the dev compose override instead. It adds hot-reloading for both the dashboard and the backend, and exposes the backend API and database ports directly:

```bash
sudo docker compose -f docker-compose.yml -f docker-compose.dev.yml up --watch
```

- Dashboard (Vite dev server): `http://localhost:5173`
- Backend API: `http://localhost:8000`
- PostgreSQL: `localhost:5432`

The `backend` directory uses [uv](https://github.com/astral-sh/uv) for dependency management and the `dashboard` directory uses Yarn.
