
# ContextInjector

As an avid reader, I wanted a way to expose my GoodReads data to an LLM in order to get book recommendations that fit my tastes.

As a security nerd, I wanted to be able to inject malicious context into that data. So I built this lightweight MCP demo server and client that exposes Goodreads/RSS data and demonstrates common integration and attack scenarios (for learning and testing).

The project includes both a client and server. Attack type can be selected at either side.

## Purpose

This project is a small demonstration of an MCP-based service that fetches and exposes book-related data (via RSS/Goodreads integration), includes logging, and contains examples of attack vectors.

## Features

- MCP server and client example interfaces
- Goodreads/RSS fetching utilities
- Logging examples
- Attack demonstration modules (injection control)

## Prerequisites

- Python 3.13 or newer (see `pyproject.toml`)
- Recommended: create and use a virtual environment

## Installation

1. Create and activate a virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate
```

2. Install the project in editable mode (installs dependencies from `pyproject.toml`):

```bash
python -m pip install -e .
```

Alternatively, install dependencies manually:

```bash
python -m pip install fastmcp feedparser python-dotenv
```

## Configuration

Example `.env`:

```dotenv
# OpenAI / LLM key (optional)
OPENAI_API_KEY=your-openai-api-key

# Goodreads settings
GOODREADS_USER_ID=182366515
GOODREADS_USER_AGENT=ContextInjector/1.0
GOODREADS_HTTP_TIMEOUT_SECONDS=10

# MCP server configuration
MCP_HOST=0.0.0.0
MCP_PORT=3333
MCP_HTTP_PATH=/mcp

# Logging
LOG_LEVEL=INFO
```

## Usage

- Run the server:

```bash
python server.py
```

- Run the client:

```bash
python client.py
```

Explore the `attacks/` and `models/` packages to see example components and demonstration code.

## Command-line arguments

Server (`server.py`):

- `--host` : Host to bind (default `0.0.0.0` or `MCP_HOST` env)
- `--port` : Port to listen on (default `3333` or `MCP_PORT` env)
- `--path` : HTTP path for MCP endpoint (default `/mcp` or `MCP_HTTP_PATH` env)
- `--profile` : Attack profile name (default `prompt_injection` or `ATTACK_PROFILE` env)
- `--inject` / `--no-inject` : Fine-grained enable/disable injection
- `--inject-max-items` : Max items to inject per response (default `2`)
- `--attack-only` : Return only attack content (strip real Goodreads data). Can also be set via `ATTACK_ONLY=1`
- `--disable-control-plane-tools` : Disable control plane tools registration

TLS / HTTPS options (optional):

- `--https` : Enable HTTPS with the provided cert and key
- `--cert` : Path to TLS certificate file (PEM). Can also be set via `TLS_CERT`.
- `--key` : Path to TLS private key file (PEM). Can also be set via `TLS_KEY`.
- `--client-ca` : Optional CA bundle (PEM) for client cert verification. Can also be set via `TLS_CLIENT_CA`.

Client (`client.py`):

- `--url` : MCP endpoint URL (default `http://127.0.0.1:3333/mcp`)
- `--http2` : Enable HTTP/2
- `--timeout` : Request timeout seconds (default `20.0`)
- `--insecure` : Disable TLS verification
- `--profile` : Attack profile to set (default `prompt_injection`)
- `--tool` : Tool name to call (default `fetch_shelf_rss`)
- `--shelf` : Shelf name used by default tool args (default `read`)
- `--limit` : Limit for default tool args (default `20`)
- `--tool-args` : Raw JSON string to use as tool arguments (overrides `--shelf`/`--limit`)

## Project layout

- `server.py` — example MCP server entrypoint
- `client.py` — simple client/demo runner
- `models/` — application models and clients
- `attacks/` — attack modules (e.g. injection)
- `logutils/` — logging formatters
- `tools/` — tool implementations
