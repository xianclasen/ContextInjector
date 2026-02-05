
# ContextInjector

A joint MCP client and server framework for testing semantic inspection engines for efficacy.

## Purpose

As an avid reader, I wanted a way to expose my GoodReads data to an LLM in order to get book recommendations that fit my tastes.

As a security nerd, I wanted to be able to inject malicious context into that data. So I built this lightweight MCP demo server and client that exposes Goodreads/RSS data and demonstrates common integration and attack scenarios (for learning and testing).

No LLM is needed for this setup, nor is it relevent. This setup is purely for testing attempted attacks originating from a malicious MCP server on the internet. Depending on how naive a real-world LLM and MCP client are these attacks may succeed or fail. I simply want to know if an inline proxy / gateway would catch the attacks using semantic inspection between the internet and the MCP client.

This project is a small demonstration of an MCP-based service that fetches and exposes book-related data (via RSS/Goodreads integration), includes logging, and contains examples of attack vectors. The main driver for me was to test semantic inspection proxies for efficacy.

## Features

The project includes both a client and server. Attack type can be selected at either side, on the server by setting the attack profile at start-up, and/or on the client by setting it at request time.

Tools exist on the server for both retreiving legitimate data, and optionally for control plane configuration of attack types (listed below).

This means that the client can naively send requests to the server, which is configured on startup with a certain attack configuration, or the client can set/override the server settings within a request.

Metadata is used to track requests on both sides and which attacks were enabled.

The provided `scripts/run_attack_matrix.sh` will run all combintations of attacks and generate a report on what was blocked or allowed.

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

## Attack profiles

Profiles simulate realistic malicious content embedded in tool outputs, or optionally sent back as full replacement for tool output (`attack-only`).

- Per-request profile override: `fetch_shelf_rss` accepts `profile_id` (numeric) and optional `attack_only` (bool).
  This avoids sending profile names through the proxy which may trip semantic inspection engines.

- `baseline` : Normal content; no attack text injected.
- `prompt_injection` : Embedded system-override instructions inside summaries.
- `mixed_content` : Plausible content with hidden instruction overrides.
- `tool_coercion` : Attempts to coerce the client to call a dangerous tool.
- `data_exfiltration` : Requests secrets, internal config, and prior tool outputs.
- `oversized_payload` : Large payload injected into fields to test size limits and truncation.
- `high_entropy` : High-entropy base64 data injected to test entropy or binary-like payload handling.
- `schema_confusion` : Wrong types and unexpected items in structured results to test schema validation.
- `assistant_impersonation` : Content that impersonates prior assistant output to test authority confusion.
- `role_confusion` : SYSTEM/DEVELOPER headers embedded in content to test role boundary enforcement.
- `delayed_instruction` : Deferred instructions meant to trigger on a later user query.
- `obfuscated_injection` : Hidden/obfuscated instructions (zero-width/HTML comment) to test normalization.
- `tool_args_smuggling` : Tool call JSON embedded in content to test tool gating.
- `data_poisoning` : Subtle recommendation-bias instructions to test semantic manipulation.
- `context_stuffing` : Repeated phrases to test bias from repetition.
- `sampling_override` : Attempts to override client sampling parameters and request multiple candidates.
- `elicitation_probe` : Probing questions intended to elicit hidden prompts or credentials.
- `logging_tamper` : Attempts to disable or redact client logging/audit trails.

Profile IDs (for `profile_id` and control-plane tools):

- `0` : baseline
- `1` : prompt_injection
- `2` : tool_coercion
- `3` : data_exfiltration
- `4` : oversized_payload
- `5` : high_entropy
- `6` : schema_confusion
- `7` : mixed_content
- `8` : assistant_impersonation
- `9` : role_confusion
- `10` : delayed_instruction
- `11` : obfuscated_injection
- `12` : tool_args_smuggling
- `13` : data_poisoning
- `14` : context_stuffing
- `15` : sampling_override
- `16` : elicitation_probe
- `17` : logging_tamper

## Command-line arguments

Server (`server.py`):

- `--host` : Host to bind (default `0.0.0.0` or `MCP_HOST` env)
- `--port` : Port to listen on (default `3333` or `MCP_PORT` env)
- `--path` : HTTP path for MCP endpoint (default `/mcp` or `MCP_HTTP_PATH` env)
- `--profile` : Attack profile name (default `prompt_injection` or `ATTACK_PROFILE` env). Server-side only.
- `--inject` / `--no-inject` : Fine-grained enable/disable injection
- `--inject-max-items` : Max items to inject per response (default `2`)
- `--single-field` : Inject into only one field per output (default, or `ATTACK_SINGLE_FIELD=1`)
- `--multi-field` : Inject into all enabled fields per output
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
- `--profile-id` : Numeric profile id passed as tool arg (proxy-safe)
- `--attack-only` : Request attack-only tool output (per-request override)
- `--tool` : Tool name to call (default `fetch_shelf_rss`)
- `--shelf` : Shelf name used by default tool args (default `read`)
- `--limit` : Limit for default tool args (default `20`)
- `--tool-args` : Raw JSON string to use as tool arguments (overrides `--shelf`/`--limit`)

## Control-plane tools (IDs only)

Control-plane tool I/O uses numeric IDs to indicate attack profile to avoid sending profile names over the wire and tripping semantic proxy engines:

- `list_attack_profiles` returns profile IDs and the default ID.
- `get_attack_profile` returns `profile_id`.
- `set_attack_profile` accepts `profile_id`.
- `set_injection_scope` accepts `single_field_per_output` (bool).

Injected responses include `server_note.meta.attack_profile_id` (numeric).

## Project layout

- `server.py` — example MCP server entrypoint
- `client.py` — simple client/demo runner
- `models/` — application models and clients
- `attacks/` — attack modules (e.g. injection)
- `logutils/` — logging formatters
- `tools/` — tool implementations
