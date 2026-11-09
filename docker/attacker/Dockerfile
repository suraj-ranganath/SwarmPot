# SwarmPot attacker image: ARTEMIS supervisor + its Codex subagent binary.
# Build context is a pinned ARTEMIS checkout (see scripts/bootstrap_upstream.sh).
#
# The objective is to run ARTEMIS *unmodified*; the image only supplies a
# Linux build of its Codex engine plus a Python runtime for the supervisor.

FROM rust:1.89-bookworm AS codex-build

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential pkg-config libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /artemis
COPY codex-rs ./codex-rs
# Release profile is LTO + codegen-units=1; this is the slow step and is
# deliberately isolated in its own stage so source edits above do not rebuild it.
RUN cargo build --release --manifest-path codex-rs/Cargo.toml \
    && strip codex-rs/target/release/codex

FROM python:3.11-slim-bookworm AS runtime

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl jq openssh-client iproute2 iptables \
        dnsutils netcat-openbsd procps tini \
    && rm -rf /var/lib/apt/lists/*

# ARTEMIS Python supervisor (unmodified sources).
WORKDIR /opt/artemis
COPY pyproject.toml ./
COPY supervisor ./supervisor
RUN pip install pyyaml psutil aiofiles pytz python-dotenv openai tiktoken pydantic \
    && pip install --no-deps -e .

# ARTEMIS's context manager loads a tiktoken BPE file on first use. The attacker
# container has no Internet route (only an allowlisted model-provider proxy), so
# bake the encoding cache in at build time.
RUN python -c "import tiktoken; [tiktoken.get_encoding(name) for name in ('o200k_base', 'cl100k_base')]"

COPY --from=codex-build /artemis/codex-rs/target/release/codex /usr/local/bin/codex

# Codex/OpenRouter provider config. No secret is baked in: the key arrives
# through OPENROUTER_API_KEY at run time.
RUN mkdir -p /root/.codex && cat > /root/.codex/config.toml <<'EOF'
model_provider = "openrouter"

[model_providers.openrouter]
name = "OpenRouter"
base_url = "https://openrouter.ai/api/v1"
env_key = "OPENROUTER_API_KEY"
EOF

# SwarmPot host-side wrapper is bind-mounted at /opt/swarmpot at run time.
ENV PYTHONPATH=/opt/swarmpot \
    SWARMPOT_IN_CONTAINER=1

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python", "-m", "swarmpot.attacker.run_episode"]
