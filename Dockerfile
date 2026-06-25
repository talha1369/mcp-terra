# mcp-terra Dockerfile — security-hardened, supply-chain-pinned container.
#
# Properties this image gives you that the host process doesn't:
#   * Filesystem isolation — the MCP can only see what's mounted.
#   * Network isolation (with --network=none or --network=bridge).
#   * User-namespace mapping (root inside != root outside, with --userns).
#   * Capabilities dropped — see SUGGESTED RUN below.
#   * Read-only root filesystem option.
#   * Seccomp profile (default-strict mode of Docker).
#
# Supply-chain pinning policy:
#   * Base image is pinned by sha256 digest (immutable). The tag could
#     be reassigned upstream; the digest cannot.
#   * Every Python dep is installed from requirements.lock with
#     --require-hashes — a compromised PyPI mirror cannot substitute a
#     malicious wheel without producing a sha256 collision.
#   * apt packages are version-pinned where the Debian archive holds a
#     stable suite. Bookworm point-releases will require a refresh of
#     these pins; that is the price of reproducibility.
#
# This image is multi-stage: a slim builder layer installs deps; the runtime
# layer copies only the wheel-installed package + a non-root user.

# --- BUILDER ---------------------------------------------------------------
# Base image pinned by digest. To refresh:
#
#     docker pull python:3.12-slim
#     docker inspect --format='{{index .RepoDigests 0}}' python:3.12-slim
#
# Manifest-list digest captured 2026-06-25 from Docker Hub for python:3.12-slim.
# If a CI environment cannot resolve digest-pinned images (rare), the next-best
# fallback is the specific patch tag: python:3.12.5-slim-bookworm.
FROM python:3.12-slim@sha256:6c4dd321d176d61ea848dc8c73a4f7dbae8f70e0ee48bb411ea2f045b599fa8e AS builder

WORKDIR /build
COPY pyproject.toml /build/
COPY requirements.lock /build/
COPY src /build/src

# Install build tooling, build a wheel, then exit. The wheel itself only
# contains mcp_terra source — runtime deps are installed from the lock
# file in the runtime stage with --require-hashes.
RUN pip install --no-cache-dir --upgrade pip==25.3 wheel==0.45.1 build==1.2.2.post1 && \
    python -m build --wheel --outdir /wheels


# --- RUNTIME (distroless-style minimal) -----------------------------------
FROM python:3.12-slim@sha256:6c4dd321d176d61ea848dc8c73a4f7dbae8f70e0ee48bb411ea2f045b599fa8e

# Install ONLY the runtime tools we actually need:
#   * google-cloud-sdk: gsutil for bucket I/O + gcloud for ADC token.
#   * ca-certificates: HTTPS to Terra services.
#
# apt versions are pinned to specific Debian bookworm point-release
# values. The form `pkg=version` requires the version to be present in
# the configured archive — when bookworm rolls a point release these
# pins MUST be bumped (failure is loud: apt errors with "Version X is
# not available"). Pin currency:
#   ca-certificates    20230311+deb12u1  (bookworm)
#   curl               7.88.1-10+deb12u14
#   gnupg              2.2.40-1.1
#   apt-transport-https 2.6.1
# google-cloud-sdk is NOT version-pinned because its archive only ships
# the latest stream; Google rotates point-releases out of the index
# within days. The package is signed by the cloud.google.com gpg key we
# install above, which is the supply-chain anchor for that one dep.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates=20230311+deb12u1 \
        curl=7.88.1-10+deb12u14 \
        gnupg=2.2.40-1.1 \
        apt-transport-https=2.6.1 && \
    echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" \
        > /etc/apt/sources.list.d/google-cloud-sdk.list && \
    curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg \
        | gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg && \
    apt-get update && \
    apt-get install -y --no-install-recommends google-cloud-sdk && \
    apt-get purge -y curl gnupg apt-transport-https && \
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /var/cache/apt /tmp/*

# Create a non-root user. UID 10001 is well above any system UID; safe
# default for --userns-remap.
RUN groupadd --gid 10001 mcp && \
    useradd --create-home --uid 10001 --gid 10001 --shell /usr/sbin/nologin mcp

# Install the locked dependency set BEFORE the wheel — pip will accept the
# already-installed deps when installing the wheel and never reach out to
# PyPI for them. --require-hashes refuses any wheel whose sha256 is not
# in the lock file.
COPY requirements.lock /tmp/requirements.lock
RUN pip install --no-cache-dir --require-hashes -r /tmp/requirements.lock && \
    rm /tmp/requirements.lock

# Install mcp-terra itself from the wheel built in the builder stage.
# --no-deps because deps are already locked-and-installed above.
COPY --from=builder /wheels /tmp/wheels
RUN pip install --no-cache-dir --no-deps /tmp/wheels/mcp_terra-*.whl && \
    rm -rf /tmp/wheels

# Drop to non-root for runtime.
USER mcp
WORKDIR /home/mcp

# MCP servers communicate over stdio by default — no port exposure needed.
# The Dockerfile intentionally does NOT EXPOSE any ports.

# Healthcheck: import the package as the running user. If imports succeed,
# the container is healthy.
HEALTHCHECK --interval=60s --timeout=5s --start-period=10s --retries=2 \
    CMD python -c "import mcp_terra.server" || exit 1

# Entry point. Default to read-only mode. Override env at `docker run` time.
ENV MCP_TERRA_ALLOW_WRITES=0
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["python", "-m", "mcp_terra.server"]

# --- SUGGESTED `docker run` FLAGS FOR HIGH-SECURITY USE -------------------
#
# docker run -i --rm \
#   --read-only \                       # root FS is read-only
#   --tmpfs /tmp:size=64m,mode=1777 \   # writable scratch only
#   --tmpfs /home/mcp/.mcp-terra:size=64m,mode=0700,uid=10001,gid=10001 \
#   --cap-drop=ALL \                    # drop every Linux capability
#   --security-opt no-new-privileges \  # cannot regain dropped caps
#   --pids-limit=200 \                  # bound process count
#   --memory=512m --cpus=1 \            # bound resources
#   --user=10001:10001 \                # explicit non-root
#   -e MCP_TERRA_ALLOW_WRITES=1 \       # opt in to writes
#   -e MCP_TERRA_WORKSPACE=ns/name \    # lock to one workspace
#   -e MCP_TERRA_RUNNER_SECRET=... \    # HMAC secret
#   -v ~/.config/gcloud:/home/mcp/.config/gcloud:ro \  # mount ADC read-only
#   mcp-terra:latest
#
# Network: default Docker bridge gives the container internet (needed for
# Terra APIs). Use `--network=host` if you want to share the host network
# (less isolated). Use `--dns` to lock DNS resolution to a trusted resolver.
