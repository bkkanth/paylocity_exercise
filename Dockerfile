# ─────────────────────────────────────────────────
# Base image: python:3.11-slim
#
# WHY slim and not the full image?
# The full python:3.11 image ships with compilers,
# build tools, and documentation (~900 MB).
# slim strips everything not needed to run a Python
# application (~120 MB). Smaller images:
#   - Pull and deploy faster in CI/CD pipelines
#   - Have a smaller attack surface (fewer binaries
#     an attacker can exploit post-compromise)
#   - Cost less to store in a container registry
#
# WHY 3.11 and not 3.12?
# 3.11 is the current LTS-adjacent stable release
# with the best library compatibility at time of
# writing. Pin the minor version so a base image
# update never silently changes your runtime.
# ─────────────────────────────────────────────────
FROM python:3.11-slim

# ─────────────────────────────────────────────────
# PYTHONDONTWRITEBYTECODE=1
#   Prevents Python from writing .pyc bytecode files
#   to disk. In a container there is no warm restart
#   that would benefit from cached bytecode, and the
#   files just waste space in the image layer.
#
# PYTHONUNBUFFERED=1
#   Forces stdout and stderr to flush immediately
#   rather than buffering in 4 KB chunks.
#   Without this, structured log lines emitted by
#   server.py's StructuredJSONFormatter may never
#   appear in `docker logs` output — they sit in
#   the buffer and are lost if the container stops
#   unexpectedly.
# ─────────────────────────────────────────────────
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# ─────────────────────────────────────────────────
# Working directory inside the container.
# /app is the conventional location for application
# code. Using a non-root path (not /) avoids
# accidentally overwriting OS files.
# ─────────────────────────────────────────────────
WORKDIR /app

# ─────────────────────────────────────────────────
# Copy requirements BEFORE source files.
#
# Docker builds images layer by layer and caches
# each layer. If requirements.txt hasn't changed,
# Docker reuses the cached pip install layer and
# skips reinstalling ~5 packages.
#
# If you copy all source files first and then pip
# install, ANY change to server.py or cli.py
# invalidates the pip layer and forces a full
# reinstall on every build — even if no dependency
# changed. This is the single biggest build-time
# win for Python containers.
# ─────────────────────────────────────────────────
COPY requirements.txt .

# ─────────────────────────────────────────────────
# Install dependencies.
#
# --no-cache-dir
#   pip caches downloaded wheels in ~/.cache/pip.
#   In a container that cache is never reused
#   (each build starts fresh), so it just wastes
#   image layer space. Disabling it shrinks the
#   final image by the size of all downloaded wheels.
# ─────────────────────────────────────────────────
RUN pip install --no-cache-dir -r requirements.txt

# ─────────────────────────────────────────────────
# Copy only the two source files needed to run.
#
# WHY not COPY . . (copy everything)?
# Copying the whole directory would include:
#   - .venv/ (~60 MB of packages already installed
#     above — just dead weight in the image)
#   - .env (secrets should never be baked into an image)
#   - __pycache__/ (bytecode for the wrong Python version)
#   - README, Makefile, .gitignore (irrelevant at runtime)
#
# Explicit COPY of only what's needed keeps the
# image small and avoids accidental secret leakage.
# A .dockerignore file is an alternative, but
# explicit COPY makes the intent self-documenting.
# ─────────────────────────────────────────────────
COPY server.py .
COPY cli.py .

# ─────────────────────────────────────────────────
# Non-root user (uid 1001, named appuser).
#
# WHY not run as root?
# By default Docker containers run as root (uid 0).
# If an attacker exploits a vulnerability in the
# application and achieves code execution inside the
# container, root gives them:
#   - Write access to the entire filesystem
#   - The ability to install tools (curl, netcat)
#   - A much easier pivot to container escape
#
# A non-root user with no shell and no home directory
# limits blast radius: the attacker inherits only the
# permissions of a locked-down service account.
#
# uid 1001 is chosen because uid 1000 is often
# already taken by the base image's default user.
# ─────────────────────────────────────────────────
RUN adduser --disabled-password --no-create-home --uid 1001 appuser
USER appuser

# ─────────────────────────────────────────────────
# Expose port 8000.
#
# EXPOSE is documentation — it does not publish the
# port. The actual port mapping happens at `docker run
# -p 8000:8000`. Without EXPOSE, tooling like
# docker-compose and container orchestrators do not
# know which port the service listens on.
# ─────────────────────────────────────────────────
EXPOSE 8000

# ─────────────────────────────────────────────────
# Health check.
#
# WHY add HEALTHCHECK?
# Docker (and Kubernetes via its own probe system)
# use health checks to decide whether a container
# is ready to receive traffic. Without one, a
# container that started but whose application
# crashed is still considered "running" by the
# scheduler and will receive traffic — returning
# errors to every caller.
#
# We target the /health endpoint in server.py which
# returns {"status": "healthy", "record_count": N}.
# curl exits with code 0 on HTTP 2xx, non-zero
# otherwise — exactly what Docker's HEALTHCHECK needs.
#
# --interval=30s  Check every 30 seconds
# --timeout=5s    Fail the check if no response in 5s
# --retries=3     Mark unhealthy after 3 consecutive failures
# ─────────────────────────────────────────────────
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

# ─────────────────────────────────────────────────
# Entry point.
#
# WHY not CMD ["python", "server.py"]?
# server.py reads API_HOST and API_PORT from
# environment variables (os.getenv). Running via
# `python server.py` invokes the __main__ block
# which calls uvicorn.run() with those values.
#
# This means the host and port are fully configurable
# at `docker run` time without rebuilding the image:
#   docker run -e API_PORT=9000 -p 9000:9000 vuln-tracker
# ─────────────────────────────────────────────────
CMD ["python", "server.py"]
