# Environment for an offline security audit of this repository (OSS Scanner).
# The build runs with network access; everything after it runs without.
# This repository's scripts use only the Python standard library, so there is
# nothing to install. The build step runs the repo's own consistency check as a
# sanity test that the checkout is complete.
FROM python:3.12-slim

# Do not run as root (Trivy AVD-DS-0002 / Semgrep dockerfile.security.missing-user).
# The audit only reads /src, so an unprivileged user is enough.
RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin scanner

WORKDIR /src
COPY --chown=scanner:scanner . /src

RUN python3 tools/check_consistency.py

USER scanner
