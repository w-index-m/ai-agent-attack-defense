FROM node:22
# CA bundle must be readable by the unprivileged user below (the build context file may be 0600).
COPY --chmod=0644 ca-bundle.crt /usr/local/share/ca-certificates/agent-proxy.crt
ENV NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/agent-proxy.crt
RUN npm config set cafile /usr/local/share/ca-certificates/agent-proxy.crt && \
    npm install -g @openai/codex
# Do not run as root (Trivy AVD-DS-0002 / Semgrep dockerfile.security.missing-user).
# node:22 ships an unprivileged "node" user (uid 1000). The global install above
# stays root-owned and world-readable, so codex runs fine as that user.
# Note: codex's own sandbox (bubblewrap) needs unprivileged user namespaces, which
# a non-root user may not have. The Cairn dispatcher invokes codex with
# --dangerously-bypass-approvals-and-sandbox, so this is not hit there; a bare
# `codex exec` inside this image (default sandbox mode) can fail with "bwrap: No
# permissions to create a new namespace".
RUN mkdir -p /workspace && chown node:node /workspace
WORKDIR /workspace
USER node
CMD ["sleep", "infinity"]
