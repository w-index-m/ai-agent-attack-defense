FROM node:22
COPY ca-bundle.crt /usr/local/share/ca-certificates/agent-proxy.crt
ENV NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/agent-proxy.crt
RUN npm config set cafile /usr/local/share/ca-certificates/agent-proxy.crt && \
    npm install -g @openai/codex
WORKDIR /workspace
CMD ["sleep", "infinity"]
