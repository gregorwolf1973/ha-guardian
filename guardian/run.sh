#!/usr/bin/with-contenv bashio

# Use ingress_port from config.yaml as the web server port.
# This way the user can change ingress_port in config.yaml and the
# server will automatically follow — no code change needed.
GUARDIAN_PORT=$(bashio::addon.ingress_port 2>/dev/null || echo "8098")
export GUARDIAN_PORT

bashio::log.info "Starting HA Guardian on port ${GUARDIAN_PORT}..."
exec python3 /guardian.py
