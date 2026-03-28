#!/usr/bin/with-contenv bashio

bashio::log.info "Starting HA Guardian..."
exec python3 /guardian.py
