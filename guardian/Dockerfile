ARG BUILD_FROM
FROM $BUILD_FROM

# Install Python dependencies via apk and pip
RUN apk add --no-cache \
        py3-aiohttp \
        py3-yaml \
        iptables \
        ip6tables && \
    pip3 install --no-cache-dir --break-system-packages \
        aiohttp \
        pyyaml || true

# Copy addon files
COPY guardian.py /guardian.py
COPY www/index.html /www/index.html
COPY run.sh /run.sh
RUN chmod a+x /run.sh

CMD ["/run.sh"]
