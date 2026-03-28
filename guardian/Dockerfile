ARG BUILD_FROM
FROM $BUILD_FROM

ARG BUILD_ARCH
ARG BUILD_DATE
ARG BUILD_DESCRIPTION
ARG BUILD_NAME
ARG BUILD_REF
ARG BUILD_REPOSITORY
ARG BUILD_VERSION

LABEL \
    io.hass.name="${BUILD_NAME}" \
    io.hass.description="${BUILD_DESCRIPTION}" \
    io.hass.arch="${BUILD_ARCH}" \
    io.hass.type="addon" \
    io.hass.version="${BUILD_VERSION}"

# Install Python dependencies
RUN pip3 install --no-cache-dir \
    aiohttp==3.9.5 \
    pyyaml==6.0.1

# Copy addon files
COPY guardian.py /guardian.py
COPY www/index.html /www/index.html
COPY run.sh /run.sh
RUN chmod a+x /run.sh

CMD ["/run.sh"]
