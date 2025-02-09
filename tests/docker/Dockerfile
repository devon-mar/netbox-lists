ARG FROM
FROM ${FROM}

ARG WHL_FILE
COPY ${WHL_FILE} /opt/netbox/dist/
RUN [ -f "/usr/local/bin/uv" ] && /usr/local/bin/uv pip install /opt/netbox/dist/${WHL_FILE} \
    || /opt/netbox/venv/bin/pip install /opt/netbox/dist/${WHL_FILE}
