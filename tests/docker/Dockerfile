ARG FROM
FROM ${FROM}

ARG WHL_FILE
COPY ${WHL_FILE} /opt/netbox/dist/
RUN /opt/netbox/venv/bin/pip install /opt/netbox/dist/${WHL_FILE}
