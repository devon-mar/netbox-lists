ARG FROM
FROM ${FROM}

ARG WHL_FILE
COPY ${WHL_FILE} /opt/netbox/dist/
RUN /usr/local/bin/uv pip install /opt/netbox/dist/${WHL_FILE}
