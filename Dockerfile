FROM python:3.12-slim

ARG MITMPROXY_VERSION=12.2.3
ARG PYYAML_VERSION=6.0.3
ARG KEYFENCE_UID=1000
ARG KEYFENCE_GID=1000

RUN groupadd --gid ${KEYFENCE_GID} keyfence \
  && useradd --uid ${KEYFENCE_UID} --gid ${KEYFENCE_GID} --no-create-home --shell /usr/sbin/nologin keyfence

WORKDIR /app
COPY pyproject.toml README.md /app/
COPY keyfence/ /app/keyfence/
RUN pip install --no-cache-dir "mitmproxy==${MITMPROXY_VERSION}" "PyYAML==${PYYAML_VERSION}" \
  && pip install --no-cache-dir --no-deps /app

COPY config.example.yaml /app/config.example.yaml
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh \
  && mkdir -p /data \
  && chown -R keyfence:keyfence /data

ENV KEYFENCE_HOME=/data \
    MITMPROXY_CONFDIR=/data/certs \
    KEYFENCE_CONFIG_EXAMPLE=/app/config.example.yaml

USER keyfence
WORKDIR /data

EXPOSE 8888

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["proxy"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s \
  CMD python -c "import sys; from keyfence.runner import probe; sys.exit(0 if probe(8888, 3.0) else 1)"
