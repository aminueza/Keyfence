FROM python:3.12-slim@sha256:191083cdf6c7bda8c76158983163ead5d5cf7b77cf3033e805bb0f5296f51b4b

ARG KEYFENCE_UID=1000
ARG KEYFENCE_GID=1000

RUN groupadd --gid ${KEYFENCE_GID} keyfence \
  && useradd --uid ${KEYFENCE_UID} --gid ${KEYFENCE_GID} --home-dir /data --no-create-home --shell /usr/sbin/nologin keyfence

WORKDIR /app
COPY requirements-docker.txt pyproject.toml README.md LICENSE /app/
COPY keyfence/ /app/keyfence/
RUN pip install --no-cache-dir --require-hashes -r /app/requirements-docker.txt \
  && pip install --no-cache-dir --no-deps --no-build-isolation /app \
  && pip uninstall -y setuptools

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
  CMD python -c "import sys; from keyfence.runner import probe; sys.exit(0 if probe(8888, timeout=3.0) else 1)"
