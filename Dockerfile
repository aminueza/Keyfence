FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml README.md /app/
COPY keyfence/ /app/keyfence/
RUN pip install --no-cache-dir /app

COPY config.example.yaml /app/config.example.yaml
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENV KEYFENCE_HOME=/data \
    KEYFENCE_CONFIG=/data/config.yaml

EXPOSE 8888

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["proxy"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s \
  CMD python -c "import socket; socket.create_connection(('127.0.0.1', 8888), timeout=3)"
