# cowrie-soc collector: reads Cowrie's JSON log volume, writes normalized
# records/findings to its own state volume and (optionally) a SOC HTTP endpoint.
FROM python:3.12-slim@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir . && rm -rf /root/.cache
COPY config ./config

# Unprivileged user; /data/state is the only writable path (a named volume).
RUN useradd --system --uid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin collector \
    && mkdir -p /data/state && chown collector /data/state
USER 10001
VOLUME ["/data/state"]

ENTRYPOINT ["cowrie-soc"]
CMD ["run", "--config", "/app/config/collector.toml"]
