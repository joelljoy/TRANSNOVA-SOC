FROM python:3.12-slim@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 \
    COLLECTOR_DB_PATH=/data/collector.db

WORKDIR /srv
COPY collector/requirements.txt .
RUN pip install -r requirements.txt \
 && groupadd --system --gid 10002 soc \
 && useradd --system --uid 10002 --gid soc --no-create-home --shell /usr/sbin/nologin soc \
 && mkdir -p /data && chown soc:soc /data
COPY collector ./collector

USER 10002:10002
EXPOSE 8000
CMD ["uvicorn", "collector.app:app", "--host", "0.0.0.0", "--port", "8000", "--http", "h11", "--no-server-header", "--no-access-log"]
