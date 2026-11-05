# Database sensor. Same base image as the web decoy.
FROM python:3.12-slim@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app
COPY requirements.txt .
# uid 999 matches the mysql user in the MariaDB image, so the audit log (mode 640) is readable.
RUN pip install -r requirements.txt \
 && groupadd --system --gid 999 sensor \
 && useradd --system --uid 999 --gid sensor --no-create-home --shell /usr/sbin/nologin sensor \
 && mkdir -p /data && chown sensor:sensor /data

COPY db_sensor ./db_sensor
COPY config ./config

USER 999:999
CMD ["python", "-m", "db_sensor.main"]
