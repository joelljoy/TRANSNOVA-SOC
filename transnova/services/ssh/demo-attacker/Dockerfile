# Local lab traffic generator (see scenarios.py). Not part of the honeypot.
FROM python:3.12-slim@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159
RUN pip install --no-cache-dir paramiko==3.5.1
COPY scenarios.py /app/scenarios.py
USER 65534:65534
ENV HOME=/tmp PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
ENTRYPOINT ["python", "/app/scenarios.py"]
