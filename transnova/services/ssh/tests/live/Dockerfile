# Live marker test client. Not the demo attacker, and not part of the deployed stack.
FROM python:3.12-slim@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159
RUN pip install --no-cache-dir paramiko==3.5.1
COPY marker_session.py /app/marker_session.py
USER 65534:65534
ENV HOME=/tmp PYTHONDONTWRITEBYTECODE=1
ENTRYPOINT ["python", "/app/marker_session.py"]
