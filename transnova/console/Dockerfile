# TransNova SOC console: builds the React app, then serves it with the FastAPI backend.
FROM node:22.11.0-slim AS web
WORKDIR /web
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 \
    SOC_FRONTEND_DIR=/srv/frontend
WORKDIR /srv
COPY console/requirements.txt .
RUN pip install -r requirements.txt \
 && groupadd --system --gid 10003 soc \
 && useradd --system --uid 10003 --gid soc --no-create-home --shell /usr/sbin/nologin soc
COPY console ./console
COPY --from=web /web/dist ./frontend
USER 10003:10003
EXPOSE 8501
HEALTHCHECK --interval=15s --timeout=3s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8501/healthz',timeout=2).status==200 else 1)"
CMD ["uvicorn", "console.serve:app", "--host", "0.0.0.0", "--port", "8501", "--no-server-header"]
