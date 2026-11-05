FROM python:3.12-slim@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HOME=/tmp STREAMLIT_BROWSER_GATHER_USAGE_STATS=false

WORKDIR /srv
COPY dashboard/requirements.txt .
RUN pip install -r requirements.txt \
 && groupadd --system --gid 10003 soc \
 && useradd --system --uid 10003 --gid soc --no-create-home --shell /usr/sbin/nologin soc
COPY dashboard/app.py ./app.py

USER 10003:10003
EXPOSE 8501
CMD ["streamlit", "run", "app.py", "--server.address=0.0.0.0", "--server.port=8501", "--server.headless=true"]
