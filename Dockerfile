FROM python:3.11-slim-bookworm

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY backend/services/requirements.txt /app/backend/services/requirements.txt
RUN pip install -r /app/backend/services/requirements.txt

COPY backend /app/backend
COPY start.sh /app/start.sh
RUN chmod +x /app/start.sh

EXPOSE 10000

WORKDIR /app/backend
CMD ["/app/start.sh"]

