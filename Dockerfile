# Stage 1: Build the React Frontend
FROM node:20-slim AS frontend_builder

WORKDIR /frontend
COPY frontend/package*.json ./
RUN npm install
COPY frontend ./
RUN npm run build

# Stage 2: Build the FastAPI/Flask Backend
FROM python:3.11-slim-bookworm

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt /app/requirements.txt
RUN pip install -r /app/requirements.txt

COPY backend /app/backend

# Copy the built React app into the static folder Flask expects to serve
COPY --from=frontend_builder /frontend/dist /app/backend/static

COPY start.sh /app/start.sh
RUN chmod +x /app/start.sh

EXPOSE 10000

WORKDIR /app/backend
CMD ["/app/start.sh"]

