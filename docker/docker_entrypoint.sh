#!/bin/sh
set -e

cd /app && exec uvicorn api_service.app:asgi_app "$@"