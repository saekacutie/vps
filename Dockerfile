FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# admin-api.py is stdlib-only; no pip dependencies required.
COPY admin-api.py vpn-status.py port-forward.py ./
COPY web-panel/ ./web-panel/
COPY entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh /app/admin-api.py /app/vpn-status.py \
    && python3 -m py_compile /app/admin-api.py /app/vpn-status.py /app/port-forward.py

EXPOSE 8080

ENTRYPOINT ["/entrypoint.sh"]
