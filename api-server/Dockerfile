FROM python:3.12-slim

COPY api_server.py /app/api_server.py
WORKDIR /app

EXPOSE 9998/tcp
EXPOSE 9999/udp

CMD ["python", "api_server.py"]
