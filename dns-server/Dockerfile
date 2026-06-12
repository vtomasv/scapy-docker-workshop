FROM python:3.12-slim

RUN pip install --no-cache-dir 'dnslib>=0.9.24,<1'

COPY dns_server.py /app/dns_server.py
WORKDIR /app

EXPOSE 53/udp

CMD ["python", "dns_server.py"]
