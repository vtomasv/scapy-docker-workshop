FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    curl \
    dnsutils \
    iproute2 \
    iputils-ping \
    net-tools \
    procps \
    && rm -rf /var/lib/apt/lists/*

COPY traffic-generator.sh /opt/traffic-generator.sh
RUN chmod +x /opt/traffic-generator.sh

CMD ["sleep", "infinity"]
