FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    curl \
    dnsutils \
    iproute2 \
    iputils-ping \
    net-tools \
    procps \
    tcpdump \
    tshark \
    vim-tiny \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

WORKDIR /labs

CMD ["bash"]
