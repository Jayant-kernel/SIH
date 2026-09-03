FROM debian:bookworm-slim

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        iproute2 \
        iputils-ping \
        tcpdump \
        traceroute \
        net-tools \
        iperf3 \
        python3 \
        python3-pip \
        python3-scapy \
        curl \
        netcat-openbsd \
        dnsutils \
        procps \
        ca-certificates \
        && pip3 install --no-cache-dir scapy 2>&1 | tail -5; \
        apt-get clean && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
