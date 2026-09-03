FROM debian:bookworm-slim

# strongSwan IKEv2 gateway image
# Minimal networking packages per Phase-1 requirements.
# Installed strongSwan version documented at build time: 5.9.8 (Debian bookworm).
# Uses swanctl / vici interface (strongswan-swanctl) and charon-systemd.

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        strongswan \
        strongswan-swanctl \
        charon-systemd \
        libstrongswan-standard-plugins \
        libstrongswan-extra-plugins \
        libcharon-extra-plugins \
        iproute2 \
        iputils-ping \
        tcpdump \
        tshark \
        traceroute \
        net-tools \
        iptables \
        iperf3 \
        python3 \
        python3-pip \
        python3-scapy \
        curl \
        netcat-openbsd \
        dnsutils \
        procps \
        conntrack \
        ca-certificates \
        openssl \
        && pip3 install --no-cache-dir scapy 2>&1 | tail -5; \
        apt-get clean && rm -rf /var/lib/apt/lists/*

# Enable IPv4/IPv6 forwarding at runtime via sysctl; also set in compose.
# Create swanctl directories
RUN mkdir -p /etc/swanctl/conf.d /etc/swanctl/x509 /etc/swanctl/private \
             /var/log /var/run

# strongSwan charon logging: log to stderr so docker logs captures it
COPY charon.conf /etc/strongswan.d/charon.conf
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 500/udp 4500/udp

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
