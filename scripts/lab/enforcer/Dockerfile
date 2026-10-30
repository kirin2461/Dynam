FROM debian:12-slim

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       ca-certificates iproute2 nftables procps python3 suricata \
    && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /usr/local/bin/ncp-enforcer-entrypoint
COPY nftables.sh /usr/local/bin/ncp-enforcer-nftables
COPY suricata.rules /etc/suricata/rules/ncp-enforcer.rules

RUN mkdir -p /var/log/suricata /results

ENTRYPOINT ["bash", "/usr/local/bin/ncp-enforcer-entrypoint"]
