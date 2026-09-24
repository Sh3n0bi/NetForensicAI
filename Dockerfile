# NetForensicAI — container image for the web UI (and CLI).
#
# Bundles tshark, so the fast C-dissector pcap engine is used automatically
# (no local Wireshark install needed). A case is a DuckDB file plus JSON
# manifests under /data, which is a volume so cases and saved settings
# outlive the container.

FROM python:3.12-slim AS runtime

# tshark for the fast pcap engine. DEBIAN_FRONTEND stops wireshark-common's
# postinst prompting about who may capture packets (which would hang the
# build); --no-install-recommends keeps the Qt/desktop stack out.
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tshark \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

# Runtime extras: pcap dissection + anomaly detection, threat-intel feeds,
# EVTX/Sysmon, and the web UI (which pulls in waitress for serving off
# loopback). AI provider SDKs are left out to keep the image lean - set an
# API key and `pip install` the relevant extra in a derived image if wanted.
RUN pip install --no-cache-dir ".[pcap,intel,evtx,web]" \
    && chmod +x /app/docker/entrypoint.sh

# Run as a non-root user: the container analyzes hostile evidence, so it
# should not hold root. Live capture (which needs privileges) is not the
# default use of this image.
RUN useradd --create-home --uid 10001 analyst \
    && mkdir -p /data/cases /data/config \
    && chown -R analyst:analyst /data
USER analyst

# Cases and settings live here, on a volume, not inside the image layer.
ENV NETFORENSIC_CASES_DIR=/data/cases \
    NETFORENSIC_CONFIG_DIR=/data/config
VOLUME ["/data"]
EXPOSE 8000

ENTRYPOINT ["/app/docker/entrypoint.sh"]
CMD ["web"]
