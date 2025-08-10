FROM python:3.13-slim

WORKDIR /app

ARG BUILDNODE=unspecified
ENV BUILDNODE=$BUILDNODE
ARG SOURCE_COMMIT=unspecified
ENV SOURCE_COMMIT=$SOURCE_COMMIT

LABEL com.apfelwurm.build-node=$BUILDNODE \
      org.label-schema.schema-version="1.0" \
      org.label-schema.url="https://volzit.de" \
      org.label-schema.vcs-ref=$SOURCE_COMMIT \
      org.label-schema.vendor="volzit" \
      org.label-schema.description="Friendly Network Detection server" \
      org.label-schema.vcs-url="https://github.com/Apfelwurm/open-friendly-net-detection-server"

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 1001 -g users fndsrv \
    && mkdir -p /app/certs /app/logs \
    && chown -R fndsrv:users /app

# Copy project files
COPY pyproject.toml README.md ./
COPY open_friendly_net_detection_server ./open_friendly_net_detection_server
COPY scripts ./scripts
RUN pip install --no-cache-dir .

USER fndsrv

EXPOSE 32125/udp

CMD ["open-friendly-net-detection-server", "--config", "config.yaml"]
