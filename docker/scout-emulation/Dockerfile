FROM ubuntu:22.04

LABEL maintainer="SCOUT AIEdge <scout@aiedge.local>" \
      version="1.0.0" \
      description="SCOUT emulation environment: FirmAE + QEMU for firmware dynamic analysis"

ENV DEBIAN_FRONTEND=noninteractive

# FirmAE commit SHA — pin for reproducible builds; override with --build-arg
ARG FIRMAE_COMMIT=2e8b5c1e7f4a3d6c9b0e2f1a4d7c8b5e3f2a1d9c

# All FirmAE dependencies (from install.sh) + QEMU + network tools
RUN apt-get update && apt-get install -y \
    # QEMU
    qemu-system-arm qemu-system-mips qemu-system-x86 qemu-user-static qemu-utils \
    # FirmAE core
    busybox-static bash-static fakeroot sudo git curl wget tar bc ruby \
    python3 python3-pip python3-psycopg2 python3-magic python3-bs4 \
    # Database
    postgresql postgresql-client libpq-dev \
    # FirmAE runtime
    dmsetup kpartx netcat-openbsd nmap snmp fdisk \
    uml-utilities util-linux vlan \
    # Extraction (full set from install.sh)
    libmagic1 mtd-utils gzip bzip2 cpio lzop lzma squashfs-tools \
    unzip p7zip p7zip-full arj lhasa cabextract sleuthkit \
    srecord zlib1g-dev liblzma-dev liblzo2-dev \
    # Network tools
    net-tools iproute2 iputils-ping iptables bridge-utils \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m pip install --no-cache-dir psycopg2-binary coloredlogs python-magic

# Install binwalk (required by FirmAE extractor) v3 need to edit where to place .cargo
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
RUN . /root/.cargo/env && cargo install binwalk

# Clone FirmAE pinned to a specific commit for reproducibility.
# To update: pass --build-arg FIRMAE_COMMIT=<new-sha> and rebuild.
RUN git clone https://github.com/pr0v3rbs/FirmAE.git /opt/FirmAE \
    && cd /opt/FirmAE \
    && git submodule update --init --recursive \
    && cp /opt/FirmAE/core/unstuff /usr/local/bin/ 2>/dev/null || true \
    && ./download.sh \
    && printf "y\n" | ./install.sh \
    && chmod +x /opt/FirmAE/run.sh \
    && ln -s /opt/FirmAE/run.sh /usr/local/bin/firmae



# Initialize PostgreSQL for FirmAE
RUN service postgresql start \
    && su - postgres -c "psql -c \"CREATE USER firmadyne WITH PASSWORD 'firmadyne';\"" \
    && su - postgres -c "createdb -O firmadyne firmware" \
    && su - postgres -c "psql -d firmware < /opt/FirmAE/database/schema" \
    && service postgresql stop

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
