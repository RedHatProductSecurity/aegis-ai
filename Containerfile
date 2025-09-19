FROM registry.access.redhat.com/ubi10:10.0-1758186945

LABEL summary="AEGIS" \
      maintainer="Product Security DevOps <prodsec-dev@redhat.com>"

ARG PIP_INDEX_URL="https://pypi.org/simple"
ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=off \
    PIP_INDEX_URL="${PIP_INDEX_URL}" \
    UV_NO_CACHE=off \
    UV_NATIVE_TLS=true \
    UV_PROJECT_ENVIRONMENT="/opt/app-root/.venv" \
    REQUESTS_CA_BUNDLE="/etc/pki/tls/certs/ca-bundle.crt"

EXPOSE 9000

# OPTIONAL: When RH_CERT_URL is passed we set RH internal root ca and the IPA CA cert
ARG RH_CERT_URL=""
COPY ./scripts /scripts
RUN ./scripts/install-certs.sh $RH_CERT_URL

# install dependencies and security updates
RUN dnf --nodocs --setopt install_weak_deps=false -y install \
    cargo \
    gcc \
    git \
    krb5-devel \
    krb5-workstation \
    libffi-devel \
    logrotate \
    make \
    openldap-devel \
    openssl-devel \
    podman \
    postgresql-devel \
    procps-ng \
    python3-devel \
    python3-pip \
    redhat-rpm-config \
    which \
    && dnf --nodocs --setopt install_weak_deps=false -y upgrade --security \
    && dnf clean all

WORKDIR /opt/app-root
COPY --exclude=.git . /opt/app-root

# install uv
RUN pip3 install gssapi uv && uv sync

ENV PATH="/opt/app-root/.local/bin:${PATH}"

RUN chgrp -R 0 /opt/app-root && \
    chmod -R g=u /opt/app-root

RUN chmod +x /opt/app-root/scripts/run_web_service.sh
