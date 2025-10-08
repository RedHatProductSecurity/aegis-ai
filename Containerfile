# TODO: consider using the ubi10-minimal to reduce size of the output image
FROM registry.access.redhat.com/ubi10:10.0-1758699521

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

# install dependencies and security updates
# FIXME: remove unneeded dependencies from the list (see Containerfile.eval)
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

# create a non-privileged user
RUN useradd -d /opt/app-root -g 0 -m aegis

# switch to the non-privileged user
USER aegis
ENV HOME="/opt/app-root" \
    PATH="/opt/app-root/.local/bin:${PATH}"

WORKDIR /opt/app-root
COPY --chown=aegis . /opt/app-root
# FIXME: the build-container task in Konflux does not support `COPY --exclude=.git`
RUN rm -rf .git

# install uv
RUN pip3 install --no-cache-dir gssapi uv && uv sync --no-cache

RUN chgrp -R 0 /opt/app-root && \
    chmod -R g=u /opt/app-root
