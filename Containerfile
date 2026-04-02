FROM registry.access.redhat.com/ubi10-minimal:10.1-1774545417

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

# install dependencies and updates
RUN microdnf --nodocs --setopt install_weak_deps=0 -y install \
    gcc \
    git-core \
    krb5-devel \
    krb5-workstation \
    make \
    openssl-devel \
    python3-devel \
    python3-pip \
    redhat-rpm-config \
    tar \
    && microdnf --nodocs --setopt install_weak_deps=0 -y upgrade \
    && microdnf clean all

# create a non-privileged user
RUN useradd -d /opt/app-root -g 0 -m aegis

# switch to the non-privileged user
USER aegis
ENV HOME="/opt/app-root" \
    PATH="/opt/app-root/.local/bin:${PATH}"

WORKDIR /opt/app-root
COPY --chown=aegis . /opt/app-root

# install uv, install local dependencies and initialize version string
RUN set -o pipefail \
    && pip3 install --no-cache-dir gssapi uv \
    && uv sync --no-cache --frozen --extra classifier_deps \
    && printf '\n[tool.hatch.version.raw-options]\nfallback_version = "%s"\n' \
        "$(uv run python -c 'import aegis_ai; print(aegis_ai.__version__)')" \
    | tee -a pyproject.toml

# remove git repo, docs, and classifier training artifacts (keep models + feature extraction)
RUN rm -fr .git docs \
    src/aegis_ai_ml/src/classifier/kernel-cve-impact-classifier/data \
    src/aegis_ai_ml/src/classifier/kernel-cve-impact-classifier/test-results \
    src/aegis_ai_ml/src/classifier/kernel-cve-impact-classifier/*_train*.py \
    src/aegis_ai_ml/src/classifier/kernel-cve-impact-classifier/cve_data_scraper.py \
    src/aegis_ai_ml/src/classifier/kernel-cve-impact-classifier/cve_predictor.py \
    src/aegis_ai_ml/src/classifier/kernel-cve-impact-classifier/cve_smote_balancer.py \
    src/aegis_ai_ml/src/classifier/kernel-cve-impact-classifier/cvss_cwe_features.py \
    src/aegis_ai_ml/src/classifier/kernel-cve-impact-classifier/fetch_cvss_cwe.py \
    src/aegis_ai_ml/src/classifier/kernel-cve-impact-classifier/split_datasets_for_train_test.py \
    src/aegis_ai_ml/src/classifier/kernel-cve-impact-classifier/test_cve_model.py

RUN chgrp -R 0 /opt/app-root && \
    chmod -R g=u /opt/app-root
