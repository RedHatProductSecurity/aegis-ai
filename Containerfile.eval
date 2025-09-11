FROM registry.access.redhat.com/ubi10-minimal

# install required RPM packages
RUN microdnf install -y gcc git-core krb5-devel make python3-pip

# create a non-privileged user
RUN useradd -d /src -g 0 -m aegis && chmod g+rwxs /src

# switch to the non-privileged user
USER aegis
WORKDIR /src
ENV HOME="/src" \
    PATH="/src/.local/bin:${PATH}"

# initialize the home directory
RUN git config --global --add safe.directory /src/aegis-ai \
    && pip install --upgrade pip uv \
    && printf "#!/bin/bash -ex\ncd aegis-ai\ngit pull\nmake eval\n" > entrypoint.sh \
    && chmod 0755 entrypoint.sh

# checkout the repository and initialize virtual environment
RUN umask 2 \
    && git clone --depth=1 https://github.com/RedHatProductSecurity/aegis-ai.git \
    && cd aegis-ai \
    && uv sync 

# the default entry point can be overridden at run time
CMD ["/src/entrypoint.sh"]
