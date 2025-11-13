FROM ubuntu:16.10
ENV DEBIAN_FRONTEND=noninteractive

# Cambia repos a old-releases y desactiva verificación por fecha expirada
RUN set -eux; \
  echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99no-check-valid; \
  sed -i 's|http://\([a-z]*\.\)\?archive\.ubuntu\.com/ubuntu|http://old-releases.ubuntu.com/ubuntu|g' /etc/apt/sources.list; \
  sed -i 's|http://security\.ubuntu\.com/ubuntu|http://old-releases.ubuntu.com/ubuntu|g' /etc/apt/sources.list; \
  apt-get update; \
  apt-get install -y --no-install-recommends openssh-client ca-certificates nano iputils-ping iproute2; \
  rm -rf /var/lib/apt/lists/*

# Usuario y llaves
RUN useradd -ms /bin/bash lab && mkdir -p /home/lab/.ssh && chown -R lab:lab /home/lab/.ssh && \
    su - lab -c 'ssh-keygen -t ed25519 -N "" -f ~/.ssh/id_ed25519'

USER lab
WORKDIR /home/lab
CMD ["sleep","infinity"]
