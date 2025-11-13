# c2/Dockerfile
FROM ubuntu:18.10
ENV DEBIAN_FRONTEND=noninteractive
RUN set -eux; \
  echo "deb http://old-releases.ubuntu.com/ubuntu/ cosmic main restricted universe multiverse" > /etc/apt/sources.list; \
  echo "deb http://old-releases.ubuntu.com/ubuntu/ cosmic-updates main restricted universe multiverse" >> /etc/apt/sources.list; \
  echo "deb http://old-releases.ubuntu.com/ubuntu/ cosmic-security main restricted universe multiverse" >> /etc/apt/sources.list; \
  apt-get update && apt-get install -y --no-install-recommends openssh-client ca-certificates nano iputils-ping iproute2 && \
  rm -rf /var/lib/apt/lists/*
RUN useradd -ms /bin/bash lab && mkdir -p /home/lab/.ssh && chown -R lab:lab /home/lab/.ssh && \
    su - lab -c 'ssh-keygen -t ed25519 -N "" -f ~/.ssh/id_ed25519'
USER lab
WORKDIR /home/lab
CMD ["sleep","infinity"]
