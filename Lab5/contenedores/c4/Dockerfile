# s1/Dockerfile
FROM ubuntu:22.10
ENV DEBIAN_FRONTEND=noninteractive

# Repos EOL -> old-releases y apt con fechas viejas
RUN set -eux; \
  echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99no-check-valid; \
  sed -i 's|http://\([a-z]*\.\)\?archive\.ubuntu\.com/ubuntu|http://old-releases.ubuntu.com/ubuntu|g' /etc/apt/sources.list || true; \
  sed -i 's|http://security\.ubuntu\.com/ubuntu|http://old-releases.ubuntu.com/ubuntu|g' /etc/apt/sources.list || true; \
  apt-get update && apt-get install -y --no-install-recommends \
    openssh-server ca-certificates nano iputils-ping iproute2 tzdata \
  && rm -rf /var/lib/apt/lists/*

# Usuario 'prueba' con password 'prueba'
RUN useradd -ms /bin/bash prueba \
  && echo 'prueba:prueba' | chpasswd \
  && mkdir -p /var/run/sshd

# Config SSH (habilita password)
RUN set -eux; \
  cat > /etc/ssh/sshd_config <<'EOF'
Port 22
Protocol 2

HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key

PasswordAuthentication yes
PubkeyAuthentication yes
ChallengeResponseAuthentication no
UsePAM yes
PermitRootLogin no

PrintMotd no
Subsystem sftp /usr/lib/openssh/sftp-server
EOF

EXPOSE 22
CMD ["/usr/sbin/sshd","-D","-e"]
