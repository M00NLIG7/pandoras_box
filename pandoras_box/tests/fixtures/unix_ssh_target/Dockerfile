# syntax=docker/dockerfile:1.7
FROM --platform=linux/amd64 ubuntu:24.04@sha256:561618e2c15bf2397621dd04f96926663a3b5616c189cf7e38db7e82f5c538ea

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-server iproute2 procps net-tools \
    && rm -rf /var/lib/apt/lists/*

ARG FIXTURE_CREDENTIAL_NONCE
RUN --mount=type=secret,id=root_password,required=true \
    test -n "$FIXTURE_CREDENTIAL_NONCE" \
    && ROOT_PASSWORD="$(cat /run/secrets/root_password)" \
    && test -n "$ROOT_PASSWORD" \
    && mkdir -p /run/sshd \
    && printf 'root:%s\n' "$ROOT_PASSWORD" | chpasswd \
    && sed -ri 's/^#?PermitRootLogin .*/PermitRootLogin yes/' /etc/ssh/sshd_config \
    && sed -ri 's/^#?PasswordAuthentication .*/PasswordAuthentication yes/' /etc/ssh/sshd_config \
    && sed -ri 's/^#?KbdInteractiveAuthentication .*/KbdInteractiveAuthentication no/' /etc/ssh/sshd_config \
    && printf '\nUsePAM no\nChallengeResponseAuthentication no\nPrintMotd no\n' >> /etc/ssh/sshd_config

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D", "-e"]
