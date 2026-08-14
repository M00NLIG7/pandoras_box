# syntax=docker/dockerfile:1.7
FROM --platform=linux/amd64 alpine:3.21@sha256:48b0309ca019d89d40f670aa1bc06e426dc0931948452e8491e3d65087abc07d

RUN --mount=type=secret,id=ca_certificate,required=false \
    if [ -s /run/secrets/ca_certificate ]; then \
        cat /run/secrets/ca_certificate >> /etc/ssl/certs/ca-certificates.crt; \
    fi \
    && apk add --no-cache gcompat libgcc libstdc++ openssh-server shadow \
    && ssh-keygen -A

ARG FIXTURE_CREDENTIAL_NONCE
RUN --mount=type=secret,id=root_password,required=true \
    test -n "$FIXTURE_CREDENTIAL_NONCE" \
    && ROOT_PASSWORD="$(cat /run/secrets/root_password)" \
    && test -n "$ROOT_PASSWORD" \
    && printf 'root:%s\n' "$ROOT_PASSWORD" | chpasswd \
    && sed -i 's/^#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config \
    && sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config \
    && printf '\nKbdInteractiveAuthentication no\nChallengeResponseAuthentication no\nPrintMotd no\nUsePAM no\n' >> /etc/ssh/sshd_config \
    && mkdir -p /run/sshd

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D", "-e"]
