FROM --platform=linux/amd64 ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ARG ROOT_PASSWORD=secret

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-server iproute2 procps net-tools \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /run/sshd \
    && echo "root:${ROOT_PASSWORD}" | chpasswd \
    && sed -ri 's/^#?PermitRootLogin .*/PermitRootLogin yes/' /etc/ssh/sshd_config \
    && sed -ri 's/^#?PasswordAuthentication .*/PasswordAuthentication yes/' /etc/ssh/sshd_config \
    && sed -ri 's/^#?KbdInteractiveAuthentication .*/KbdInteractiveAuthentication no/' /etc/ssh/sshd_config \
    && printf '\nUsePAM no\nChallengeResponseAuthentication no\nPrintMotd no\n' >> /etc/ssh/sshd_config

EXPOSE 22 44372

CMD ["/usr/sbin/sshd", "-D", "-e"]
