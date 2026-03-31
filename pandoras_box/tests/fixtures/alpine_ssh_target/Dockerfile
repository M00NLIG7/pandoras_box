FROM --platform=linux/amd64 alpine:3.21

ARG ROOT_PASSWORD=secret

RUN sed -i 's#https://dl-cdn.alpinelinux.org#http://dl-cdn.alpinelinux.org#g' /etc/apk/repositories \
    && apk add --no-cache gcompat libgcc libstdc++ openssh-server shadow \
    && ssh-keygen -A \
    && echo "root:${ROOT_PASSWORD}" | chpasswd \
    && sed -i 's/^#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config \
    && sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config \
    && printf '\nKbdInteractiveAuthentication no\nChallengeResponseAuthentication no\nPrintMotd no\nUsePAM no\n' >> /etc/ssh/sshd_config \
    && mkdir -p /run/sshd

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D", "-e"]
