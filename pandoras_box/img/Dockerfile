FROM alpine:edge

WORKDIR /root

# Combine package installation and cleanup
RUN apk add --no-cache gnutls && \
    wget https://github.com/sogaani/winexe/releases/download/v1.0/winexe-static -O winexe-static && \
    chmod +x winexe-static && \
    rm -rf /var/cache/apk/*

ENTRYPOINT ["./winexe-static"]
