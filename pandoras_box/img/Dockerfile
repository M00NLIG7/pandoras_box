FROM alpine:edge

WORKDIR /root

RUN apk add gnutls
RUN wget https://github.com/sogaani/winexe/releases/download/v1.0/winexe-static
RUN chmod +x winexe-static

COPY winexe-wrapper.sh /root
RUN chmod +x /root/winexe-wrapper.sh

ENTRYPOINT ["/root/winexe-wrapper.sh"]
