FROM busybox:glibc

COPY libdl.so.2 /lib/
COPY winexe-static .
COPY winexe-static-2 .

CMD ["tail", "-f", "/dev/null"]
