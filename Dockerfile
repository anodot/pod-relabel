FROM alpine:3.19.7
COPY ./pod-relabel_linux_amd64 /usr/local/bin/pod-relabel-app

RUN adduser -D pod-relabel-app && chmod +x /usr/local/bin/pod-relabel-app
USER pod-relabel-app

ENTRYPOINT ["/usr/local/bin/pod-relabel-app"]