FROM alpine

ENV SOCKET_FILE=""
ENV LISTEN_ADDRESS="0.0.0.0:8000"

RUN adduser \
    --disabled-password \
    --gecos "redirector" \
    --shell "/sbin/nologin" \
    --no-create-home \
    "redirector"

COPY redirector /go/bin/

USER redirector

EXPOSE 8000

ENTRYPOINT ["/go/bin/redirector"]
