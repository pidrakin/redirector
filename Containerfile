FROM alpine

ENV USER=redirector
ENV BINARY=redirector

RUN adduser \
    --disabled-password \
    --gecos "${USER}" \
    --shell "/sbin/nologin" \
    --no-create-home \
    "${USER}"

COPY ${BINARY}/${BINARY} /go/bin/

# Use an unprivileged user.
USER ${USER}:${USER}

ENTRYPOINT ["/go/bin/${BINARY}"]
