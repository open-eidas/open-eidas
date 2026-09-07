FROM golang:1.25-bookworm AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

ARG VERSION=dev
# CGO est requis : le binding PKCS#11 charge le module du HSM via dlopen.
RUN CGO_ENABLED=1 go build -trimpath \
        -ldflags "-s -w -X main.version=${VERSION}" \
        -o /out/ocsp-responder ./cmd/ocsp-responder


FROM debian:bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends softhsm2 opensc ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10002 --create-home --home-dir /var/lib/open-eidas --groups softhsm ocsp \
 && mkdir -p /var/lib/softhsm/tokens /var/lib/open-eidas/state \
 && chown -R ocsp:ocsp /var/lib/softhsm/tokens /var/lib/open-eidas

COPY --from=build /out/ocsp-responder /usr/local/bin/ocsp-responder
COPY deploy/ocsp-responder/entrypoint.sh /usr/local/bin/entrypoint.sh

ENV SOFTHSM2_CONF=/etc/softhsm/softhsm2.conf \
    OPENEIDAS_PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so \
    OPENEIDAS_LISTEN=:8319

USER ocsp
WORKDIR /var/lib/open-eidas
EXPOSE 8319

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["serve"]
