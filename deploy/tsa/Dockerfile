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
        -o /out/tsa-server ./cmd/tsa-server


FROM debian:bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends softhsm2 opensc ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --create-home --home-dir /var/lib/open-eidas --groups softhsm tsa \
 && mkdir -p /var/lib/softhsm/tokens /var/lib/open-eidas/state \
 && chown -R tsa:tsa /var/lib/softhsm/tokens /var/lib/open-eidas

COPY --from=build /out/tsa-server /usr/local/bin/tsa-server
COPY deploy/tsa/entrypoint.sh /usr/local/bin/entrypoint.sh

ENV SOFTHSM2_CONF=/etc/softhsm/softhsm2.conf \
    OPENEIDAS_PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so \
    OPENEIDAS_LISTEN=:8318

USER tsa
WORKDIR /var/lib/open-eidas
EXPOSE 8318

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["serve"]
