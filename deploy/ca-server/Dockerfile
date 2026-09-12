FROM rust:1-bookworm AS build

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY bin ./bin

ARG VERSION=dev
# Pas de CGO à activer : le binding PKCS#11 (crate `cryptoki`) charge le
# module du HSM via dlopen au même titre que le binaire Go, mais sans lien
# statique contre une bibliothèque C particulière au moment de la
# compilation. `ca-server` tire en plus `sqlx`/PostgreSQL (feature
# `postgres` de `oe-castore`, déclarée dans bin/ca-server/Cargo.toml).
RUN cargo build --release --bin ca-server \
 && cp target/release/ca-server /out-ca-server \
 && rm -rf target


FROM debian:bookworm-slim

RUN apt-get update \
 && apt-get upgrade -y \
 && apt-get install -y --no-install-recommends softhsm2 opensc ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10003 --create-home --home-dir /var/lib/open-eidas --groups softhsm ca \
 && mkdir -p /var/lib/softhsm/tokens /var/lib/open-eidas/state \
 && chown -R ca:ca /var/lib/softhsm/tokens /var/lib/open-eidas

COPY --from=build /out-ca-server /usr/local/bin/ca-server
COPY deploy/ca-server/entrypoint.sh /usr/local/bin/entrypoint.sh

ENV SOFTHSM2_CONF=/etc/softhsm/softhsm2.conf \
    OPENEIDAS_PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so \
    OPENEIDAS_LISTEN=:8320

USER ca
WORKDIR /var/lib/open-eidas
EXPOSE 8320

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["serve"]
