FROM docker.io/library/golang:1.25-alpine AS builder
ARG GO_PRIVATE
WORKDIR /app
COPY go.* ./
RUN go mod download
COPY . .
# -ldflags="-s" removing symbol table (func name)
# -ldflags="-w" removing DWARF debug info (bad for: gdb, gcore, dlv)
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o network .
# for deep debug
#RUN CGO_ENABLED=0 GOOS=linux go build -o network -gcflags="all=-N -l" -o network .

FROM docker.io/library/golang:1.25-alpine AS coredns
WORKDIR /app
RUN apk add make git && \
    git clone https://github.com/coredns/coredns && cd ./coredns && git checkout v1.11.3 && \
    GOFLAGS="-buildvcs=false" make gen && GOFLAGS="-buildvcs=false" make

FROM docker.io/library/alpine:3.23
LABEL description="https://cloudnetip.com/wiki"
ARG VERSION
ENV VERSION=$VERSION
ARG VERSION_HASH
ENV VERSION_HASH=$VERSION_HASH
RUN apk --no-cache add nftables wireguard-tools-wg-quick openssl

# fixed zombie proccess for wg-quick
# and turn off wg-quick firewall rules
# bash version 5.2.15(1)-release (x86_64-alpine-linux-musl)
RUN sed -i 's@remove_firewall() {@remove_firewall() { return@' /usr/bin/wg-quick && \
    sed -i 's@add_default() {@add_default() { return@' /usr/bin/wg-quick && \
    sed -i "s|for i in \$(while read -r _.*|for i in \$(wg show \"\$INTERFACE\" allowed-ips \| awk -F '\\\t' '{print \$2}' \| sort -nr -k 2); do|" /usr/bin/wg-quick

COPY --from=builder /app/network .
COPY --from=coredns /app/coredns/coredns .
COPY --from=oxmix/proxy:2 /proxy-nginx .
COPY --from=oxmix/proxy:2 /resty /resty

ENTRYPOINT ["./network"]
