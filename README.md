# Netip Network Component
[![CI Status](https://github.com/oxmix/netip-network/workflows/Package%20release/badge.svg)](https://github.com/oxmix/netip-network/actions/workflows/package-release.yaml)

This repository is for public viewing and container assembly. For more information, follow the link https://cloudnetip.com/wiki

```shell
docker run -d --name netip.network --restart always \
  --cap-add=NET_ADMIN --network=host \
  -e CONNECT_KEY=****** \
  -e FIREWALL_GROUPS='Default, Or my group name' \
ghcr.io/oxmix/netip-network:latest
```
