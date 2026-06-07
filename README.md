# Pangolin Middleware: Badger

[![GitHub Release](https://img.shields.io/github/release/fosrl/badger?sort=semver)](https://github.com/fosrl/badger/releases)
[![Go Version](https://img.shields.io/github/go-mod/go-version/fosrl/badger)](https://github.com/fosrl/badger/blob/main/go.mod)
[![CI](https://github.com/fosrl/badger/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/fosrl/badger/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/fosrl/badger)](https://goreportcard.com/report/github.com/fosrl/badger)
[![License](https://img.shields.io/github/license/fosrl/badger)](https://github.com/fosrl/badger/blob/main/LICENSE)
[![Traefik Plugin](https://img.shields.io/badge/Traefik-Plugin-24A1C1)](https://plugins.traefik.io/)
[![Pangolin](https://img.shields.io/badge/Pangolin-Middleware-blue)](https://github.com/fosrl/pangolin)

Badger is a middleware plugin designed to work with Traefik in conjunction with [Pangolin](https://github.com/fosrl/pangolin), an identity-aware reverse proxy and zero-trust VPN. Badger acts as an authentication bouncer, ensuring only authenticated and authorized requests are allowed through the proxy.

> [!NOTE]
> Badger can also be used standalone for IP handling (Cloudflare and custom proxy support) without Pangolin. Simply set `disableForwardAuth: true` in your configuration. See the [Disabling Forward Auth](#disabling-forward-auth) section below for details.

This plugin is **required** to be installed alongside [Pangolin](https://github.com/fosrl/pangolin) to enforce secure authentication and session management.

## What Badger does

Badger runs as a Traefik middleware in front of protected services.

For each request, Badger can:

1. determine the real client IP from Cloudflare or a trusted upstream proxy,
2. normalize `X-Real-IP` and `X-Forwarded-For` for downstream services,
3. call the Pangolin API to verify authentication and resource access,
4. allow, block, or redirect the request based on the verification result.

## Modes

### Pangolin authentication mode

This is the default mode. Badger validates incoming requests against the
Pangolin API before forwarding them to the upstream service.

### IP handling only mode

Set `disableForwardAuth: true` to disable Pangolin authentication and only use
Badger for real-client-IP handling.

Use this only when authentication is handled elsewhere or when you explicitly
want Badger to act only as an IP normalization middleware.

## Installation

Badger is automatically installed with Pangolin. Learn how to install Pangolin in the [Pangolin Documentation](https://docs.pangolin.net/self-host/quick-install).

## Configuration

Pangolin will provide the necessary configuration to Badger automatically via the HTTP provider. However, you can override the configuration settings by manually providing them in the Traefik config.

### Required Configuration Options

When forward auth is enabled (default), the following options are required:

```yaml
apiBaseUrl: "http://localhost:3001/api/v1"
userSessionCookieName: "p_session_token"
resourceSessionRequestParam: "p_session_request"
```

### Disabling Forward Auth

To disable forward auth and only use IP handling, set `disableForwardAuth: true`. When enabled, all requests pass through without authentication, and the required configuration options above are not needed:

Only do this if you do not need Pangolin's authentication features and only want IP handling.

```yaml
disableForwardAuth: true
```

### IP Handling Configuration

Badger automatically extracts the real client IP from requests. By default, it trusts Cloudflare IP ranges and uses the `CF-Connecting-IP` header.

#### Using with Cloudflare (Default)

No additional configuration needed. Badger automatically:

- Trusts Cloudflare IP ranges
- Extracts IP from `CF-Connecting-IP` header
- Sets `X-Real-IP` and `X-Forwarded-For` headers for downstream services

#### Using without Cloudflare

If you're using a different proxy or load balancer, configure custom trusted IPs and/or a custom IP header:

Ensure you always disable the default Cloudflare IP ranges by setting `disableDefaultCFIPs: true` and provide your own trusted IP ranges in CIDR format under `trustip` if using a different proxy.

```yaml
apiBaseUrl: "http://localhost:3001/api/v1"
userSessionCookieName: "p_session_token"
resourceSessionRequestParam: "p_session_request"

# Disable Cloudflare IP ranges
disableDefaultCFIPs: true

# Add your proxy/load balancer IP ranges (CIDR format)
trustip:
  - "10.0.0.0/8"
  - "172.16.0.0/12"

# Optional: Use a custom header instead of CF-Connecting-IP
customIPHeader: "X-Forwarded-For"
```

## Updating Cloudflare IPs

To update the Cloudflare IP ranges, run:

```bash
./updateCFIps.sh
```

This fetches the latest IP ranges from Cloudflare and updates `ips/ips.go`.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
