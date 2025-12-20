# Pangolin Middleware: Badger

Badger is a middleware plugin designed to work with the Traefik reverse proxy in conjunction with [Pangolin](https://github.com/fosrl/pangolin), an identity-aware reverse proxy and VPN. Badger acts as an authentication bouncer, ensuring only authenticated and authorized requests are allowed through the proxy.

> [!NOTE] 
> Badger can also be used standalone for IP handling (Cloudflare and custom proxy support) without Pangolin. Simply set `disableForwardAuth: true` in your configuration. See the [Disabling Forward Auth](#disabling-forward-auth) section below for details.

This plugin is **required** to be installed alongside [Pangolin](https://github.com/fosrl/pangolin) to enforce secure authentication and session management.

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

```yaml
disableForwardAuth: true

# IP handling configuration (optional)
trustip:
  - "10.0.0.0/8"
customIPHeader: "X-Forwarded-For"
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

### Configuration Options Reference

| Option                        | Type     | Required* | Default | Description                                                                         |
| ----------------------------- | -------- | --------- | ------- | ----------------------------------------------------------------------------------- |
| `disableForwardAuth`          | bool     | No        | `false` | Disable forward auth; only IP handling is performed                                |
| `apiBaseUrl`                  | string   | Yes*      | -       | Base URL of the Pangolin API                                                        |
| `userSessionCookieName`       | string   | Yes*      | -       | Cookie name for user sessions                                                       |
| `resourceSessionRequestParam` | string   | Yes*      | -       | Query parameter name for resource session requests                                  |
| `trustip`                     | []string | No        | `[]`    | Array of trusted IP ranges in CIDR format                                           |
| `disableDefaultCFIPs`         | bool     | No        | `false` | Disable default Cloudflare IP ranges                                                |
| `customIPHeader`              | string   | No        | `""`    | Custom header name to extract IP from (only used if request is from trusted source) |

\* Required only when `disableForwardAuth` is `false` (default)


## Updating Cloudflare IPs

To update the Cloudflare IP ranges, run:

```bash
./updateCFIps.sh
```

This fetches the latest IP ranges from Cloudflare and updates `ips/ips.go`.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
