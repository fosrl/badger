# Badger Plugin for Traefik with Pangolin Integration

Badger is a middleware plugin designed to work with the Traefik reverse proxy in conjunction with [Pangolin](https://github.com/fosrl/pangolin), a multi-tenant tunneled reverse proxy server and management interface with identity and access management. Badger acts as an authentication bouncer, ensuring only authenticated and authorized requests are allowed through the proxy.

This plugin is **required** to be configured alongside [Pangolin](https://github.com/fosrl/pangolin) to enforce secure authentication and session management.

## Installation

Learn how to set up [Pangolin](https://github.com/fosrl/pangolin) and Badger in the [Pangolin Documentation](https://github.com/fosrl/pangolin).

## Configuration

Badger requires the following configuration parameters to be specified in your [Traefik configuration file](https://doc.traefik.io/traefik/getting-started/configuration-overview/). These coincide with the separate [Pangolin](https://github.com/fosrl/pangolin) configuration file. These options do not need to be configured unless you need to override the automatically provided config from Pangolin.

### Configuration Options

```yaml
apiBaseUrl: "http://localhost:3001/api/v1"
userSessionCookieName: "p_session_token"
resourceSessionRequestParam: "p_session_request"
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
