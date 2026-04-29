# PegaProx Grafana Dashboard

## PegaProx API Token
Access to metrics exposed by PegaProx is secured and requires proper authentication. This ensures that only authorized systems or users can retrieve monitoring data from the exporter endpoint.

To authenticate against the exporter, an API token must be provided with each request. This token acts as a credential and is required for all metric queries.

### Obtaining an API Token
It is recommended to create a dedicated technical account for monitoring purposes. Using a separate account improves security, auditability, and avoids unintended side effects from personal user accounts.

Follow these steps to generate a suitable API token:
* Log in to PegaProx with an administrative or authorized user account.
* Navigate to the User Settings section.
* Create a new API key for the technical account.
* Assign read-only permissions to the API key to restrict access strictly to metric retrieval.
* Copy and securely store the generated API token.

## Prometheus Exporter
To collect metrics from PegaProx, you need to configure Prometheus to scrape the built-in exporter endpoint. Since the metrics endpoint is secured, a few additional settings are required compared to a default scrape job.

PegaProx exposes its metrics over HTTPS on port 5000 under the path /api/metrics. Because of this, you must explicitly enable TLS in your Prometheus configuration. In addition, authentication is required, so you need to create an API token in PegaProx and pass it along with each request.

```
- job_name: 'pegaprox'
  metrics_path: /api/metrics
  scheme: https
  authorization:
  type: Bearer
  credentials: pgx_token123token123
  tls_config:
  insecure_skip_verify: true
  static_configs:
  - targets: ['pegaprox01.int.gyptazy.com:5000']
```

## Grafana Dashboard
You can simply import the dashboard or JSON file to your Grafana instance.