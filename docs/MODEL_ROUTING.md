# Model Routing Benchmark Results: Strands Decider 2B vs Always Large Model

**Benchmark Goal:** Compare latency, token consumption, and official Amazon Bedrock execution costs between:
1. **Baseline Strategy (`Always Large`):** Every finding is analyzed using the large model tier (`amazon.nova-pro-v1:0`).
2. **Strands Decider-Routed Strategy:** Strands Decider 2B categorizes findings into `template` ($0.00 / instant), `small` (`amazon.nova-micro-v1:0`), or `large` (`amazon.nova-pro-v1:0`).

## Summary Metrics

| Metric | Always Large Model | Decider-Routed | Reduction / Benefit |
| :--- | :--- | :--- | :--- |
| **Total Latency** | `43050.8 ms` | `25913.9 ms` | **39.8% Faster** |
| **Total Token Cost** | `$0.01328` | `$0.00429` | **67.7% Cost Reduction** |
| **Total Tokens** | `4605` tokens | `3690` tokens | **19.9% Fewer Tokens** |
| **Workload Split** | 100% Large Model | 20% Template, 50% Small, 30% Large | Balanced System-1 / System-2 |

## Detailed Finding Breakdown

| Finding | Severity | Routed Tier | Baseline Latency / Cost | Routed Latency / Cost | Cost Type |
| :--- | :--- | :--- | :--- | :--- | :--- |
| Missing HTTP Strict-Transport-Security (HSTS) Header | Low | `template` | 4583ms / $0.00133 | 0ms / $0.00000 | Real Bedrock Tokens |
| Missing Content-Security-Policy (CSP) Header | Medium | `template` | 4376ms / $0.00133 | 0ms / $0.00000 | Real Bedrock Tokens |
| Server Information Disclosure in HTTP Banner | Info | `small` | 4322ms / $0.00132 | 2595ms / $0.00006 | Real Bedrock Tokens |
| OpenSSL Denial of Service in Certificate Parsing | Low | `small` | 4517ms / $0.00133 | 2449ms / $0.00006 | Real Bedrock Tokens |
| Express Cookie Without Secure and SameSite Attributes | Low | `small` | 4045ms / $0.00132 | 2396ms / $0.00006 | Real Bedrock Tokens |
| Node.js HTTP Request Smuggling | Medium | `small` | 4751ms / $0.00133 | 2434ms / $0.00006 | Real Bedrock Tokens |
| Nginx TLS 1.0 / 1.1 Weak Cipher Suites Enabled | Low | `small` | 4114ms / $0.00133 | 2428ms / $0.00006 | Real Bedrock Tokens |
| Apache HTTP Server Path Traversal and Remote Code Execution | Critical | `large` | 4206ms / $0.00133 | 4843ms / $0.00133 | Real Bedrock Tokens |
| Log4j JNDI Remote Code Execution (Log4Shell) | Critical | `large` | 4088ms / $0.00134 | 3964ms / $0.00134 | Real Bedrock Tokens |
| Spring Framework Remote Code Execution (Spring4Shell) | High | `large` | 4050ms / $0.00133 | 4806ms / $0.00133 | Real Bedrock Tokens |

## Official AWS Bedrock Pricing Baseline
- **Large Tier Model (`amazon.nova-pro-v1:0`):** $0.800 / 1M input, $3.200 / 1M output (Source: AWS Bedrock Pricing).
- **Small Tier Model (`amazon.nova-micro-v1:0`):** $0.035 / 1M input, $0.140 / 1M output (Source: AWS Bedrock Pricing).
- **Template Remediation:** $0.00 / 0ms execution time.
- **Strands Decider 2B:** System One pointer-head classification (measured on the deployed instance: TBD, zero autoregressive token overhead).