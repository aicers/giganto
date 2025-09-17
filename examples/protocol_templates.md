# Protocol Templates GraphQL API Usage Examples

This document provides examples of how to use the new protocol template GraphQL queries to retrieve field format information for protocols.

## Query: Get All Protocol Templates

Returns field format information for all supported protocols:

```graphql
query GetAllProtocolTemplates {
  protocolTemplates {
    protocol
    fields
  }
}
```

Example response:
```json
{
  "data": {
    "protocolTemplates": [
      {
        "protocol": "conn",
        "fields": [
          "time", "orig_addr", "orig_port", "resp_addr", "resp_port", "proto",
          "conn_state", "start_time", "end_time", "service", "orig_bytes", "resp_bytes",
          "orig_pkts", "resp_pkts", "orig_l2_bytes", "resp_l2_bytes"
        ]
      },
      {
        "protocol": "dns",
        "fields": [
          "time", "orig_addr", "orig_port", "resp_addr", "resp_port", "proto",
          "start_time", "end_time", "query", "answer", "trans_id", "rtt", "qclass",
          "qtype", "rcode", "aa_flag", "tc_flag", "rd_flag", "ra_flag", "ttl"
        ]
      }
    ]
  }
}
```

## Query: Get Specific Protocol Template

Returns field format information for a specific protocol:

```graphql
query GetConnTemplate {
  protocolTemplates(protocol: "conn") {
    protocol
    fields
  }
}
```

Example response:
```json
{
  "data": {
    "protocolTemplates": [
      {
        "protocol": "conn",
        "fields": [
          "time", "orig_addr", "orig_port", "resp_addr", "resp_port", "proto",
          "conn_state", "start_time", "end_time", "service", "orig_bytes", "resp_bytes",
          "orig_pkts", "resp_pkts", "orig_l2_bytes", "resp_l2_bytes"
        ]
      }
    ]
  }
}
```

## Query: Export Protocol Templates to File

Exports protocol templates to a file in JSON or CSV format:

```graphql
mutation ExportAllTemplatesAsJSON {
  exportProtocolTemplates(exportType: "json")
}
```

```graphql
mutation ExportConnTemplateAsCSV {
  exportProtocolTemplates(exportType: "csv", protocol: "conn")
}
```

Example response:
```json
{
  "data": {
    "exportProtocolTemplates": "/path/to/export/protocol_templates_20240116_143022.json"
  }
}
```

## Use Cases

### 1. Web UI Dynamic Query Generation

The Web UI can now dynamically generate GraphQL queries for each protocol:

```javascript
// Fetch template for HTTP protocol
const template = await fetchProtocolTemplate("http");

// Dynamically build GraphQL query
const query = `
  query GetHttpEvents($filter: NetworkFilter!) {
    httpRawEvents(filter: $filter) {
      edges {
        node {
          ${template.fields.join('\n          ')}
        }
      }
    }
  }
`;
```

### 2. REconverge Field Format Configuration

REconverge can automatically configure field formats:

```python
# Fetch all protocol templates
templates = fetch_protocol_templates()

# Generate configuration for each protocol
for template in templates:
    config = {
        'protocol': template['protocol'],
        'fields': [
            {'name': field, 'type': infer_type(field)}
            for field in template['fields']
        ]
    }
    write_protocol_config(config)
```

### 3. CSV Export for Manual Configuration

Export templates as CSV for manual review and configuration:

```graphql
mutation ExportCSV {
  exportProtocolTemplates(exportType: "csv")
}
```

The CSV format provides:
- `protocol`: Protocol name
- `field_index`: Field position in the template
- `field_name`: Name of the field

This enables easy review and manual modification of field formats when needed.

## Supported Protocols

The API supports templates for all protocols available in Giganto:

### Network Protocols
- conn, dns, http, rdp, smtp, ntlm, kerberos, ssh, dce rpc, ftp, mqtt, ldap, tls, smb, nfs, bootp, dhcp, radius

### Log Protocols
- log, secu log, op_log

### Netflow Protocols
- netflow5, netflow9

### Sysmon Events
- process create, file create time, network connect, process terminate, image load, file create, registry value set, registry key rename, file create stream hash, pipe event, dns query, file delete, process tamper, file delete detected

### Time Series & Statistics
- periodic time series, statistics