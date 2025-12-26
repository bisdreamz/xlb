# XlbConfig

- [1. Property `XlbConfig > listen`](#listen)
  - [1.1. Property `XlbConfig > listen > oneOf > item 0`](#listen_oneOf_i0)
  - [1.2. Property `XlbConfig > listen > oneOf > item 1`](#listen_oneOf_i1)
    - [1.2.1. Property `XlbConfig > listen > oneOf > item 1 > ip`](#listen_oneOf_i1_ip)
- [2. Property `XlbConfig > mode`](#mode)
  - [2.1. Property `XlbConfig > mode > oneOf > item 0`](#mode_oneOf_i0)
  - [2.2. Property `XlbConfig > mode > oneOf > item 1`](#mode_oneOf_i1)
- [3. Property `XlbConfig > name`](#name)
- [4. Property `XlbConfig > orphan_ttl_secs`](#orphan_ttl_secs)
- [5. Property `XlbConfig > otel`](#otel)
  - [5.1. Property `XlbConfig > otel > anyOf > OtelConfig`](#otel_anyOf_i0)
    - [5.1.1. Property `XlbConfig > otel > anyOf > item 0 > enabled`](#otel_anyOf_i0_enabled)
    - [5.1.2. Property `XlbConfig > otel > anyOf > item 0 > endpoint`](#otel_anyOf_i0_endpoint)
    - [5.1.3. Property `XlbConfig > otel > anyOf > item 0 > export_interval_secs`](#otel_anyOf_i0_export_interval_secs)
    - [5.1.4. Property `XlbConfig > otel > anyOf > item 0 > headers`](#otel_anyOf_i0_headers)
      - [5.1.4.1. Property `XlbConfig > otel > anyOf > item 0 > headers > additionalProperties`](#otel_anyOf_i0_headers_additionalProperties)
    - [5.1.5. Property `XlbConfig > otel > anyOf > item 0 > protocol`](#otel_anyOf_i0_protocol)
  - [5.2. Property `XlbConfig > otel > anyOf > item 1`](#otel_anyOf_i1)
- [6. Property `XlbConfig > ports`](#ports)
  - [6.1. XlbConfig > ports > PortMapping](#ports_items)
    - [6.1.1. Property `XlbConfig > ports > ports items > local_port`](#ports_items_local_port)
    - [6.1.2. Property `XlbConfig > ports > ports items > remote_port`](#ports_items_remote_port)
- [7. Property `XlbConfig > proto`](#proto)
- [8. Property `XlbConfig > provider`](#provider)
  - [8.1. Property `XlbConfig > provider > oneOf > item 0`](#provider_oneOf_i0)
    - [8.1.1. Property `XlbConfig > provider > oneOf > item 0 > static`](#provider_oneOf_i0_static)
      - [8.1.1.1. Property `XlbConfig > provider > oneOf > item 0 > static > backends`](#provider_oneOf_i0_static_backends)
        - [8.1.1.1.1. XlbConfig > provider > oneOf > item 0 > static > backends > Host](#provider_oneOf_i0_static_backends_items)
          - [8.1.1.1.1.1. Property `XlbConfig > provider > oneOf > item 0 > static > backends > backends items > ip`](#provider_oneOf_i0_static_backends_items_ip)
          - [8.1.1.1.1.2. Property `XlbConfig > provider > oneOf > item 0 > static > backends > backends items > name`](#provider_oneOf_i0_static_backends_items_name)
  - [8.2. Property `XlbConfig > provider > oneOf > item 1`](#provider_oneOf_i1)
    - [8.2.1. Property `XlbConfig > provider > oneOf > item 1 > kubernetes`](#provider_oneOf_i1_kubernetes)
      - [8.2.1.1. Property `XlbConfig > provider > oneOf > item 1 > kubernetes > namespace`](#provider_oneOf_i1_kubernetes_namespace)
      - [8.2.1.2. Property `XlbConfig > provider > oneOf > item 1 > kubernetes > service`](#provider_oneOf_i1_kubernetes_service)
- [9. Property `XlbConfig > shutdown_timeout`](#shutdown_timeout)

**Title:** XlbConfig

|                           |                  |
| ------------------------- | ---------------- |
| **Type**                  | `object`         |
| **Required**              | No               |
| **Additional properties** | Any type allowed |

**Description:** The user facing application config

| Property                                 | Pattern | Type             | Deprecated | Definition | Title/Description                                                                                                                                                                                          |
| ---------------------------------------- | ------- | ---------------- | ---------- | ---------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| - [listen](#listen )                     | No      | object           | No         | In         | The IP address to "listen" on which is the expected dest IP value for inbound packets of interest. Default to auto which will pick the primary address of the interface associated with the default route. |
| - [mode](#mode )                         | No      | object           | No         | In         | Routing mode of either nat or dsr, presently only nat is supported                                                                                                                                         |
| - [name](#name )                         | No      | string or null   | No         | -          | Optional name to attach to future otel metrics, if not provided defaults to kube service name or static-lb for static deployments                                                                          |
| - [orphan_ttl_secs](#orphan_ttl_secs )   | No      | integer          | No         | -          | The duration by which an inactive flow, which has not seen any closure, is considered orphaned                                                                                                             |
| - [otel](#otel )                         | No      | Combination      | No         | -          | Optional OpenTelemetry metrics configuration                                                                                                                                                               |
| + [ports](#ports )                       | No      | array            | No         | -          | The port mappings of inbound to backend dest ports. E.g. [80 -> 8080], [443 -> 443]                                                                                                                        |
| - [proto](#proto )                       | No      | enum (of string) | No         | In         | The target protocol to proxy to the backends e.g. tcp or udp                                                                                                                                               |
| + [provider](#provider )                 | No      | object           | No         | In         | The source of backend hosts to load balance to                                                                                                                                                             |
| - [shutdown_timeout](#shutdown_timeout ) | No      | integer          | No         | -          | Grace period after a shutdown which is used to 'politely' send RSTs to any active flows, particularly to allow graceful drain after a potential lb A record removal                                        |

## <a name="listen"></a>1. Property `XlbConfig > listen`

|                           |                  |
| ------------------------- | ---------------- |
| **Type**                  | `combining`      |
| **Required**              | No               |
| **Additional properties** | Any type allowed |
| **Default**               | `"auto"`         |
| **Defined in**            |                  |

**Description:** The IP address to "listen" on which is the expected dest IP value for inbound packets of interest. Default to auto which will pick the primary address of the interface associated with the default route.

| One of(Option)             |
| -------------------------- |
| [item 0](#listen_oneOf_i0) |
| [item 1](#listen_oneOf_i1) |

### <a name="listen_oneOf_i0"></a>1.1. Property `XlbConfig > listen > oneOf > item 0`

|              |                    |
| ------------ | ------------------ |
| **Type**     | `enum (of string)` |
| **Required** | No                 |

**Description:** Will attach to the interface and primary ip of associated with the default network route

Must be one of:
* "auto"

### <a name="listen_oneOf_i1"></a>1.2. Property `XlbConfig > listen > oneOf > item 1`

|                           |             |
| ------------------------- | ----------- |
| **Type**                  | `object`    |
| **Required**              | No          |
| **Additional properties** | Not allowed |

**Description:** Specify an ipv4 listen addr, also used to determine the target interface

| Property                     | Pattern | Type   | Deprecated | Definition | Title/Description |
| ---------------------------- | ------- | ------ | ---------- | ---------- | ----------------- |
| + [ip](#listen_oneOf_i1_ip ) | No      | string | No         | -          | -                 |

#### <a name="listen_oneOf_i1_ip"></a>1.2.1. Property `XlbConfig > listen > oneOf > item 1 > ip`

|              |          |
| ------------ | -------- |
| **Type**     | `string` |
| **Required** | Yes      |

## <a name="mode"></a>2. Property `XlbConfig > mode`

|                           |                  |
| ------------------------- | ---------------- |
| **Type**                  | `combining`      |
| **Required**              | No               |
| **Additional properties** | Any type allowed |
| **Default**               | `"nat"`          |
| **Defined in**            |                  |

**Description:** Routing mode of either nat or dsr, presently only nat is supported

| One of(Option)           |
| ------------------------ |
| [item 0](#mode_oneOf_i0) |
| [item 1](#mode_oneOf_i1) |

### <a name="mode_oneOf_i0"></a>2.1. Property `XlbConfig > mode > oneOf > item 0`

|              |                    |
| ------------ | ------------------ |
| **Type**     | `enum (of string)` |
| **Required** | No                 |

**Description:** Packets pass through lb bi-directionally, and is compatible with all deployment environments

Must be one of:
* "nat"

### <a name="mode_oneOf_i1"></a>2.2. Property `XlbConfig > mode > oneOf > item 1`

|              |                    |
| ------------ | ------------------ |
| **Type**     | `enum (of string)` |
| **Required** | No                 |

**Description:** Packets are distributed to backends but the client source is maintained, so the backend can skip the lb and respond directly back to the client. This requires vip configuration and arp to be disabled for the vip on the backends

Must be one of:
* "dsr"

## <a name="name"></a>3. Property `XlbConfig > name`

|              |                  |
| ------------ | ---------------- |
| **Type**     | `string or null` |
| **Required** | No               |

**Description:** Optional name to attach to future otel metrics, if not provided defaults to kube service name or static-lb for static deployments

## <a name="orphan_ttl_secs"></a>4. Property `XlbConfig > orphan_ttl_secs`

|              |           |
| ------------ | --------- |
| **Type**     | `integer` |
| **Required** | No        |
| **Format**   | `uint32`  |
| **Default**  | `300`     |

**Description:** The duration by which an inactive flow, which has not seen any closure, is considered orphaned

| Restrictions |     |
| ------------ | --- |
| **Minimum**  | N/A |

## <a name="otel"></a>5. Property `XlbConfig > otel`

|                           |                  |
| ------------------------- | ---------------- |
| **Type**                  | `combining`      |
| **Required**              | No               |
| **Additional properties** | Any type allowed |

**Description:** Optional OpenTelemetry metrics configuration

| Any of(Option)               |
| ---------------------------- |
| [OtelConfig](#otel_anyOf_i0) |
| [item 1](#otel_anyOf_i1)     |

### <a name="otel_anyOf_i0"></a>5.1. Property `XlbConfig > otel > anyOf > OtelConfig`

|                           |                          |
| ------------------------- | ------------------------ |
| **Type**                  | `object`                 |
| **Required**              | No                       |
| **Additional properties** | Any type allowed         |
| **Defined in**            | #/definitions/OtelConfig |

**Description:** OpenTelemetry configuration for metrics export

| Property                                                       | Pattern | Type             | Deprecated | Definition | Title/Description                                           |
| -------------------------------------------------------------- | ------- | ---------------- | ---------- | ---------- | ----------------------------------------------------------- |
| - [enabled](#otel_anyOf_i0_enabled )                           | No      | boolean          | No         | -          | Enable/disable OTEL metrics export                          |
| + [endpoint](#otel_anyOf_i0_endpoint )                         | No      | string           | No         | -          | OTLP endpoint (e.g., "http://otel-collector:4317" for gRPC) |
| - [export_interval_secs](#otel_anyOf_i0_export_interval_secs ) | No      | integer          | No         | -          | Export interval in seconds                                  |
| - [headers](#otel_anyOf_i0_headers )                           | No      | object           | No         | -          | Optional headers for authentication (e.g., API keys)        |
| - [protocol](#otel_anyOf_i0_protocol )                         | No      | enum (of string) | No         | In         | Protocol: grpc or http/protobuf                             |

#### <a name="otel_anyOf_i0_enabled"></a>5.1.1. Property `XlbConfig > otel > anyOf > item 0 > enabled`

|              |           |
| ------------ | --------- |
| **Type**     | `boolean` |
| **Required** | No        |
| **Default**  | `false`   |

**Description:** Enable/disable OTEL metrics export

#### <a name="otel_anyOf_i0_endpoint"></a>5.1.2. Property `XlbConfig > otel > anyOf > item 0 > endpoint`

|              |          |
| ------------ | -------- |
| **Type**     | `string` |
| **Required** | Yes      |

**Description:** OTLP endpoint (e.g., "http://otel-collector:4317" for gRPC)

#### <a name="otel_anyOf_i0_export_interval_secs"></a>5.1.3. Property `XlbConfig > otel > anyOf > item 0 > export_interval_secs`

|              |           |
| ------------ | --------- |
| **Type**     | `integer` |
| **Required** | No        |
| **Format**   | `uint64`  |
| **Default**  | `10`      |

**Description:** Export interval in seconds

| Restrictions |     |
| ------------ | --- |
| **Minimum**  | N/A |

#### <a name="otel_anyOf_i0_headers"></a>5.1.4. Property `XlbConfig > otel > anyOf > item 0 > headers`

|                           |                                                                                                    |
| ------------------------- | -------------------------------------------------------------------------------------------------- |
| **Type**                  | `object`                                                                                           |
| **Required**              | No                                                                                                 |
| **Additional properties** | [Each additional property must conform to the schema](#otel_anyOf_i0_headers_additionalProperties) |
| **Default**               | `{}`                                                                                               |

**Description:** Optional headers for authentication (e.g., API keys)

| Property                                           | Pattern | Type   | Deprecated | Definition | Title/Description |
| -------------------------------------------------- | ------- | ------ | ---------- | ---------- | ----------------- |
| - [](#otel_anyOf_i0_headers_additionalProperties ) | No      | string | No         | -          | -                 |

##### <a name="otel_anyOf_i0_headers_additionalProperties"></a>5.1.4.1. Property `XlbConfig > otel > anyOf > item 0 > headers > additionalProperties`

|              |          |
| ------------ | -------- |
| **Type**     | `string` |
| **Required** | No       |

#### <a name="otel_anyOf_i0_protocol"></a>5.1.5. Property `XlbConfig > otel > anyOf > item 0 > protocol`

|                |                    |
| -------------- | ------------------ |
| **Type**       | `enum (of string)` |
| **Required**   | No                 |
| **Defined in** |                    |

**Description:** Protocol: grpc or http/protobuf

Must be one of:
* "grpc"
* "http"

### <a name="otel_anyOf_i1"></a>5.2. Property `XlbConfig > otel > anyOf > item 1`

|              |        |
| ------------ | ------ |
| **Type**     | `null` |
| **Required** | No     |

## <a name="ports"></a>6. Property `XlbConfig > ports`

|              |         |
| ------------ | ------- |
| **Type**     | `array` |
| **Required** | Yes     |

**Description:** The port mappings of inbound to backend dest ports. E.g. [80 -> 8080], [443 -> 443]

|                      | Array restrictions |
| -------------------- | ------------------ |
| **Min items**        | N/A                |
| **Max items**        | N/A                |
| **Items unicity**    | False              |
| **Additional items** | False              |
| **Tuple validation** | See below          |

| Each item of this array must be | Description                                                                                         |
| ------------------------------- | --------------------------------------------------------------------------------------------------- |
| [PortMapping](#ports_items)     | Generic port mapping struct representing a port on the local machine and a port on some remote host |

### <a name="ports_items"></a>6.1. XlbConfig > ports > PortMapping

|                           |                           |
| ------------------------- | ------------------------- |
| **Type**                  | `object`                  |
| **Required**              | No                        |
| **Additional properties** | Any type allowed          |
| **Defined in**            | #/definitions/PortMapping |

**Description:** Generic port mapping struct representing a port on the local machine and a port on some remote host

| Property                                   | Pattern | Type    | Deprecated | Definition | Title/Description                                                                             |
| ------------------------------------------ | ------- | ------- | ---------- | ---------- | --------------------------------------------------------------------------------------------- |
| + [local_port](#ports_items_local_port )   | No      | integer | No         | -          | Port on this local machine e.g. could be the lb listen port, the source port we have assigned |
| + [remote_port](#ports_items_remote_port ) | No      | integer | No         | -          | Port on a remote host e.g. backend node service port, or a src port from a client connection  |

#### <a name="ports_items_local_port"></a>6.1.1. Property `XlbConfig > ports > ports items > local_port`

|              |           |
| ------------ | --------- |
| **Type**     | `integer` |
| **Required** | Yes       |
| **Format**   | `uint16`  |

**Description:** Port on this local machine e.g. could be the lb listen port, the source port we have assigned

| Restrictions |     |
| ------------ | --- |
| **Minimum**  | N/A |

#### <a name="ports_items_remote_port"></a>6.1.2. Property `XlbConfig > ports > ports items > remote_port`

|              |           |
| ------------ | --------- |
| **Type**     | `integer` |
| **Required** | Yes       |
| **Format**   | `uint16`  |

**Description:** Port on a remote host e.g. backend node service port, or a src port from a client connection

| Restrictions |     |
| ------------ | --- |
| **Minimum**  | N/A |

## <a name="proto"></a>7. Property `XlbConfig > proto`

|                |                    |
| -------------- | ------------------ |
| **Type**       | `enum (of string)` |
| **Required**   | No                 |
| **Default**    | `"tcp"`            |
| **Defined in** |                    |

**Description:** The target protocol to proxy to the backends e.g. tcp or udp

Must be one of:
* "tcp"
* "udp"

## <a name="provider"></a>8. Property `XlbConfig > provider`

|                           |                  |
| ------------------------- | ---------------- |
| **Type**                  | `combining`      |
| **Required**              | Yes              |
| **Additional properties** | Any type allowed |
| **Defined in**            |                  |

**Description:** The source of backend hosts to load balance to

| One of(Option)               |
| ---------------------------- |
| [item 0](#provider_oneOf_i0) |
| [item 1](#provider_oneOf_i1) |

### <a name="provider_oneOf_i0"></a>8.1. Property `XlbConfig > provider > oneOf > item 0`

|                           |             |
| ------------------------- | ----------- |
| **Type**                  | `object`    |
| **Required**              | No          |
| **Additional properties** | Not allowed |

| Property                               | Pattern | Type   | Deprecated | Definition | Title/Description |
| -------------------------------------- | ------- | ------ | ---------- | ---------- | ----------------- |
| + [static](#provider_oneOf_i0_static ) | No      | object | No         | -          | -                 |

#### <a name="provider_oneOf_i0_static"></a>8.1.1. Property `XlbConfig > provider > oneOf > item 0 > static`

|                           |                  |
| ------------------------- | ---------------- |
| **Type**                  | `object`         |
| **Required**              | Yes              |
| **Additional properties** | Any type allowed |

| Property                                          | Pattern | Type  | Deprecated | Definition | Title/Description |
| ------------------------------------------------- | ------- | ----- | ---------- | ---------- | ----------------- |
| + [backends](#provider_oneOf_i0_static_backends ) | No      | array | No         | -          | -                 |

##### <a name="provider_oneOf_i0_static_backends"></a>8.1.1.1. Property `XlbConfig > provider > oneOf > item 0 > static > backends`

|              |         |
| ------------ | ------- |
| **Type**     | `array` |
| **Required** | Yes     |

|                      | Array restrictions |
| -------------------- | ------------------ |
| **Min items**        | N/A                |
| **Max items**        | N/A                |
| **Items unicity**    | False              |
| **Additional items** | False              |
| **Tuple validation** | See below          |

| Each item of this array must be                  | Description |
| ------------------------------------------------ | ----------- |
| [Host](#provider_oneOf_i0_static_backends_items) | -           |

###### <a name="provider_oneOf_i0_static_backends_items"></a>8.1.1.1.1. XlbConfig > provider > oneOf > item 0 > static > backends > Host

|                           |                    |
| ------------------------- | ------------------ |
| **Type**                  | `object`           |
| **Required**              | No                 |
| **Additional properties** | Any type allowed   |
| **Defined in**            | #/definitions/Host |

| Property                                                 | Pattern | Type   | Deprecated | Definition | Title/Description |
| -------------------------------------------------------- | ------- | ------ | ---------- | ---------- | ----------------- |
| + [ip](#provider_oneOf_i0_static_backends_items_ip )     | No      | string | No         | -          | -                 |
| + [name](#provider_oneOf_i0_static_backends_items_name ) | No      | string | No         | -          | -                 |

###### <a name="provider_oneOf_i0_static_backends_items_ip"></a>8.1.1.1.1.1. Property `XlbConfig > provider > oneOf > item 0 > static > backends > backends items > ip`

|              |          |
| ------------ | -------- |
| **Type**     | `string` |
| **Required** | Yes      |
| **Format**   | `ip`     |

###### <a name="provider_oneOf_i0_static_backends_items_name"></a>8.1.1.1.1.2. Property `XlbConfig > provider > oneOf > item 0 > static > backends > backends items > name`

|              |          |
| ------------ | -------- |
| **Type**     | `string` |
| **Required** | Yes      |

### <a name="provider_oneOf_i1"></a>8.2. Property `XlbConfig > provider > oneOf > item 1`

|                           |             |
| ------------------------- | ----------- |
| **Type**                  | `object`    |
| **Required**              | No          |
| **Additional properties** | Not allowed |

| Property                                       | Pattern | Type   | Deprecated | Definition | Title/Description |
| ---------------------------------------------- | ------- | ------ | ---------- | ---------- | ----------------- |
| + [kubernetes](#provider_oneOf_i1_kubernetes ) | No      | object | No         | -          | -                 |

#### <a name="provider_oneOf_i1_kubernetes"></a>8.2.1. Property `XlbConfig > provider > oneOf > item 1 > kubernetes`

|                           |                  |
| ------------------------- | ---------------- |
| **Type**                  | `object`         |
| **Required**              | Yes              |
| **Additional properties** | Any type allowed |

| Property                                                | Pattern | Type   | Deprecated | Definition | Title/Description |
| ------------------------------------------------------- | ------- | ------ | ---------- | ---------- | ----------------- |
| + [namespace](#provider_oneOf_i1_kubernetes_namespace ) | No      | string | No         | -          | -                 |
| + [service](#provider_oneOf_i1_kubernetes_service )     | No      | string | No         | -          | -                 |

##### <a name="provider_oneOf_i1_kubernetes_namespace"></a>8.2.1.1. Property `XlbConfig > provider > oneOf > item 1 > kubernetes > namespace`

|              |          |
| ------------ | -------- |
| **Type**     | `string` |
| **Required** | Yes      |

##### <a name="provider_oneOf_i1_kubernetes_service"></a>8.2.1.2. Property `XlbConfig > provider > oneOf > item 1 > kubernetes > service`

|              |          |
| ------------ | -------- |
| **Type**     | `string` |
| **Required** | Yes      |

## <a name="shutdown_timeout"></a>9. Property `XlbConfig > shutdown_timeout`

|              |           |
| ------------ | --------- |
| **Type**     | `integer` |
| **Required** | No        |
| **Format**   | `uint32`  |
| **Default**  | `15`      |

**Description:** Grace period after a shutdown which is used to 'politely' send RSTs to any active flows, particularly to allow graceful drain after a potential lb A record removal

| Restrictions |     |
| ------------ | --- |
| **Minimum**  | N/A |

----------------------------------------------------------------------------------------------------------------------------
Generated using [json-schema-for-humans](https://github.com/coveooss/json-schema-for-humans) on 2025-12-20 at 21:43:40 -0600
