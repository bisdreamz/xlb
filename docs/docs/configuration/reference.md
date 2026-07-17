# XlbConfig

- [1. Property `XlbConfig > admin`](#admin)
  - [1.1. Property `XlbConfig > admin > address`](#admin_address)
  - [1.2. Property `XlbConfig > admin > port`](#admin_port)
- [2. Property `XlbConfig > listen`](#listen)
  - [2.1. Property `XlbConfig > listen > oneOf > item 0`](#listen_oneOf_i0)
  - [2.2. Property `XlbConfig > listen > oneOf > item 1`](#listen_oneOf_i1)
    - [2.2.1. Property `XlbConfig > listen > oneOf > item 1 > ip`](#listen_oneOf_i1_ip)
- [3. Property `XlbConfig > mode`](#mode)
  - [3.1. Property `XlbConfig > mode > oneOf > item 0`](#mode_oneOf_i0)
  - [3.2. Property `XlbConfig > mode > oneOf > item 1`](#mode_oneOf_i1)
- [4. Property `XlbConfig > name`](#name)
- [5. Property `XlbConfig > orphan_ttl_secs`](#orphan_ttl_secs)
- [6. Property `XlbConfig > otel`](#otel)
  - [6.1. Property `XlbConfig > otel > anyOf > OtelConfig`](#otel_anyOf_i0)
    - [6.1.1. Property `XlbConfig > otel > anyOf > item 0 > enabled`](#otel_anyOf_i0_enabled)
    - [6.1.2. Property `XlbConfig > otel > anyOf > item 0 > endpoint`](#otel_anyOf_i0_endpoint)
    - [6.1.3. Property `XlbConfig > otel > anyOf > item 0 > export_interval_secs`](#otel_anyOf_i0_export_interval_secs)
    - [6.1.4. Property `XlbConfig > otel > anyOf > item 0 > headers`](#otel_anyOf_i0_headers)
      - [6.1.4.1. Property `XlbConfig > otel > anyOf > item 0 > headers > additionalProperties`](#otel_anyOf_i0_headers_additionalProperties)
    - [6.1.5. Property `XlbConfig > otel > anyOf > item 0 > protocol`](#otel_anyOf_i0_protocol)
  - [6.2. Property `XlbConfig > otel > anyOf > item 1`](#otel_anyOf_i1)
- [7. Property `XlbConfig > ports`](#ports)
  - [7.1. XlbConfig > ports > PortMapping](#ports_items)
    - [7.1.1. Property `XlbConfig > ports > ports items > local_port`](#ports_items_local_port)
    - [7.1.2. Property `XlbConfig > ports > ports items > remote_port`](#ports_items_remote_port)
- [8. Property `XlbConfig > proto`](#proto)
- [9. Property `XlbConfig > provider`](#provider)
  - [9.1. Property `XlbConfig > provider > oneOf > item 0`](#provider_oneOf_i0)
    - [9.1.1. Property `XlbConfig > provider > oneOf > item 0 > static`](#provider_oneOf_i0_static)
      - [9.1.1.1. Property `XlbConfig > provider > oneOf > item 0 > static > backends`](#provider_oneOf_i0_static_backends)
        - [9.1.1.1.1. XlbConfig > provider > oneOf > item 0 > static > backends > Host](#provider_oneOf_i0_static_backends_items)
          - [9.1.1.1.1.1. Property `XlbConfig > provider > oneOf > item 0 > static > backends > backends items > ip`](#provider_oneOf_i0_static_backends_items_ip)
          - [9.1.1.1.1.2. Property `XlbConfig > provider > oneOf > item 0 > static > backends > backends items > name`](#provider_oneOf_i0_static_backends_items_name)
  - [9.2. Property `XlbConfig > provider > oneOf > item 1`](#provider_oneOf_i1)
    - [9.2.1. Property `XlbConfig > provider > oneOf > item 1 > kubernetes`](#provider_oneOf_i1_kubernetes)
      - [9.2.1.1. Property `XlbConfig > provider > oneOf > item 1 > kubernetes > namespace`](#provider_oneOf_i1_kubernetes_namespace)
      - [9.2.1.2. Property `XlbConfig > provider > oneOf > item 1 > kubernetes > service`](#provider_oneOf_i1_kubernetes_service)
- [10. Property `XlbConfig > resources`](#resources)
  - [10.1. Property `XlbConfig > resources > network_capacity_mbps`](#resources_network_capacity_mbps)
- [11. Property `XlbConfig > shutdown_timeout`](#shutdown_timeout)

**Title:** XlbConfig

|                           |                  |
| ------------------------- | ---------------- |
| **Type**                  | `object`         |
| **Required**              | No               |
| **Additional properties** | Any type allowed |

**Description:** The user facing application config

| Property                                 | Pattern | Type             | Deprecated | Definition | Title/Description                                                                                                                                                                                          |
| ---------------------------------------- | ------- | ---------------- | ---------- | ---------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| - [admin](#admin )                       | No      | object           | No         | In         | Local health, readiness, and administrative status API.                                                                                                                                                    |
| - [listen](#listen )                     | No      | object           | No         | In         | The IP address to "listen" on which is the expected dest IP value for inbound packets of interest. Default to auto which will pick the primary address of the interface associated with the default route. |
| - [mode](#mode )                         | No      | object           | No         | In         | Routing mode of either nat or dsr, presently only nat is supported                                                                                                                                         |
| - [name](#name )                         | No      | string or null   | No         | -          | Optional service name attached to OTEL metrics. Defaults to "xlb" when omitted.                                                                                                                            |
| - [orphan_ttl_secs](#orphan_ttl_secs )   | No      | integer          | No         | -          | The duration by which an inactive flow, which has not seen any closure, is considered orphaned. Values below five minutes are raised to five minutes at startup.                                           |
| - [otel](#otel )                         | No      | Combination      | No         | -          | Optional OpenTelemetry metrics configuration                                                                                                                                                               |
| + [ports](#ports )                       | No      | array            | No         | -          | The port mappings of inbound to backend dest ports. E.g. [80 -> 8080], [443 -> 443]                                                                                                                        |
| - [proto](#proto )                       | No      | enum (of string) | No         | In         | The target protocol to proxy to the backends e.g. tcp or udp                                                                                                                                               |
| + [provider](#provider )                 | No      | object           | No         | In         | The source of backend hosts to load balance to                                                                                                                                                             |
| - [resources](#resources )               | No      | object           | No         | In         | Optional resource-capacity overrides for virtualized environments.                                                                                                                                         |
| - [shutdown_timeout](#shutdown_timeout ) | No      | integer          | No         | -          | Reactive grace period after a shutdown signal. Matching TCP packets that arrive during this window receive a reset before XLB exits.                                                                       |

## <a name="admin"></a>1. Property `XlbConfig > admin`

|                           |                  |
| ------------------------- | ---------------- |
| **Type**                  | `object`         |
| **Required**              | No               |
| **Additional properties** | Any type allowed |
| **Defined in**            |                  |

**Description:** Local health, readiness, and administrative status API.

| Property                     | Pattern | Type    | Deprecated | Definition | Title/Description                                       |
| ---------------------------- | ------- | ------- | ---------- | ---------- | ------------------------------------------------------- |
| - [address](#admin_address ) | No      | string  | No         | -          | Address on which the unauthenticated admin API listens. |
| - [port](#admin_port )       | No      | integer | No         | -          | TCP port on which the admin API listens.                |

### <a name="admin_address"></a>1.1. Property `XlbConfig > admin > address`

|              |               |
| ------------ | ------------- |
| **Type**     | `string`      |
| **Required** | No            |
| **Format**   | `ip`          |
| **Default**  | `"127.0.0.1"` |

**Description:** Address on which the unauthenticated admin API listens.

### <a name="admin_port"></a>1.2. Property `XlbConfig > admin > port`

|              |           |
| ------------ | --------- |
| **Type**     | `integer` |
| **Required** | No        |
| **Format**   | `uint16`  |
| **Default**  | `9090`    |

**Description:** TCP port on which the admin API listens.

| Restrictions |     |
| ------------ | --- |
| **Minimum**  | N/A |

## <a name="listen"></a>2. Property `XlbConfig > listen`

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

### <a name="listen_oneOf_i0"></a>2.1. Property `XlbConfig > listen > oneOf > item 0`

|              |                    |
| ------------ | ------------------ |
| **Type**     | `enum (of string)` |
| **Required** | No                 |

**Description:** Will attach to the interface and primary ip of associated with the default network route

Must be one of:
* "auto"

### <a name="listen_oneOf_i1"></a>2.2. Property `XlbConfig > listen > oneOf > item 1`

|                           |             |
| ------------------------- | ----------- |
| **Type**                  | `object`    |
| **Required**              | No          |
| **Additional properties** | Not allowed |

**Description:** Specify an ipv4 listen addr, also used to determine the target interface

| Property                     | Pattern | Type   | Deprecated | Definition | Title/Description |
| ---------------------------- | ------- | ------ | ---------- | ---------- | ----------------- |
| + [ip](#listen_oneOf_i1_ip ) | No      | string | No         | -          | -                 |

#### <a name="listen_oneOf_i1_ip"></a>2.2.1. Property `XlbConfig > listen > oneOf > item 1 > ip`

|              |          |
| ------------ | -------- |
| **Type**     | `string` |
| **Required** | Yes      |

## <a name="mode"></a>3. Property `XlbConfig > mode`

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

### <a name="mode_oneOf_i0"></a>3.1. Property `XlbConfig > mode > oneOf > item 0`

|              |                    |
| ------------ | ------------------ |
| **Type**     | `enum (of string)` |
| **Required** | No                 |

**Description:** Packets pass through lb bi-directionally, and is compatible with all deployment environments

Must be one of:
* "nat"

### <a name="mode_oneOf_i1"></a>3.2. Property `XlbConfig > mode > oneOf > item 1`

|              |                    |
| ------------ | ------------------ |
| **Type**     | `enum (of string)` |
| **Required** | No                 |

**Description:** Packets are distributed to backends but the client source is maintained, so the backend can skip the lb and respond directly back to the client. This requires vip configuration and arp to be disabled for the vip on the backends

Must be one of:
* "dsr"

## <a name="name"></a>4. Property `XlbConfig > name`

|              |                  |
| ------------ | ---------------- |
| **Type**     | `string or null` |
| **Required** | No               |

**Description:** Optional service name attached to OTEL metrics. Defaults to "xlb" when omitted.

## <a name="orphan_ttl_secs"></a>5. Property `XlbConfig > orphan_ttl_secs`

|              |           |
| ------------ | --------- |
| **Type**     | `integer` |
| **Required** | No        |
| **Format**   | `uint32`  |
| **Default**  | `300`     |

**Description:** The duration by which an inactive flow, which has not seen any closure, is considered orphaned. Values below five minutes are raised to five minutes at startup.

| Restrictions |     |
| ------------ | --- |
| **Minimum**  | N/A |

## <a name="otel"></a>6. Property `XlbConfig > otel`

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

### <a name="otel_anyOf_i0"></a>6.1. Property `XlbConfig > otel > anyOf > OtelConfig`

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

#### <a name="otel_anyOf_i0_enabled"></a>6.1.1. Property `XlbConfig > otel > anyOf > item 0 > enabled`

|              |           |
| ------------ | --------- |
| **Type**     | `boolean` |
| **Required** | No        |
| **Default**  | `false`   |

**Description:** Enable/disable OTEL metrics export

#### <a name="otel_anyOf_i0_endpoint"></a>6.1.2. Property `XlbConfig > otel > anyOf > item 0 > endpoint`

|              |          |
| ------------ | -------- |
| **Type**     | `string` |
| **Required** | Yes      |

**Description:** OTLP endpoint (e.g., "http://otel-collector:4317" for gRPC)

#### <a name="otel_anyOf_i0_export_interval_secs"></a>6.1.3. Property `XlbConfig > otel > anyOf > item 0 > export_interval_secs`

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

#### <a name="otel_anyOf_i0_headers"></a>6.1.4. Property `XlbConfig > otel > anyOf > item 0 > headers`

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

##### <a name="otel_anyOf_i0_headers_additionalProperties"></a>6.1.4.1. Property `XlbConfig > otel > anyOf > item 0 > headers > additionalProperties`

|              |          |
| ------------ | -------- |
| **Type**     | `string` |
| **Required** | No       |

#### <a name="otel_anyOf_i0_protocol"></a>6.1.5. Property `XlbConfig > otel > anyOf > item 0 > protocol`

|                |                    |
| -------------- | ------------------ |
| **Type**       | `enum (of string)` |
| **Required**   | No                 |
| **Defined in** |                    |

**Description:** Protocol: grpc or http/protobuf

Must be one of:
* "grpc"
* "http"

### <a name="otel_anyOf_i1"></a>6.2. Property `XlbConfig > otel > anyOf > item 1`

|              |        |
| ------------ | ------ |
| **Type**     | `null` |
| **Required** | No     |

## <a name="ports"></a>7. Property `XlbConfig > ports`

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

### <a name="ports_items"></a>7.1. XlbConfig > ports > PortMapping

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

#### <a name="ports_items_local_port"></a>7.1.1. Property `XlbConfig > ports > ports items > local_port`

|              |           |
| ------------ | --------- |
| **Type**     | `integer` |
| **Required** | Yes       |
| **Format**   | `uint16`  |

**Description:** Port on this local machine e.g. could be the lb listen port, the source port we have assigned

| Restrictions |     |
| ------------ | --- |
| **Minimum**  | N/A |

#### <a name="ports_items_remote_port"></a>7.1.2. Property `XlbConfig > ports > ports items > remote_port`

|              |           |
| ------------ | --------- |
| **Type**     | `integer` |
| **Required** | Yes       |
| **Format**   | `uint16`  |

**Description:** Port on a remote host e.g. backend node service port, or a src port from a client connection

| Restrictions |     |
| ------------ | --- |
| **Minimum**  | N/A |

## <a name="proto"></a>8. Property `XlbConfig > proto`

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

## <a name="provider"></a>9. Property `XlbConfig > provider`

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

### <a name="provider_oneOf_i0"></a>9.1. Property `XlbConfig > provider > oneOf > item 0`

|                           |             |
| ------------------------- | ----------- |
| **Type**                  | `object`    |
| **Required**              | No          |
| **Additional properties** | Not allowed |

| Property                               | Pattern | Type   | Deprecated | Definition | Title/Description |
| -------------------------------------- | ------- | ------ | ---------- | ---------- | ----------------- |
| + [static](#provider_oneOf_i0_static ) | No      | object | No         | -          | -                 |

#### <a name="provider_oneOf_i0_static"></a>9.1.1. Property `XlbConfig > provider > oneOf > item 0 > static`

|                           |                  |
| ------------------------- | ---------------- |
| **Type**                  | `object`         |
| **Required**              | Yes              |
| **Additional properties** | Any type allowed |

| Property                                          | Pattern | Type  | Deprecated | Definition | Title/Description |
| ------------------------------------------------- | ------- | ----- | ---------- | ---------- | ----------------- |
| + [backends](#provider_oneOf_i0_static_backends ) | No      | array | No         | -          | -                 |

##### <a name="provider_oneOf_i0_static_backends"></a>9.1.1.1. Property `XlbConfig > provider > oneOf > item 0 > static > backends`

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

###### <a name="provider_oneOf_i0_static_backends_items"></a>9.1.1.1.1. XlbConfig > provider > oneOf > item 0 > static > backends > Host

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

###### <a name="provider_oneOf_i0_static_backends_items_ip"></a>9.1.1.1.1.1. Property `XlbConfig > provider > oneOf > item 0 > static > backends > backends items > ip`

|              |          |
| ------------ | -------- |
| **Type**     | `string` |
| **Required** | Yes      |
| **Format**   | `ip`     |

###### <a name="provider_oneOf_i0_static_backends_items_name"></a>9.1.1.1.1.2. Property `XlbConfig > provider > oneOf > item 0 > static > backends > backends items > name`

|              |          |
| ------------ | -------- |
| **Type**     | `string` |
| **Required** | Yes      |

### <a name="provider_oneOf_i1"></a>9.2. Property `XlbConfig > provider > oneOf > item 1`

|                           |             |
| ------------------------- | ----------- |
| **Type**                  | `object`    |
| **Required**              | No          |
| **Additional properties** | Not allowed |

| Property                                       | Pattern | Type   | Deprecated | Definition | Title/Description |
| ---------------------------------------------- | ------- | ------ | ---------- | ---------- | ----------------- |
| + [kubernetes](#provider_oneOf_i1_kubernetes ) | No      | object | No         | -          | -                 |

#### <a name="provider_oneOf_i1_kubernetes"></a>9.2.1. Property `XlbConfig > provider > oneOf > item 1 > kubernetes`

|                           |                  |
| ------------------------- | ---------------- |
| **Type**                  | `object`         |
| **Required**              | Yes              |
| **Additional properties** | Any type allowed |

| Property                                                | Pattern | Type   | Deprecated | Definition | Title/Description |
| ------------------------------------------------------- | ------- | ------ | ---------- | ---------- | ----------------- |
| + [namespace](#provider_oneOf_i1_kubernetes_namespace ) | No      | string | No         | -          | -                 |
| + [service](#provider_oneOf_i1_kubernetes_service )     | No      | string | No         | -          | -                 |

##### <a name="provider_oneOf_i1_kubernetes_namespace"></a>9.2.1.1. Property `XlbConfig > provider > oneOf > item 1 > kubernetes > namespace`

|              |          |
| ------------ | -------- |
| **Type**     | `string` |
| **Required** | Yes      |

##### <a name="provider_oneOf_i1_kubernetes_service"></a>9.2.1.2. Property `XlbConfig > provider > oneOf > item 1 > kubernetes > service`

|              |          |
| ------------ | -------- |
| **Type**     | `string` |
| **Required** | Yes      |

## <a name="resources"></a>10. Property `XlbConfig > resources`

|                           |                  |
| ------------------------- | ---------------- |
| **Type**                  | `object`         |
| **Required**              | No               |
| **Additional properties** | Any type allowed |
| **Defined in**            |                  |

**Description:** Optional resource-capacity overrides for virtualized environments.

| Property                                                     | Pattern | Type            | Deprecated | Definition | Title/Description                                                                                                                                                                                                                                             |
| ------------------------------------------------------------ | ------- | --------------- | ---------- | ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| - [network_capacity_mbps](#resources_network_capacity_mbps ) | No      | integer or null | No         | -          | Per-interface network capacity in megabits per second.<br /><br />Physical NIC drivers usually report this through sysfs. Cloud and virtual NICs commonly report an unknown speed, in which case this value supplies the denominator for network utilization. |

### <a name="resources_network_capacity_mbps"></a>10.1. Property `XlbConfig > resources > network_capacity_mbps`

|              |                   |
| ------------ | ----------------- |
| **Type**     | `integer or null` |
| **Required** | No                |
| **Format**   | `uint64`          |
| **Default**  | `null`            |

**Description:** Per-interface network capacity in megabits per second.

Physical NIC drivers usually report this through sysfs. Cloud and virtual NICs commonly report an unknown speed, in which case this value supplies the denominator for network utilization.

| Restrictions |     |
| ------------ | --- |
| **Minimum**  | N/A |

## <a name="shutdown_timeout"></a>11. Property `XlbConfig > shutdown_timeout`

|              |           |
| ------------ | --------- |
| **Type**     | `integer` |
| **Required** | No        |
| **Format**   | `uint32`  |
| **Default**  | `15`      |

**Description:** Reactive grace period after a shutdown signal. Matching TCP packets that arrive during this window receive a reset before XLB exits.

| Restrictions |     |
| ------------ | --- |
| **Minimum**  | N/A |
