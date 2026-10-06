# Attestation Guard

卫星载荷配置下发前的**签名与版本承接校验服务**。只有供应商签名有效、且版本号承接当前已接纳版本的配置证明才会被接纳，从而防止重放、回退和并发请求造成分叉。

- 纯 Python 3.11 标准库实现（内置 RFC 8032 Ed25519），镜像构建无需联网安装依赖。
- 状态持久化在 SQLite（WAL + `BEGIN IMMEDIATE`），重启后仍可查询唯一已接纳代次。
- 提供 Dockerfile 与 Docker Compose，包含健康检查、宿主机端口 `APP_PORT` 配置，以及一次性 `verify` 服务。

## API

### `GET /healthz`

健康检查，返回 `200 {"status":"ok"}`。

### `POST /api/attestations`

请求体（UTF-8 JSON）：

| 字段 | 说明 |
| --- | --- |
| `attestationId` | 本次证明的唯一编号（全局唯一，用于重放检测） |
| `keyId` | 随部署声明的供应商公钥编号 |
| `payloadBase64` | 载荷的 Base64；载荷为 UTF-8 JSON 的原始字节 |
| `signatureBase64` | 对**载荷解码后原始字节**的 Ed25519 签名，Base64 |

载荷 JSON 必须包含：

```json
{
  "deviceId": "sat-alpha",
  "generation": 2,
  "previousGeneration": 1,
  "configSha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
}
```

`configSha256` 必须是 **64 位小写十六进制**的配置 SHA-256。

可选字段 `restoresGeneration`（**紧急恢复**，非负整数）：指向本设备**当前头之前**
已接纳的一代，且 `configSha256` 必须与该历史代次的摘要完全一致。恢复证明仍是
普通链节点——必须由设备密钥签名、`previousGeneration` 承接当前头、`generation`
严格更大；它只是把新代次的配置显式标记为"恢复自某历史代次"，**不是**把代次计数
器回拨。恢复被接纳后，接纳响应与 `GET /api/devices/{deviceId}/head` 都会携带
`restoresGeneration`，明确标示恢复来源；普通证明不含该字段，原有契约不变。

接纳规则：

1. 用 `keyId` 对应的部署公钥验证签名；未知密钥 / 错误签名一律拒绝，且**不改变状态**。
2. 每台设备**首次**提交的 `previousGeneration` 必须为 `0`，且 `generation > 0`。
3. 后续提交必须 `previousGeneration == 当前已接纳 generation` 且 `generation` 严格更大（允许跳号）。
4. **相同编号 + 字节级相同内容**的重试：返回原接纳结果（`200`，`status:"duplicate"`），不写新状态。
5. 相同编号但内容不同、同代次异内容、过期前代：均为 `409` 冲突，状态不变。
6. 并发请求由数据库写锁串行化，同一后继代次只有一个胜者，败者得到 `409 CONCURRENT_UPDATE`/冲突码，不产生分叉。
7. 携带 `restoresGeneration` 的恢复证明：目标代次必须已为本设备接纳且**早于当前头**，
   摘要必须与该代次记录一致，否则返回对应 `409` 冲突码，状态不变。恢复证明与普通后继
   一样参与并发串行化：并发的普通后继与恢复证明中只有一个能承接当前头。

成功响应：`201`（首次）或 `200`（重试）：

```json
{
  "status": "accepted",
  "deviceId": "sat-alpha",
  "generation": 2,
  "previousGeneration": 1,
  "configSha256": "...",
  "attestationId": "...",
  "acceptedAt": "2026-10-06T16:34:16Z"
}
```

恢复证明的接纳响应额外包含 `"restoresGeneration": <历史代次>`。

### `GET /api/devices/{deviceId}/head`

返回设备当前**唯一**已接纳代次与配置摘要；若当前头是恢复证明，同时返回
`restoresGeneration` 标示其历史恢复来源。服务重启后结果不变。未知设备返回
`404 DEVICE_NOT_FOUND`。

### 稳定错误码

| HTTP | code | 触发条件 |
| --- | --- | --- |
| 400 | `MALFORMED_REQUEST` | 请求字段缺失/类型错误、非 JSON |
| 400 | `INVALID_BASE64` | Base64 无法解码 |
| 400 | `INVALID_JSON_PAYLOAD` | 载荷非 UTF-8 JSON、缺字段、代次非整数、哈希格式错 |
| 401 | `UNKNOWN_KEY_ID` | 部署声明中不存在该 `keyId` |
| 401 | `INVALID_SIGNATURE` | Ed25519 验签失败 |
| 403 | `KEY_NOT_BOUND_TO_DEVICE` | 密钥绑定了其它设备 |
| 409 | `FIRST_PREDECESSOR_NOT_ZERO` | 设备首单前代非 0 |
| 409 | `GENERATION_ZERO` | 新代次为 0 |
| 409 | `GENERATION_NOT_GREATER` | 新代次未严格递增 |
| 409 | `STALE_PREDECESSOR` | 前代不等于当前头（过期/回退/重放） |
| 409 | `ATTESTATION_ID_CONTENT_MISMATCH` | 编号复用但签名内容不同 |
| 409 | `GENERATION_CONTENT_CONFLICT` | 同代次已接纳不同内容 |
| 409 | `RESTORE_SOURCE_NOT_FOUND` | 恢复目标代次未为本设备接纳（或设备尚无历史） |
| 409 | `RESTORE_SOURCE_NOT_EARLIER` | 恢复目标未早于当前头（如指向当前头本身） |
| 409 | `RESTORE_CONFIG_MISMATCH` | 恢复摘要与目标历史代次的记录不符 |
| 409 | `CONCURRENT_UPDATE` | 并发竞争失败（请重新读取 head 后重试） |

所有冲突/鉴权失败都不会推进设备状态。

## 部署声明的公钥

编辑 `deploy/keys.json`（随部署提供，不经过 API 下发）：

```json
{
  "keys": {
    "vendor-sat-alpha-1": {
      "algorithm": "Ed25519",
      "publicKeyBase64": "BASE64(32 字节公钥)",
      "deviceId": "sat-alpha"
    }
  }
}
```

`deviceId` 可省略；填写后该密钥只能为该设备签名。生成密钥：

```bash
python3 -m scripts.keytool generate --key-id vendor-x --device-id sat-x --pretty
```

> 仓库 `deploy/keys.json` 中的密钥仅用于开发/演示（对应种子见 `deploy/dev-seeds.txt`，该文件不入镜像、不提交）。生产环境请替换。

## 运行

本地（无需 Docker）：

```bash
python3 -m app.server                     # 默认 :8080，数据 /data/attestations.db
APP_PORT=9090 DB_PATH=./data/att.db KEYS_PATH=./deploy/keys.json python3 -m app.server
```

Docker Compose：

```bash
cp .env.example .env        # 设置 APP_PORT（宿主机端口）
docker compose up -d --build api
curl -s localhost:${APP_PORT:-8080}/healthz
```

容器内部固定监听 8080；宿主机发布端口由 `APP_PORT` 控制（`${APP_PORT:-8080}:8080`）。
接纳数据保存在命名卷 `attest-data`（`/data`），因此重启后 head 依旧唯一可查。

### 一次性 `verify` 服务

运行代码测试、构建检查（字节码编译）和签名接纳冒烟，结束后**自行退出并以退出码汇总结果**：

```bash
docker compose run --build --rm verify
# 全部通过 -> 退出码 0；任一失败 -> 退出码非 0
```

冒烟在容器内自起一个临时 HTTP 服务，覆盖：健康检查、首次接纳、幂等重试、错误签名/未知密钥拒绝、后继承接、过期前代冲突、以及**重启同一数据库后 head 仍唯一且分叉尝试被拒**。

## 测试

```bash
sh scripts/verify.sh        # = compileall + 全部 unittest + smoke
# 或
python3 -m unittest discover -v -s tests
```

测试包含 RFC 8032 官方向量、与 `cryptography` 库的双向互操作校验、接纳链规则、
同编号/同代次冲突、线程内与**跨进程**并发竞争、以及真实进程 `kill -9` 后的持久化验证。
