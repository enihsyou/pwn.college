# pwn.college API 与 `task init`

本文记录 `scripts/task-init.py` 使用的 pwn.college 自定义 API。接口基址为：

```text
https://pwn.college/pwncollege_api/v1
```

脚本不调用 CTFd 的 `/api/v1`，也不再从 SSH 主机名或 GitHub Tree API 推断题目。
模块列表响应可在本地系统临时目录短期缓存，但缓存只复用 API 的完整 JSON 响应。

## 使用的接口

| 方法 | 路径 | 用途 |
| --- | --- | --- |
| `GET` | `/docker` | 读取当前运行中的 `dojo`、`module`、`challenge` ID |
| `GET` | `/dojos/{dojo}/modules` | 读取指定 dojo 的模块及其 challenge 列表，并按 ID 获取名称 |

相关但不参与 `task init` 的只读接口包括：

| 路径 | 用途 |
| --- | --- |
| `/dojos` | 查询当前用户可见的 dojo |
| `/dojos/{dojo}/{module}/{challenge}/description` | 查询题目描述（有可见性/锁定检查） |
| `/docker/next` | 查询当前模块的下一题 |
| `/users/me` | 查询当前登录用户，可用于单独确认 Token |
| `/workspace` | 查询 Workspace 状态；不带 `service`、`port` 才是纯状态查询 |
| `/dojos/{dojo}/solves` | 查询 dojo 解题记录 |
| `/search?q={query}` | 搜索 dojo、module、challenge |

## 认证与请求头

Token 只从环境变量 `DOJO_ACCESS_TOKEN` 读取。Taskfile 顶层通过 Task 的
`dotenv` 机制加载 `.env`；直接运行脚本时先在当前进程导出该变量。

每个 GET 请求都必须带以下三个请求头，`Content-Type` 必须是精确的
`application/json`（不能省略，也不要追加 `charset`）：

```http
Authorization: Token <DOJO_ACCESS_TOKEN>
Content-Type: application/json
Accept: application/json
```

这里使用 `Token` 而不是 `Bearer`。`Bearer` 在 pwn.college 侧保留给 SSH、Workspace
等内部服务凭据。脚本不会把 Token 放入 URL、生成文件、普通错误信息或日志；API 返回的
错误详情也会做长度限制和 Token 脱敏。

## 模块响应缓存

`/docker` 永远实时请求，不缓存。`/dojos/{dojo}/modules` 的完整成功响应可写入系统
临时目录；文件名由 dojo ID 的 SHA-256 安全区分。缓存包含 schema `version`、dojo ID、
ETag 和完整 `response`，不含认证 Token。

七天内直接使用结构有效的缓存。过期缓存会带原 ETag 发送 `If-None-Match`；收到 `304`
时仅刷新文件 mtime。网络或 HTTP 错误发生时，如果旧缓存仍通过 schema/version 校验，
脚本会发出警告并回退；否则报告错误。损坏或版本不匹配的缓存会被忽略，缓存写入失败
只发出警告，不阻止本次 API 调用。

## 调用示例

以下示例仅展示调用形状，不包含真实凭据：

```bash
curl -sS \
  -H "Authorization: Token $DOJO_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  https://pwn.college/pwncollege_api/v1/docker

curl -sS \
  -H "Authorization: Token $DOJO_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  https://pwn.college/pwncollege_api/v1/dojos/system-security/modules
```

正常的 `/docker` 成功响应包含：

```json
{
  "success": true,
  "dojo": "system-security",
  "module": "race-conditions",
  "challenge": "level-11-1"
}
```

`/dojos/{dojo}/modules` 成功响应的顶层是 `success` 与 `modules`。每个 module 至少
包含 `id`、`name` 和 `challenges`；每个 challenge 至少包含 `id`、`name`。其余的
`description`、`resources`、`unified_items` 等字段不会参与路径匹配。

## 项目数据流与生成路径

```text
DOJO_ACCESS_TOKEN
       |
       v
GET /docker --------------> dojo_id, module_id, challenge_id
       |
       v
GET /dojos/{dojo}/modules -> 精确 ID 匹配 module.name/challenge.name
       |
       v
challenges/{dojo}/{module_id}/{challenge_id}/flag.{py|sh}
```

新文件的前两行固定为（随后才接模板内容）：

```text
# {Module Name} - {Challenge Name}
# https://pwn.college/{dojo}/{module_id}/{challenge_id}
```

URL 和目录名都使用 API 返回的精确 challenge ID。成对的 `-0`/`-1` challenge
各自拥有独立目录，不再合并；若 `flag.{py|sh}` 已存在，脚本直接保留它，不覆盖内容。

## Legacy 路径迁移

一次性脚本 [`scripts/migrate_challenge_paths.py`](../scripts/migrate_challenge_paths.py)
直接读取每个 `challenges/legacy/{dojo}` 的 modules API 响应，默认只输出迁移计划；
确认计划后使用 `python scripts/migrate_challenge_paths.py --apply` 执行。它只移动目标
不存在且能由精确 API ID、API 显示名或文件头 URL 唯一确认的目录；`-0`/`-1` 旧合并目录
和其他冲突、无法映射项会原地保留并报告。

## 错误响应与排查

脚本把 API 失败转换成不含凭据的清晰错误：

- `DOJO_ACCESS_TOKEN` 缺失或为空：先设置环境变量或检查 `.env` 是否被 Task 加载。
- HTTP 错误：报告接口路径和状态码；401/403 通常表示 Token、登录或可见性问题，404
  可能是 dojo/路由/资源不存在。
- 网络或超时：报告无法连接的接口路径和网络原因。
- JSON 或 schema 错误：报告响应不是对象、`success` 不是布尔值、缺少字段或字段类型不符。
- `success: false`：报告 API 的 `error`（例如无活动 challenge），但会脱敏并限制长度。
- module 或 challenge ID 找不到：报告未匹配的精确 ID 以及所属 dojo/module。
