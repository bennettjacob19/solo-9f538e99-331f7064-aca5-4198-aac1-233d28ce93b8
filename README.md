# DNS 值班解析系统（serve-stale 演练）

平台值班场景：内部服务的权威 DNS 失联时，解析器继续为已确认的地址提供解析，
但记录被删除（NXDOMAIN）后绝不把旧地址交给调用方。回源经过不可信网络，
因此每条上游答复都用**共享密钥的 HMAC-SHA256** 认证，伪造的 A 答复无法污染
缓存，伪造的 NXDOMAIN 也无法清除旧记录。

## 组成

| 服务 | 模块 | 端口 | 说明 |
|---|---|---|---|
| `auth` | `app.auth_server` | UDP 5354 | 本地权威端，行为可由网页实时切换 |
| `resolver` | `app.resolver` | UDP 5353 | 缓存/serve-stale UDP 解析器 |
| `web` | `app.web` | HTTP 8000 | FastAPI 操作网页 |

三者通过共享卷上的 SQLite（WAL 模式）协作：`control` 表存权威端行为，
`cache` 表存解析器缓存（**绝对时间戳**），`query_log`/`auth_log` 表供网页展示。

## 运行

```bash
docker compose up --build
# 网页:  http://localhost:8000
# 查询:  dig @127.0.0.1 -p 5353 service.example A
```

无 Docker 的本地运行（等价三进程）：

```bash
pip install -r requirements.txt
DB_PATH=/tmp/dns/app.db AUTH_PORT=15354 python -m app.auth_server &
DB_PATH=/tmp/dns/app.db RESOLVER_PORT=15353 AUTH_PORT=15354 python -m app.resolver &
DB_PATH=/tmp/dns/app.db RESOLVER_PORT=15353 WEB_PORT=8000 python -m app.web &
```

自测（自动拉起三进程，跑全部关键交错，约 3 分钟）：

```bash
python tests/selftest.py
```

## 语义（默认值，可用环境变量调整）

- 成功答复 TTL = **5 秒**（`FRESH_TTL`），缓存命中时 TTL 倒数。
- 过期后重新回源；上游超时（`UPSTREAM_TIMEOUT`=2s）时旧 A 最多沿用 **20 秒**
  （`STALE_WINDOW`），应答 TTL 为剩余可用时长；超过即 **SERVFAIL**。
- **NXDOMAIN 只作 5 秒新鲜缓存，绝不作过期备用**：过期+上游超时 → SERVFAIL。
- 解析器确认 NXDOMAIN 时**立即持久清除旧 A**：此后任何答复都不再含旧 A。
- 每次回源用**独立 socket + 随机事务 ID + 问题匹配**，超时后迟到的旧答复
  无人接收、也不会被错配给后续查询，因此无法复活旧记录。
- 缓存期限以绝对 epoch 存于 SQLite，**重启不延长旧 A 的有效期**
  （窗口继续倒数，不会重新计时）。

## 回源应答认证（HMAC-SHA256）

每次回源（尚未过期、需要向上游取数时）解析器都会：

1. 生成 **128 位随机挑战**（`secrets.token_hex(16)`），放在查询的 additional
   段 TXT `_auth.<域名>` 中；
2. 权威端在答复的 additional 段 TXT 中回显挑战并附带签名：
   `hmac-v1;kid=<id>;challenge=<hex>;sig=<hex>`；
3. `sig = HMAC-SHA256(共享密钥, "DNSAUTH1\n" + 域名 + "\n" + 查询名 + "\n" +
   事务 ID + "\n" + qtype + "\n" + rcode + "\n" + A 地址 + "\n" + TTL +
   "\n" + challenge)`。

解析器用**常量时间比较**校验；以下情况一律视为**回源不可用**，与超时同等处理：

- 没有认证 TXT（`missing`）、格式错误（`malformed`）、kid 未知（`bad-key`）；
- 挑战不匹配（`bad-challenge`，即重放或伪造）；
- HMAC 不匹配（`bad-signature`，即签名后内容被篡改或用错密钥）。

由此保证：

- **只有认证通过的 A 才能刷新缓存**；伪造的 A 既不能写入，也不能延长/替换已有
  记录，只能按原 20 秒窗口继续沿用旧 A，超过即 SERVFAIL；
- **只有认证通过的 NXDOMAIN 才能清除旧 A**；伪造的 NXDOMAIN 不改变缓存；
- 认证失败期间旧 A 的 **绝对 stale 期限不变**，重启也不会重置；
- 伪造答复先到不会阻止随后正确签名的答复被接受（解析器在超时前继续监听）。

挑战每次查询都不同，且签名绑定挑战，因此截获的旧答复无法重放。

### 密钥

- 优先读取环境变量 `DNS_HMAC_KEY`（可选 `DNS_HMAC_KEY_ID`，默认 `k1`）；
- 未设置时，首个启动的进程生成 32 字节随机密钥写入 `HMAC_KEY_FILE`
  （docker compose 中为共享卷上的 `/data/hmac.key`），原子创建、权限 0600；
  auth / resolver / web 三个进程与**每次重启都复用同一密钥**；
- 网页只显示 `kid` 与密钥指纹（SHA-256 前 16 位），**不显示密钥本身**。

### 网页开关

网页"应答签名"可实时切换权威端的行为，便于演练：

- **正确签名**（`ok`）：正常签名；
- **错误签名**（`badsig`）：先对真实内容签名，再篡改 A 地址或 rcode，
  模拟被篡改的答复；
- **缺失签名**（`noauth`）：不带认证 TXT 直接应答。

"发起查询"是经解析器的真实 UDP 查询，结果中展示 `来源`
（`upstream`/`cache-fresh`/`cache-stale`/`none`）与 `应答认证`
（`ok`/`missing`/`bad-signature`/`bad-challenge`/`bad-key`/`malformed`，
缓存命中显示 `—`），日志表也有"认证"列。

网页可切换权威端行为：`a`（可改 IP）/ `nxdomain` / `delay`（延迟应答，默认 3s，
大于上游超时，用于演练迟到应答）/ `timeout`（不应答，模拟权威端失联）。
网页"发起查询"经解析器发真实 DNS 查询，展示实际答复（rcode、应答、TTL）
与来源（`upstream` / `cache-fresh` / `cache-stale` / `none`，由解析器在
additional 段 TXT `_src.<域名>` 中带回），并展示双方日志。

固定域名默认 `service.example`（`FIXED_DOMAIN` 可改）。解析器只服务该域名，
其余名称 REFUSED，非 A 查询返回 NODATA。

## 文件

```
app/common.py        配置 + SQLite 状态面 + 共享密钥加载/持久化
app/message_auth.py  HMAC-SHA256 挑战/签名/校验协议
app/auth_server.py   可控权威端（dnslib 编解码，线程并发，应答签名）
app/resolver.py      缓存/serve-stale 解析器（回源认证）
app/web.py           FastAPI 操作网页
tests/selftest.py    端到端自测（A–J 十组场景）
tests/rogue_upstream.py  自测用伪造上游（篡改/重放/无签名/错误密钥）
Dockerfile / docker-compose.yml / requirements.txt
```
