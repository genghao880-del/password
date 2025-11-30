# Strong-Password

一个基于 Cloudflare Workers + D1 的轻量级密码管理器。

## 亮点
- Cloudflare Workers 无服务器部署，D1 存储
- 本地构建 Tailwind CSS，生产更干净稳定
- 严格 CSP 与安全响应头，默认无缓存
- 支持 2FA（动态码与恢复码）与批量操作
## 安全与部署指南

为确保线上安全，请按以下步骤配置并验证：

- 环境变量（Workers → Settings → Variables）：
	- Secrets：`JWT_SECRET`（≥32位随机字符串）、`TURNSTILE_SECRET`（从 Turnstile 后台获取）。
	- Variables：`CUSTOM_DOMAIN`（你的自定义域名，如 `661985.xyz`）。
- 前端站点密钥：在 `public/index.html` 中将 `CHANGE_ME_SITEKEY` 替换为你的 Turnstile Site Key。
- 人机验证：前端登录/注册请求会附带 `X-CF-Turnstile` 头，后端验证 `TURNSTILE_SECRET`。
- CORS：仅允许你的域名与 Worker 子域来源跨域读取响应。
- 鉴权令牌：后端使用 `env.JWT_SECRET` 进行 HMAC-SHA256 签名与校验，缺失时拒绝颁发与验证。
- 防撞库：登录/注册限流（默认 10 次/分钟），错误 5 次触发 15 分钟临时锁定；成功清除计数。
- SQL 注入：所有数据库操作采用 `prepare(...).bind(...)` 预编译语句，无字符串拼接。

### 验证清单

- 未设置 `JWT_SECRET`：登录/注册应失败（安全失败）。
- 已配置 Turnstile，但未携带 token：返回 403。
- 连续 5 次错误密码：返回 423 临时锁定。
- 非允许来源跨域：浏览器阻止读取响应（无 `Access-Control-Allow-Origin`）。

### 部署命令

 使用 Cloudflare Wrangler v4 部署。

 ### Release Notes
 See `CHANGELOG.md` for a summary of recent changes and deployment context.

 ### Typical Flow
- Configure `[vars]` in `wrangler.toml` (e.g., `CUSTOM_DOMAIN`, `TURNSTILE_SITE_KEY`).
- Set secrets via `wrangler secret put` (`TURNSTILE_SECRET`, `JWT_SECRET`).
- Deploy with `wrangler deploy`.
- Verify `/api/config` returns sitekey/domain; test auth with Turnstile.
npx wrangler deploy
```

### 初始化/导出数据库结构（D1）

```powershell
# 初始化到远端 D1（覆盖请谨慎）
npx wrangler d1 execute password --file=schema.sql --remote

# 查看表结构与索引
npx wrangler d1 execute password --remote --command "SELECT sql FROM sqlite_master WHERE type='table' ORDER BY name;"
npx wrangler d1 execute password --remote --command "SELECT sql FROM sqlite_master WHERE type='index' AND sql IS NOT NULL ORDER BY name;"
```

### 常见问题

- Turnstile 无法获取 token：检查前端是否正确加载脚本、`sitekey` 是否有效；可在网络差时重试执行 `turnstile.execute`。
- 401 未授权：确认请求头有 `Authorization: Bearer <token>` 且 JWT 未过期。
- 429 速率限制：等待窗口重置或降低测试频率；生产环境可按需调整限流阈值。
- 423 临时锁：等待 15 分钟或在后台调整锁定策略。

## 快速开始
- 安装依赖：`npm i`
- 本地预览：`npx wrangler dev`
- 部署：`npx wrangler deploy`

## 环境变量
- `CUSTOM_DOMAIN`：设置自定义域名（例如 `example.com`），用于 CORS/CSP 等逻辑。

## 文档
- 综合指南：`docs/PROJECT_GUIDE.md`
- 贡献指南：`docs/CONTRIBUTING.md`
- 许可证：`docs/LICENSE`

## 展示与访问
- 配置你的域名后访问
- Worker URL 格式：`https://your-worker-name.your-account.workers.dev`

## 贡献
- 欢迎 PR。请提供清晰的提交说明，描述改动与影响。
