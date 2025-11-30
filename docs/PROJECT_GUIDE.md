# Strong-Password 项目综合指南

该文档整合了部署、数据库初始化、测试与常见问题，面向对外展示与快速上手。

## 概览
- 平台：Cloudflare Workers + D1 数据库
- 前端：原生 JS + 本地构建的 Tailwind CSS
- 部署域名：`661985.xyz`（通过 `CUSTOM_DOMAIN` 环境变量配置）

## 快速开始
- 安装依赖：`npm i`
- 本地预览（需要 Wrangler 登录）：`npx wrangler dev`
- 构建 Tailwind：项目已使用生成好的 `public/tailwind.generated.css`，如需更新请在本地构建后替换该文件。

## 部署
1. 确保 Cloudflare 账号已登录：`npx wrangler login`
2. 设置环境变量（Wrangler `wrangler.toml` 中）：
   - `CUSTOM_DOMAIN = "661985.xyz"`
3. 部署命令：`npx wrangler deploy`
4. Worker 绑定：
   - D1：`DB`（在 `wrangler.toml` 中已配置）

## 数据库初始化（D1）
- 初次部署后，Worker 会在接口访问时自动迁移。也可手动执行：
   - 创建或更新 schema：参考根目录的 `schema.sql`

## 安全与缓存策略
- 严格安全头（CSP、HSTS、X-Frame-Options、Referrer-Policy 等）在 Worker 中统一设置。
- 强制无缓存：`Cache-Control: no-store` 与 ETag、`Clear-Site-Data`；前端使用版本号触发刷新。

## 常见问题
- 刷新后空白：已在前端确保初次加载 `manager.render()`，并通过版本缓存清理脚本避免陈旧资源。
- Tailwind 生产环境警告：已改用本地生成的 CSS 文件，避免使用 CDN 脚本。
- Insights/第三方脚本阻断：CSP 限制外部脚本来源，并在服务端对 `index.html` 做净化。

## 测试
- 基本手动验证：登录/注册、密码 CRUD、导入导出、2FA（动态码与恢复码）。
- 建议：在本地与生产均验证 CSP、CORS、缓存头是否符合预期。

## 贡献
- 提交说明清晰，包含改动范围与影响。
- 优先修改相关文件的最小集，避免无关更改。

## 许可证
- 参见根目录 `LICENSE`。
