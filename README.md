# Strong-Password

一个基于 Cloudflare Workers + D1 的轻量级密码管理器。

## 亮点
- Cloudflare Workers 无服务器部署，D1 存储
- 本地构建 Tailwind CSS，生产更干净稳定
- 严格 CSP 与安全响应头，默认无缓存
- 支持 2FA（动态码与恢复码）与批量操作

## 快速开始
- 安装依赖：`npm i`
- 本地预览：`npx wrangler dev`
- 部署：`npx wrangler deploy`

## 环境变量
- `CUSTOM_DOMAIN`：设置自定义域名（例如 `661985.xyz`），用于 CORS/CSP 等逻辑。

## 文档
- 综合指南：`docs/PROJECT_GUIDE.md`
- 贡献指南：`docs/CONTRIBUTING.md`
- 许可证：`docs/LICENSE`

## 展示与访问
- 站点：`https://661985.xyz`
- Worker：`https://password.genghao880.workers.dev`

## 贡献
- 欢迎 PR。请提供清晰的提交说明，描述改动与影响。
