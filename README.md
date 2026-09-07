# Free Clash Auto Subscription

一个用于 GitHub Actions 的免费 Clash / Mihomo 订阅聚合模板。

## 功能

- 从 `sources.yaml` 中读取公开订阅源
- 下载 YAML/JSON/纯 URI 文本
- 解析 Clash/Mihomo 节点
- 支持常见 SS / SSR(有限) / VMess / VLESS / Trojan / Hysteria2 / HTTP / SOCKS5
- 自动去重
- 自动规范化节点名称
- 生成：
  - `public/clash.yaml`：当前订阅
  - `public/history/YYYYMMDD.yaml`：历史快照
- GitHub Actions 每 6 小时自动运行
- 可手动 `workflow_dispatch`
- 最终订阅地址：
  `https://raw.githubusercontent.com/<USER>/<REPO>/main/public/clash.yaml`

> 重要：公共免费节点不能保证长期稳定。这个项目的“稳定”来自持续采集、去重和更新，而不是保证某个节点永久可用。

## 1. 创建仓库

把整个项目上传到 GitHub，例如：

```text
free-clash/
├── public/
├── scripts/
├── sources.yaml
├── requirements.txt
└── .github/workflows/update.yml
```

## 2. 添加公开订阅源

编辑 `sources.yaml`：

```yaml
sources:
  - name: source-1
    url: "https://example.com/clash.yaml"
    enabled: true
  - name: source-2
    url: "https://example.com/sub.txt"
    enabled: true
```

只添加你有权使用的公开订阅地址。不要把自己的密码、私有订阅 Token 或账号凭据提交到 GitHub。

## 3. 本地运行

```bash
python -m pip install -r requirements.txt
python scripts/update.py
```

运行完成后：

```text
public/clash.yaml
public/history/20260907.yaml
```

## 4. GitHub Actions

推送后，Actions 会按计划运行。也可以在 GitHub：

`Actions -> Update Clash Subscription -> Run workflow`

## 5. Clash/Mihomo

把以下地址作为订阅：

```text
https://raw.githubusercontent.com/<USER>/<REPO>/main/public/clash.yaml
```

Mihomo 支持 `url-test` 自动测速；本项目生成的配置默认使用 `url-test`，健康检查周期为 300 秒。参见 Mihomo 官方文档：
https://wiki.metacubex.one/en/config/proxy-groups/url-test/

## 6. 关于节点测速

GitHub Actions 默认做“下载、解析、去重、格式检查”，不会假装把节点标成“稳定”。

如果你要做真正的可用性筛选，建议后续在 Actions 中加入 Mihomo Linux 内核进行 `/proxies/<name>/delay` 测试。Mihomo API 提供节点延迟测试接口，但免费节点的大量测试会增加 CI 时间和公共源压力。

## 7. 安全

不要提交：

- 私人订阅 Token
- 账号密码
- SSH 私钥
- Cookie
- 个人代理服务凭据

公共节点本身也不等于可信节点。不要用免费节点传输敏感信息。
