# Network routing rules

这个仓库使用两个域名源文件统一生成 ZeroOmega、Shadowrocket 和 OpenClash 规则。

## 日常维护

- 需要直连的普通域名：编辑 `Raw_Direct.txt`
- 需要代理的普通域名：编辑 `Raw_Proxy.txt`
- 精确域名、关键词、CIDR、REJECT 或客户端兼容例外：编辑 `config/special_rules.yaml`

Raw 文件每行只写一个域名，不要添加协议、端口、路径、通配符或客户端规则前缀。例如：

```text
openai.com
claude.ai
```

提交源文件后，GitHub Actions 会验证并更新：

- `AutoProxy.list`
- `MyRules.sgmodule`
- `ToDirect.yaml`
- `ToProxy.yaml`

这四个文件是生成结果，不要直接修改。直接修改后，GitHub Actions 会按照源文件重新生成，手工内容会被覆盖。

## CIDR 和特殊规则

CIDR 写入 `config/special_rules.yaml`：

```yaml
direct_cidr:
  - 17.253.0.0/16

proxy_cidr:
  - 8.8.8.0/24
```

CIDR 会生成到 Shadowrocket 和 OpenClash。AutoProxy 域名列表不生成 CIDR，并会在生成日志中明确提示跳过数量。

规则能力对应关系：

| 类型 | AutoProxy | Shadowrocket | OpenClash |
| --- | --- | --- | --- |
| 域名后缀 | 支持 | 支持 | 支持 |
| 精确域名 | 作为域名匹配输出 | 支持 | 支持 |
| 域名关键词 | 跳过 | 支持 | 支持 |
| IP-CIDR | 跳过 | 支持 | 支持 |
| REJECT | 不适用 | 支持 | 不在本仓库两个路由列表中输出 |

## 冲突保护

生成器会阻止以下问题进入成品文件：

- 无效域名或 CIDR
- 同一域名同时出现在直连和代理后缀中
- 直连、代理 CIDR 网段重叠
- 特殊配置包含未知字段或不支持的格式

父域与子域需要不同策略时，使用 `direct_exact` 或 `proxy_exact`。精确规则会放在后缀规则之前。例如 `apple.com` 直连，但 `push.apple.com` 代理。

OpenClash 的直连、代理规则来自两个独立 provider，主配置必须把 `ToProxy` 放在 `ToDirect` 前。生成器允许 `proxy_exact` 中的精确代理域名覆盖 `Raw_Direct.txt` 中的直连父域；普通直连、代理后缀之间的重叠仍会报错。

## 本地验证

生成文件：

```bash
python3 scripts/generate_rules.py
```

只检查、不修改：

```bash
python3 scripts/generate_rules.py --check
```

生成器只使用 Python 标准库，不需要安装第三方依赖。

完整测试：

```bash
python3 -m unittest discover -s tests -v
```
