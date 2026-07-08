# 前沿漏洞目录

此目录存储所有前沿 AI 漏洞的 manifest + payloads。

## 添加新漏洞

```bash
# 1. 复制脚手架
cp -r _scaffold my-vuln-name

# 2. 编辑 manifest.yaml（必填项: id, name, status）
# 3. 编辑 payloads.yaml（填充攻击载荷）
# 4. 将 status 改为 "active" → 自动加入攻击管道
```

## 命名规范

建议格式: `{时间窗口}-{漏洞关键词}`
- `2026H2-multimodal-jailbreak`
- `2026H2-think-chain-poison`
- `2026H3-tool-call-confuse`

## 每个目录必须包含

- `manifest.yaml` — 漏洞元数据（唯一必填）
- `payloads.yaml` — Payload 数据

## 生命周期

```
experimental → active → deprecated → retired
```

- `experimental`: 实验阶段，需手动 `--enable-frontier experimental` 启用
- `active`: 正式追踪，自动加入攻击管道
- `deprecated`: 已过时/被修复，保留数据但不执行
- `retired`: 归档保留，完全不加载
