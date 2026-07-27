# ai300-schemas

AI-300 三项目共享数据契约包。

## 职责

- 定义 `TargetProfile` / `FingerprintData` / `VulnerabilityFinding`
- 定义 `UnifiedFinding` / `Evidence`
- 定义 `PyRITTargetConfig`

## 设计原则

- **零业务依赖**：不依赖任何 recon / attack / eval 业务代码
- **标准库优先**：除测试外不引入第三方依赖
- **向前兼容**：反序列化时自动忽略未知字段

## 安装

```powershell
cd ai300-schemas
pip install -e .
```

## 使用示例

```python
from ai300_schemas import TargetProfile, UnifiedFinding, PyRITTargetConfig

profile = TargetProfile(target="https://example.com")
text = profile.to_json()
restored = TargetProfile.from_json(text)

finding = UnifiedFinding(
    source_tool="garak",
    severity="high",
    title="Jailbreak succeeded",
)
```

## 测试

```powershell
pytest ai300-schemas/tests
```
