# 配置管理模式

## 文件职责划分

```
.env                      ← 业务选择器（运行时切换，高频变更）
  PLATFORM_SELECTOR         → 攻击模型来源
  SCORER_PLATFORM_SELECTOR  → 评分器来源（可选，不设则复用攻击平台）
  TARGET_PRESET             → 目标场景预设（可选）
  TEMPERATURE / MAX_TOKENS  → 通用参数

configs/platforms.env     ← 平台模型定义（低频变更）
  [OPENAI] / [OLLAMA] / [CUSTOM] / [ANTHROPIC] / [GOOGLE_GEMINI]
  每个节包含：OPENAI_CHAT_ENDPOINT + CHAT_MODEL + SCORER_MODEL + API_KEY

configs/targets.env       ← 目标预设定义（低频变更）
  [TARGET_DEMO_CHAT] / [TARGET_DUAL_AUTH] / ...
  每个节包含：TARGET_URL + TARGET_API_FORMAT + 认证参数
```

## configparser 行尾注释规范

`.env` 风格配置文件中，变量值行尾使用 `# ←必填` / `# 可选` 标记字段重要性，渗透测试者一眼就知道改什么：

```ini
# ═══ HOST ═══
HTTP_BASE  = http://target:8080             # ←必填
HTTPS_BASE = https://ai-api.example.com     # ←必填

# ═══ 认证凭据 ═══
API_KEY    = sk-proj-xxxxxxxx               # ←必填
CSRF_TOKEN = xyz789                         # 可选
```

代码加载时必须开启行尾注释解析，否则 `#` 之后内容会被当作值的一部分：

```python
import io, configparser

config = configparser.ConfigParser(inline_comment_prefixes=('#',))
config.optionxform = lambda o: o            # 保留大小写
with open(path, "r", encoding="utf-8") as f:
    config_string = "[DEFAULT]\n" + f.read()  # configparser 要求 [DEFAULT] 节
config.read_file(io.StringIO(config_string))  # read_string() 不处理行尾注释
```

关键要点：
- `inline_comment_prefixes=('#',)` 必须显式设置（默认 `None`）
- 必须用 `read_file()` 而非 `read_string()`（后者忽略 `inline_comment_prefixes`）
- 注释与值之间至少一个空格，`#` 开头的内容被自动截断
- **安全保证**：满足以上三点后，行尾 `#` 注释内容**不会被读入变量值**，渗透测试时直接改值即可，无需删除注释

## 新增配置节模式

### 新增平台（例：Azure OpenAI）

在 `configs/platforms.env` 中添加：

```ini
[AZURE_OPENAI]
OPENAI_CHAT_ENDPOINT=https://your-resource.openai.azure.com/openai/deployments/gpt-4o
CHAT_MODEL=gpt-4o
SCORER_MODEL=gpt-4o
OPENAI_CHAT_KEY=your-azure-key

[AZURE_OPENAI_SCORER]
OPENAI_CHAT_ENDPOINT=https://your-resource.openai.azure.com/openai/deployments/gpt-4o
SCORER_MODEL=gpt-4o
OPENAI_CHAT_KEY=your-azure-key
```

在 `.env` 中使用：

```ini
PLATFORM_SELECTOR=AZURE_OPENAI
SCORER_PLATFORM_SELECTOR=AZURE_OPENAI_SCORER
```

### 新增目标预设

在 `configs/targets.env` 中添加：

```ini
[TARGET_PROD_SERVER]
TARGET_URL=https://prod.company.com/api/v2/chat
TARGET_API_FORMAT=openai
TARGET_API_KEY=your-key
TARGET_COOKIE=auth_token=xyz
```

在 `.env` 中使用：

```ini
TARGET_PRESET=PROD_SERVER
```

### 新增配置类型（例：代理设置）

当前系统中尚未存在代理功能。如果需要新增，应按以下模式：

新建 `configs/network.env`：

```ini
[PROXY]
HTTP_PROXY=http://proxy.company.com:8080
HTTPS_PROXY=http://proxy.company.com:8080
NO_PROXY=localhost,127.0.0.1,*.internal
```

在 `targets/config.py` 添加加载函数 `load_network_config()`。
在 `.env` 顶层添加选择器 `NETWORK_PROFILE=PROXY`。

## 优先级合并实现

参考 `entrypoint/bootstrap.py` 中的 `_resolve()` 模式：

```python
def _resolve(key: str, default=None):
    """优先级: CLI args > target_preset > default"""
    cli_val = getattr(args, key, None)
    if cli_val and cli_val_is_not_default(cli_val, key):
        return cli_val
    preset_val = target_preset.get(key)
    if preset_val is not None:
        return preset_val
    return default
```

对于布尔型参数，需额外判断默认值语义（`--no-ssl` 的 False 是有意义的设置还是默认值）。

## 环境加载流程

```
1. dotenv.load_dotenv(.env)     → 加载 KEY=VALUE 到 os.environ
2. os.getenv("PLATFORM_SELECTOR") → 读取选择器
3. configparser 读取 configs/platforms.env → 解析 [SECTION]
4. _build_config(section_name)  → 构建攻击/评分器配置字典
5. configparser 读取 configs/targets.env → 解析 [TARGET_xxx]
6. 合并 CLI args + target_preset + defaults
```
