# 考试环境离线安装指南

> **最后更新**: 2026-07-19
> **版本**: v3.5
> **关联模块**: pyrit_ai300/ (安装部署)
> **状态**: 已完成

## 适用场景

考试机器无网络连接时，需提前在有网环境准备依赖包。

---

## 安装步骤

### 第一步：有网环境下载依赖

```bash
# 下载 pyrit-ai300 及其所有依赖到本地目录
pip download pyrit-ai300 -d ./wheels
```

### 第二步：将 wheels 目录拷贝到考试机器

```bash
# 通过 U 盘、共享文件夹等方式将 wheels/ 目录拷贝到考试机器
```

### 第三步：考试机器离线安装

```bash
# 离线安装，不访问网络
pip install --no-index --find-links=./wheels pyrit-ai300
```

---

## 注意事项

| 项目 | 说明 |
|------|------|
| **Python 版本** | 考试机器 Python 版本需与下载环境一致（>=3.10） |
| **操作系统** | wheels 与操作系统相关，需同为 Windows 或 Linux |
| **依赖完整性** | `pip download` 会自动包含 `pyrit>=0.14.0` 及其所有传递依赖 |
| **验证安装** | 安装后执行 `ai300 list modules` 确认可用 |

---

## 验证命令

```bash
# 验证 CLI 可用
ai300 list modules

# 验证 PyRIT 依赖正常
python -c "import pyrit; print(pyrit.__version__)"

# 验证载荷加载
python -c "from pyrit_ai300.payloads import PayloadManager; m = PayloadManager(); m.load_data_dir('data/'); print(f'Loaded {len(m.get_all_refs())} refs')"
```

---

## 常见问题

**Q: 提示 `Could not find a version that satisfies the requirement pyrit`？**
A: 检查 `--find-links` 路径是否正确，确保 wheels/ 目录中包含 `pyrit-*.whl` 文件。

**Q: 安装成功但 `import pyrit` 报错？**
A: 可能是 Python 版本不匹配。pyrit-ai300 要求 Python >= 3.10。

**Q: 考试时修改了 payload YAML 需要重新安装吗？**
A: 不需要。YAML 数据文件不在包内，修改后直接生效。
