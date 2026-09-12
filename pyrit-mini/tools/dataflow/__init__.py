"""tools/dataflow/ — 数据流完整性验证子包

包含 ARM→Strike→Assess→Report/Evidence 全链路数据流校验组件:
    - models.py   : DataSnapshot/ValidationResult/DataFlowReport 数据模型
    - rules.py    : FIELD_CONTRACTS/TRANSFER_RULES/CROSS_PHASE_RULES
    - format.py   : 报告格式化 (text/json)
    - cli.py      : 命令行入口 + 演示模式
    - validator.py: DataFlowValidator 核心验证器
    - hooks.py    : 流水线 Phase 快照钩子集成

调用方式:
    from tools.dataflow.validator import DataFlowValidator
    from tools.dataflow.hooks import snapshot_hook, validate_and_report

Entry point (pyproject.toml):
    pyrit-dataflow = "tools.dataflow.validator:main"
"""
