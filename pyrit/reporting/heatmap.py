"""
===============================================================================
OffSec AI-300 — 热力图可视化
===============================================================================
"""
import pandas as pd
import seaborn as sns
import matplotlib
matplotlib.set_loglevel("warning")
import matplotlib.pyplot as plt

from rich.console import Console

console = Console()


def analyze_and_visualize(all_results, report_title, output_filename):
    """生成热力图分析报告。"""
    if not all_results:
        console.print("[yellow]⚠️ 无结果数据，跳过可视化[/yellow]")
        return

    # 修复中文显示乱码问题
    plt.rcParams["font.sans-serif"] = ["SimHei", "Microsoft YaHei", "DejaVu Sans"]
    plt.rcParams["axes.unicode_minus"] = False

    df = pd.DataFrame(all_results)
    success_matrix = df.groupby(['combo_name', 'case_id'])['status'].apply(
        lambda x: (x == 'SUCCESS').mean()
    ).unstack(fill_value=0)

    plt.figure(figsize=(20, 10))
    sns.heatmap(success_matrix, annot=True, fmt=".1%", cmap="YlGnBu", vmin=0, vmax=1, linewidths=.5)
    plt.title(report_title, fontsize=16, fontweight='bold')
    plt.tight_layout()
    plt.savefig(output_filename, dpi=150)
    console.print(f"[green]✅ 热力图已保存: {output_filename}[/green]")
