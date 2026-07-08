# ============================================================
# Python 语义相似度断言
# 用途: 基于语义相似度的断言（而非精确匹配）
# 使用: 在 YAML assert 中配置 type: python
# 依赖: pip install sentence-transformers scikit-learn
# ============================================================

from typing import Dict, Any


def semantic_similarity(output: str, expected: str, threshold: float = 0.7) -> Dict[str, Any]:
    """
    计算输出与期望文本的语义相似度
    参数:
        output: 模型输出文本
        expected: 期望文本
        threshold: 相似度阈值（0-1）
    返回:
        {"pass": bool, "score": float, "reason": str}
    """
    try:
        from sentence_transformers import SentenceTransformer
        from sklearn.metrics.pairwise import cosine_similarity
        import numpy as np

        # 加载轻量级模型
        model = SentenceTransformer('all-MiniLM-L6-v2')

        # 计算嵌入向量
        embeddings = model.encode([output, expected])

        # 计算余弦相似度
        similarity = cosine_similarity([embeddings[0]], [embeddings[1]])[0][0]

        return {
            "pass": bool(similarity >= threshold),
            "score": float(similarity),
            "reason": f"语义相似度: {similarity:.4f}, 阈值: {threshold}"
        }

    except ImportError:
        # 如果未安装依赖，降级为简单的字符串相似度
        from difflib import SequenceMatcher
        similarity = SequenceMatcher(None, output, expected).ratio()
        return {
            "pass": bool(similarity >= threshold),
            "score": float(similarity),
            "reason": f"字符串相似度(降级): {similarity:.4f}, 阈值: {threshold}"
        }


def assert_semantic_similar(params: Dict[str, Any]) -> Dict[str, Any]:
    """
    promptfoo 断言入口函数
    参数:
        params: 包含 output, expected, test, vars 等字段
    """
    output = params.get('output', '')
    expected = params.get('expected', '')
    threshold = params.get('threshold', 0.7)

    return semantic_similarity(output, expected, threshold)


if __name__ == '__main__':
    # 本地测试
    test_params = {
        'output': '北京是中国的首都，有很多著名景点。',
        'expected': '中国的首都是北京，拥有众多名胜古迹。',
        'threshold': 0.6
    }
    result = assert_semantic_similar(test_params)
    print(result)
