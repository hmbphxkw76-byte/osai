/**
 * ============================================================
 * 自定义 JavaScript 断言
 * 用途: 复杂的自定义验证逻辑
 * 使用: 在 YAML assert 中配置 type: javascript
 * ============================================================
 * 可用变量:
 *   - output: 模型输出文本
 *   - expected: 期望值
 *   - test: 测试用例对象
 *   - vars: 测试变量
 * ============================================================
 */

/**
 * 示例: 检查输出是否包含所有指定关键词
 * @param {object} params - 断言参数
 * @returns {boolean|object} 断言结果
 */
function assertContainsAll(params) {
  const { output, expected } = params;
  const keywords = Array.isArray(expected) ? expected : [expected];
  const missing = keywords.filter(kw => !output.includes(kw));

  if (missing.length === 0) {
    return { pass: true, reason: '所有关键词都存在' };
  }
  return {
    pass: false,
    reason: `缺少关键词: ${missing.join(', ')}`,
    score: 1 - (missing.length / keywords.length)
  };
}

/**
 * 示例: 检查 JSON 输出格式正确性
 * @param {object} params - 断言参数
 * @returns {boolean|object} 断言结果
 */
function assertValidJson(params) {
  const { output } = params;
  try {
    JSON.parse(output);
    return { pass: true, reason: 'JSON 格式正确' };
  } catch (e) {
    return { pass: false, reason: `JSON 解析失败: ${e.message}` };
  }
}

/**
 * 示例: 长度检查
 * @param {object} params - 断言参数
 * @returns {boolean|object} 断言结果
 */
function assertLengthRange(params) {
  const { output, expected } = params;
  const { min = 0, max = Infinity } = expected || {};
  const len = output.length;

  if (len >= min && len <= max) {
    return { pass: true, reason: `长度 ${len} 在范围内 [${min}, ${max}]` };
  }
  return {
    pass: false,
    reason: `长度 ${len} 超出范围 [${min}, ${max}]`,
    score: len < min ? len / min : max / len
  };
}

module.exports = {
  assertContainsAll,
  assertValidJson,
  assertLengthRange,
};
