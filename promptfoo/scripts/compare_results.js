/**
 * ============================================================
 * 结果对比脚本
 * 用途: 对比两次 promptfoo 评估结果，检测回归
 * 使用: node scripts/compare_results.js <baseline.json> <new.json>
 * ============================================================
 */

const fs = require('fs');
const path = require('path');

// 解析命令行参数
const args = process.argv.slice(2);
if (args.length < 2) {
  console.error('使用方法: node scripts/compare_results.js <baseline.json> <new.json>');
  console.error('示例: node scripts/compare_results.js output/v1_results.json output/v2_results.json');
  process.exit(1);
}

const [baselinePath, newPath] = args;

// 读取结果文件
function loadResults(filePath) {
  try {
    const content = fs.readFileSync(filePath, 'utf-8');
    return JSON.parse(content);
  } catch (e) {
    console.error(`无法读取文件 ${filePath}: ${e.message}`);
    process.exit(1);
  }
}

const baseline = loadResults(baselinePath);
const current = loadResults(newPath);

// 计算通过率统计
function calcStats(results) {
  if (!results.results || !Array.isArray(results.results)) {
    return { total: 0, pass: 0, fail: 0, passRate: 0 };
  }

  let pass = 0;
  let fail = 0;

  for (const result of results.results) {
    if (result.pass === true || (result.score !== undefined && result.score >= 0.5)) {
      pass++;
    } else {
      fail++;
    }
  }

  const total = pass + fail;
  return {
    total,
    pass,
    fail,
    passRate: total > 0 ? (pass / total) * 100 : 0
  };
}

const baselineStats = calcStats(baseline);
const currentStats = calcStats(current);

// 输出对比结果
console.log('='.repeat(60));
console.log('  Promptfoo 结果对比报告');
console.log('='.repeat(60));
console.log(`  基线文件: ${path.basename(baselinePath)}`);
console.log(`  当前文件: ${path.basename(newPath)}`);
console.log('='.repeat(60));
console.log('');

console.log('📊 通过率对比:');
console.log(`  基线: ${baselineStats.pass}/${baselineStats.total} (${baselineStats.passRate.toFixed(2)}%)`);
console.log(`  当前: ${currentStats.pass}/${currentStats.total} (${currentStats.passRate.toFixed(2)}%)`);

const diff = currentStats.passRate - baselineStats.passRate;
const diffStr = diff >= 0 ? `+${diff.toFixed(2)}%` : `${diff.toFixed(2)}%`;
const diffColor = diff >= 0 ? '\x1b[32m' : '\x1b[31m';
console.log(`  变化: ${diffColor}${diffStr}\x1b[0m`);
console.log('');

// 检测回归（新增失败项）
if (baseline.results && current.results) {
  const regressions = [];
  const improvements = [];

  for (let i = 0; i < Math.min(baseline.results.length, current.results.length); i++) {
    const baseResult = baseline.results[i];
    const currResult = current.results[i];

    const basePass = baseResult.pass === true || (baseResult.score !== undefined && baseResult.score >= 0.5);
    const currPass = currResult.pass === true || (currResult.score !== undefined && currResult.score >= 0.5);

    const description = currResult.description || baseResult.description || `Test #${i + 1}`;

    if (basePass && !currPass) {
      regressions.push({ description, baseScore: baseResult.score, currScore: currResult.score });
    } else if (!basePass && currPass) {
      improvements.push({ description, baseScore: baseResult.score, currScore: currResult.score });
    }
  }

  if (regressions.length > 0) {
    console.log('🔴 检测到回归项:');
    for (const reg of regressions) {
      console.log(`  - ${reg.description}`);
      console.log(`    基线分数: ${reg.baseScore} → 当前分数: ${reg.currScore}`);
    }
    console.log('');
  }

  if (improvements.length > 0) {
    console.log('🟢 检测到改善项:');
    for (const imp of improvements) {
      console.log(`  - ${imp.description}`);
      console.log(`    基线分数: ${imp.baseScore} → 当前分数: ${imp.currScore}`);
    }
    console.log('');
  }
}

console.log('='.repeat(60));

// 退出码：有回归则返回 1
process.exit(diff < 0 ? 1 : 0);
