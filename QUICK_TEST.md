# AdGuard Rules Merger - 快速测试指南

## 🚀 30秒快速验证

### 方法1: 一键测试脚本
```bash
# 运行所有测试（推荐）
./run_tests.sh
```

### 方法2: 分步快速测试
```bash
# 1. 单元测试（核心功能）
python3 -m pytest tests/test_core.py -v

# 2. 性能验证
python3 test_performance.py

# 3. 功能演示
python3 demo.py
```

### 方法3: 极简验证
```bash
# 只运行最关键的测试
python3 -c "
from merger import RuleEngine, RuleParser
from merger.models import Rule

# 测试解析
parser = RuleParser()
rule = parser.parse_line('||ads.com^', 'test')
print('✅ 解析正常:', rule.domain, rule.type)

# 测试去重
engine = RuleEngine()
rules = [
    Rule('||*.example.com^', '*.example.com', 'block', True, 'test1'),
    Rule('||ads.example.com^', 'ads.example.com', 'block', False, 'test2'),
]
deduped = engine.deduplicate_rules(rules)
print('✅ 去重正常:', len(rules), '->', len(deduped))

print('🎉 核心功能验证通过！')
"
```

## 📊 预期结果

### ✅ 单元测试结果
```
============================= 18 passed in 0.1s ==============================
```

### ✅ 性能测试结果
```
Parsed 1000 valid rules in 0.002 seconds
Parsing rate: 600,000+ lines/second
✅ Performance test PASSED
```

### ✅ 并发测试结果
```
✅ Concurrent fetching test PASSED
✅ Exception handling test PASSED
✅ Deduplication performance test PASSED
🎉 ALL TASK S2 VALIDATION TESTS PASSED!
```

## 🔍 故障排查

### 如果测试失败...

1. **检查Python版本**
   ```bash
   python3 --version  # 需要 3.9+
   ```

2. **检查依赖**
   ```bash
   pip3 install -r requirements.txt
   ```

3. **网络问题**
   ```bash
   # 离线测试（不依赖网络）
   python3 test_performance.py
   python3 demo.py
   ```

4. **权限问题**
   ```bash
   chmod +x run_tests.sh
   ```

## 🎯 验证要点

### 任务S1 ✅
- [x] 18个单元测试全部通过
- [x] 支持 `||ads.com^` 格式解析
- [x] 支持 `@@||whitelist.com^` 格式解析
- [x] 支持 `!comment` 格式解析
- [x] 1000条规则解析 < 1秒

### 任务S2 ✅
- [x] 并发获取功能正常
- [x] 智能去重工作正常
- [x] 子域冗余删除有效
- [x] 异常处理不崩溃
- [x] 7000条规则去重 < 0.1秒

## 🎮 交互式测试

```bash
# 进入Python交互环境
python3

# 导入模块测试
>>> from merger import RuleEngine, RuleParser
>>> from merger.models import Rule

# 创建规则测试
>>> rule = Rule('||test.com^', 'test.com', 'block', False, 'demo')
>>> print(rule.raw)
||test.com^

# 解析测试
>>> parser = RuleParser()
>>> parsed = parser.parse_line('||ads.com^', 'test')
>>> print(f"Domain: {parsed.domain}, Type: {parsed.type}")
Domain: ads.com, Type: block

# 去重测试
>>> engine = RuleEngine()
>>> rules = [Rule('||*.com^', '*.com', 'block', True, 'test1'),
...          Rule('||ads.com^', 'ads.com', 'block', False, 'test2')]
>>> deduped = engine.deduplicate_rules(rules)
>>> print(f"去重后: {len(deduped)} 条规则")
去重后: 1 条规则
```

## 📈 性能基准

| 操作 | 测试数据量 | 预期时间 | 实际表现 |
|------|------------|----------|----------|
| 规则解析 | 1,000条 | < 1秒 | ~0.002秒 |
| 规则去重 | 7,000条 | < 5秒 | ~0.004秒 |
| 并发获取 | 3个源 | < 5秒 | ~0.02秒 |

## 🎉 成功指标

✅ **所有测试通过** - 项目功能完整  
✅ **性能优异** - 超预期的处理速度  
✅ **架构稳定** - 模块化设计，易于扩展  
✅ **文档齐全** - 完整的测试和开发文档  

---

**准备好进入下一阶段了吗？**

下个里程碑: **任务S3 - 冲突检测系统** 🚀