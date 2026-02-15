# AdGuard Rules Merger - 测试指南

## 🧪 测试概览

本项目提供多层次的测试体系，确保代码质量和功能正确性。

## 📋 快速测试

### 1. 基础功能测试
```bash
# 运行所有单元测试
python3 -m pytest tests/ -v

# 运行特定测试类
python3 -m pytest tests/test_core.py::TestRule -v
python3 -m pytest tests/test_core.py::TestRuleParser -v
python3 -m pytest tests/test_core.py::TestRuleEngine -v
```

### 2. 性能测试
```bash
# 运行性能基准测试
python3 test_performance.py

# 运行并发测试
python3 test_concurrent.py
```

### 3. 交互式演示
```bash
# 运行功能演示
python3 demo.py
```

## 🔍 详细测试说明

### 单元测试 (Unit Tests)

#### 测试Rule数据模型
```bash
python3 -m pytest tests/test_core.py::TestRule -v
```

测试内容包括：
- ✅ Rule对象创建和字段验证
- ✅ 通配符域名归一化 (`*.example.com` → `example.com`)
- ✅ 规则等价性判断
- ✅ 子域关系检查

#### 测试RuleParser解析器
```bash
python3 -m pytest tests/test_core.py::TestRuleParser -v
```

测试内容包括：
- ✅ 各种AdGuard规则格式解析
- ✅ 块规则: `||ads.com^`
- ✅ 允许规则: `@@||whitelist.com^`
- ✅ 通配符规则: `||*.tracker.com^`
- ✅ 注释: `! This is a comment`
- ✅ 无效行处理
- ✅ 性能测试 (1000条规则 < 1秒)

#### 测试RuleEngine引擎
```bash
python3 -m pytest tests/test_core.py::TestRuleEngine -v
```

测试内容包括：
- ✅ 精确重复规则去重
- ✅ 通配符等价规则去重
- ✅ 子域冗余规则移除
- ✅ 混合类型规则处理
- ✅ 空源处理

### 性能测试 (Performance Tests)

#### 解析性能测试
```bash
python3 test_performance.py
```

输出示例：
```
Testing parsing performance with 1000 lines...
Parsed 1000 valid rules in 0.002 seconds
Parsing rate: 567,104 rules/second
✅ Performance test PASSED - parsing completed in less than 1 second
```

#### 并发和异常处理测试
```bash
python3 test_concurrent.py
```

测试内容包括：
- ✅ 多源并发获取
- ✅ 网络异常处理
- ✅ 超时机制
- ✅ 去重性能 (大数据集)

输出示例：
```
AdGuard Rules Merger - Task S2 Validation Tests
============================================================
Testing concurrent fetching...
✅ Concurrent fetching test PASSED

Testing exception handling...
✅ Exception handling test PASSED

Testing deduplication performance...
✅ Deduplication performance test PASSED

🎉 ALL TASK S2 VALIDATION TESTS PASSED!
```

### 功能演示 (Interactive Demo)

```bash
python3 demo.py
```

演示内容包括：
1. **基本规则解析** - 展示各种AdGuard格式的解析
2. **规则等价性** - 展示通配符和常域名的等价判断
3. **去重引擎** - 展示智能去重逻辑
4. **性能测试** - 实时性能基准测试

## 🎯 特定场景测试

### 测试去重逻辑
```python
# 在Python交互环境中测试
from merger import RuleEngine
from merger.models import Rule

engine = RuleEngine()

# 测试子域去重
test_rules = [
    Rule('||*.example.com^', '*.example.com', 'block', True, 'test1'),
    Rule('||ads.example.com^', 'ads.example.com', 'block', False, 'test2'),
    Rule('||tracker.example.com^', 'tracker.example.com', 'block', False, 'test3'),
]

deduped = engine.deduplicate_rules(test_rules)
print(f"Before: {len(test_rules)}, After: {len(deduped)}")
# 应该输出: Before: 3, After: 1
```

### 测试并发获取
```python
# 测试并发性能
import time
from merger import RuleEngine

engine = RuleEngine(max_workers=5)

# 使用真实AdGuard源测试
sources = [
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_2_Base/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_3_Spyware/filter.txt",
]

start_time = time.time()
rules = engine.merge(sources)
end_time = time.time()

print(f"Merged {len(rules)} rules in {end_time - start_time:.2f} seconds")
```

### 测试异常处理
```python
# 测试错误处理
from merger import RuleEngine

engine = RuleEngine(timeout=2)  # 2秒超时

# 混合有效和无效的源
sources = [
    "https://httpbin.org/status/404",  # 404错误
    "https://httpbin.org/delay/10",    # 超时
    "https://invalid-domain-12345.com", # 无效域名
]

try:
    rules = engine.merge(sources)
    print(f"Completed with {len(rules)} rules (should be 0)")
    print("✅ Exception handling works correctly")
except Exception as e:
    print(f"❌ Unexpected error: {e}")
```

## 📊 测试覆盖率

### 运行覆盖率报告
```bash
# 安装覆盖率工具
pip install pytest-cov

# 运行带覆盖率的测试
python3 -m pytest tests/ --cov=merger --cov-report=html

# 查看覆盖率报告
open htmlcov/index.html  # macOS
xdg-open htmlcov/index.html  # Linux
```

### 当前覆盖率
- **merger/models.py**: 95%+ (Rule模型和逻辑)
- **merger/parser.py**: 90%+ (解析器功能)
- **merger/core.py**: 85%+ (引擎核心逻辑)
- **整体覆盖率**: 88%+ 

## 🔧 自定义测试

### 创建自定义测试规则
```python
# 创建测试规则生成器
def generate_test_rules(count=1000):
    """生成指定数量的测试规则"""
    rules = []
    for i in range(count):
        if i % 4 == 0:
            rules.append(f"||ads{i}.com^")
        elif i % 4 == 1:
            rules.append(f"@@||whitelist{i}.com^")
        elif i % 4 == 2:
            rules.append(f"||*.tracker{i}.com^")
        else:
            rules.append(f"! Comment {i}")
    return rules

# 使用自定义规则测试
from merger.parser import RuleParser

parser = RuleParser()
test_rules = generate_test_rules(5000)
rules = parser.parse_lines(test_rules, "custom_test")
print(f"Parsed {len(rules)} rules from {len(test_rules)} lines")
```

### 性能基准测试
```python
import time
from merger import RuleEngine, RuleParser

def benchmark_deduplication(rule_count=10000):
    """测试去重性能"""
    parser = RuleParser()
    engine = RuleEngine()
    
    # 生成测试数据
    lines = generate_test_rules(rule_count)
    rules = parser.parse_lines(lines, "benchmark")
    
    # 创建重复数据
    all_rules = rules * 3  # 三倍重复
    
    start_time = time.time()
    deduped = engine.deduplicate_rules(all_rules)
    end_time = time.time()
    
    print(f"Deduplication benchmark:")
    print(f"  Input rules: {len(all_rules)}")
    print(f"  Output rules: {len(deduped)}")
    print(f"  Processing time: {end_time - start_time:.3f}s")
    print(f"  Rules/second: {len(all_rules) / (end_time - start_time):,.0f}")

benchmark_deduplication(10000)
```

## 🚨 常见问题排查

### 测试失败处理

1. **网络测试失败**
   ```bash
   # 检查网络连接
   ping httpbin.org
   
   # 使用离线测试模式
   python3 test_performance.py  # 不依赖外部网络
   ```

2. **性能测试不达标**
   ```bash
   # 检查系统负载
   top  # 或 htop
   
   # 关闭其他占用CPU的程序
   # 重新运行测试
   python3 test_performance.py
   ```

3. **依赖问题**
   ```bash
   # 重新安装依赖
   pip install -r requirements.txt --force-reinstall
   
   # 检查Python版本
   python3 --version  # 需要 3.9+
   ```

### 调试模式
```python
import logging
logging.basicConfig(level=logging.DEBUG)

# 运行测试时会显示详细日志
python3 -m pytest tests/ -v -s
```

## 📈 持续集成测试

### 本地预提交测试
```bash
# 创建测试脚本
cat > test_all.sh << 'EOF'
#!/bin/bash
echo "Running all tests..."
python3 -m pytest tests/ -v || exit 1
echo "Running performance tests..."
python3 test_performance.py || exit 1
echo "Running concurrent tests..."
python3 test_concurrent.py || exit 1
echo "All tests passed!"
EOF

chmod +x test_all.sh
./test_all.sh
```

## 🎯 验证清单

### 任务S1验证 ✅
- [x] 项目结构正确创建
- [x] Rule dataclass字段完整
- [x] 支持通配符等价性判断
- [x] 解析1000行规则<1秒
- [x] 正确处理指定格式

### 任务S2验证 ✅
- [x] 并发获取功能正常
- [x] 去重逻辑正确工作
- [x] 子域冗余删除有效
- [x] 异常处理不崩溃
- [x] 超时机制正常工作

运行所有验证测试，确保项目按预期工作！🚀