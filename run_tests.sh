#!/bin/bash
# AdGuard Rules Merger - 一键测试脚本

set -e  # 遇到错误时退出

echo "🚀 AdGuard Rules Merger - 完整测试套件"
echo "=========================================="

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 测试计数器
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# 测试函数
run_test() {
    local test_name="$1"
    local test_command="$2"
    
    echo -e "\n${YELLOW}📋 $test_name${NC}"
    echo "运行: $test_command"
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    if eval "$test_command"; then
        echo -e "${GREEN}✅ $test_name - PASSED${NC}"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        return 0
    else
        echo -e "${RED}❌ $test_name - FAILED${NC}"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        return 1
    fi
}

# 检查Python环境
echo -e "\n${YELLOW}🔍 检查环境${NC}"
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version)
    echo -e "${GREEN}✅ Python版本: $PYTHON_VERSION${NC}"
else
    echo -e "${RED}❌ Python3未安装${NC}"
    exit 1
fi

# 检查依赖
echo "检查依赖包..."
if python3 -c "import pytest, requests, yaml" &> /dev/null; then
    echo -e "${GREEN}✅ 所有依赖已安装${NC}"
else
    echo -e "${YELLOW}⚠️  安装缺失的依赖...${NC}"
    pip3 install -r requirements.txt
fi

# 运行各类测试
echo -e "\n${YELLOW}🧪 开始测试${NC}"

# 1. 单元测试
run_test "单元测试" "python3 -m pytest tests/test_core.py -v"

# 2. 性能测试
run_test "性能测试" "python3 test_performance.py"

# 3. 并发测试
run_test "并发和异常处理测试" "python3 test_concurrent.py"

# 4. 功能演示
run_test "功能演示" "timeout 30 python3 demo.py"

# 5. 代码质量检查
echo -e "\n${YELLOW}🔍 代码质量检查${NC}"
if command -v flake8 &> /dev/null; then
    run_test "代码风格检查" "flake8 merger/ --max-line-length=100 --ignore=E501,W503"
else
    echo -e "${YELLOW}⚠️  flake8未安装，跳过代码风格检查${NC}"
fi

# 6. 导入测试
run_test "包导入测试" "python3 -c 'from merger import RuleEngine, Rule, RuleParser; print(\"✅ 所有模块导入成功\")'"

# 7. 基本功能验证
run_test "基本功能验证" "python3 -c \"
from merger import RuleEngine
from merger.models import Rule

# 测试去重功能
engine = RuleEngine()
rules = [
    Rule('||*.example.com^', '*.example.com', 'block', True, 'test1'),
    Rule('||ads.example.com^', 'ads.example.com', 'block', False, 'test2'),
    Rule('||other.com^', 'other.com', 'block', False, 'test3'),
]
deduped = engine.deduplicate_rules(rules)
assert len(deduped) == 2, f'Expected 2 rules, got {len(deduped)}'
print('✅ 去重功能正常')
\""