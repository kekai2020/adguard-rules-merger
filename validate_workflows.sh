#!/bin/bash
# Validate GitHub Actions workflow files

echo "🔍 Validating GitHub Actions Workflows"
echo "======================================="

# Check if required files exist
echo ""
echo "📁 Checking workflow files..."

required_files=(
    ".github/workflows/test.yml"
    ".github/workflows/merge.yml"
    ".github/workflows/release.yml"
)

all_exist=true
for file in "${required_files[@]}"; do
    if [ -f "$file" ]; then
        echo "  ✅ $file"
    else
        echo "  ❌ $file (missing)"
        all_exist=false
    fi
done

if [ "$all_exist" = false ]; then
    echo ""
    echo "❌ Some workflow files are missing!"
    exit 1
fi

# Basic YAML syntax check
echo ""
echo "🔍 Checking YAML syntax..."

for file in "${required_files[@]}"; do
    if python3 -c "import yaml; yaml.safe_load(open('$file'))" 2>/dev/null; then
        echo "  ✅ $file - Valid YAML"
    else
        echo "  ❌ $file - Invalid YAML syntax"
        exit 1
    fi
done

# Check if act is installed for local testing
if command -v act &> /dev/null; then
    echo ""
    echo "🧪 act is installed, you can test workflows locally:"
    echo "  act -j test         # Run test job"
    echo "  act -j merge        # Run merge job"
    echo "  act workflow_dispatch -W .github/workflows/merge.yml  # Manual trigger"
else
    echo ""
    echo "💡 Tip: Install 'act' for local workflow testing:"
    echo "  https://github.com/nektos/act"
fi

# Simulate workflow steps
echo ""
echo "🧪 Simulating workflow steps..."

echo ""
echo "1. Testing Python setup..."
python3 --version

echo ""
echo "2. Testing dependency installation..."
if pip3 install -r requirements.txt --dry-run 2>/dev/null; then
    echo "  ✅ Dependencies can be installed"
else
    echo "  ⚠️  Could not verify dependencies (pip may not support --dry-run)"
fi

echo ""
echo "3. Testing imports..."
python3 -c "from merger import RuleEngine, Rule, RuleParser; print('  ✅ All imports successful')"

echo ""
echo "4. Testing basic functionality..."
python3 -c "
from merger import RuleEngine
from merger.models import Rule

engine = RuleEngine()
rules = [
    Rule('||*.example.com^', '*.example.com', 'block', True, 'test1'),
    Rule('||ads.example.com^', 'ads.example.com', 'block', False, 'test2'),
    Rule('||other.com^', 'other.com', 'block', False, 'test3'),
]
deduped = engine.deduplicate_rules(rules)
assert len(deduped) == 2, f'Expected 2 rules, got {len(deduped)}'
print('  ✅ Basic functionality test passed')
"

echo ""
echo "======================================="
echo "🎉 Workflow validation completed!"
echo ""
echo "Next steps:"
echo "  1. Push to GitHub: git push origin main"
echo "  2. Check Actions tab: https://github.com/yourusername/adguard-rules-merger/actions"
echo "  3. Verify workflows are running correctly"
echo ""
echo "Workflow triggers:"
echo "  - test.yml: On PR/push to main, runs tests"
echo "  - merge.yml: Hourly (cron), manual dispatch, or on config changes"
echo "  - release.yml: Daily at 00:00 UTC, creates releases"