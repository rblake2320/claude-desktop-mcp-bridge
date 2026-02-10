#!/bin/bash

# Skill Examples Verification Script
# Checks that our golden-path examples are properly set up

echo "🔍 Verifying Skill Examples Setup"
echo "================================"
echo ""

# Set colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

success=0
total=0

# Function to check if something exists
check_exists() {
    local path=$1
    local description=$2

    ((total++))

    if [ -e "$path" ]; then
        echo -e "✅ ${GREEN}$description${NC}"
        ((success++))
    else
        echo -e "❌ ${RED}$description${NC}"
        echo "   Missing: $path"
    fi
}

# Function to check file content
check_content() {
    local path=$1
    local pattern=$2
    local description=$3

    ((total++))

    if [ -e "$path" ] && grep -q "$pattern" "$path"; then
        echo -e "✅ ${GREEN}$description${NC}"
        ((success++))
    else
        echo -e "❌ ${RED}$description${NC}"
        echo "   File: $path"
        echo "   Pattern: $pattern"
    fi
}

# Base directory
SKILLS_DIR="$HOME/.claude/skills"

echo "📂 Directory Structure"
echo "---------------------"

check_exists "$SKILLS_DIR/verified" "verified/ directory exists"
check_exists "$SKILLS_DIR/untrusted" "untrusted/ directory exists"
check_exists "$SKILLS_DIR/built-in" "built-in/ directory exists"

echo ""
echo "📋 JSON Formatter (VERIFIED)"
echo "----------------------------"

JSON_DIR="$SKILLS_DIR/verified/json-formatter"
check_exists "$JSON_DIR" "json-formatter directory"
check_exists "$JSON_DIR/skill-manifest.json" "skill-manifest.json"
check_exists "$JSON_DIR/skill.ts" "skill.ts"

# Check manifest content
check_content "$JSON_DIR/skill-manifest.json" '"trust_level":\s*"verified"' "trust_level is verified"
check_content "$JSON_DIR/skill-manifest.json" '"name":\s*"json-formatter"' "name is json-formatter"
check_content "$JSON_DIR/skill-manifest.json" '"integrity_hash".*"[a-f0-9]\{64\}"' "integrity_hash is present"

# Check skill implementation
check_content "$JSON_DIR/skill.ts" 'export const name = "json-formatter"' "skill name export"
check_content "$JSON_DIR/skill.ts" 'export async function execute' "execute function"

echo ""
echo "🔗 URL Checker (UNTRUSTED)"
echo "-------------------------"

URL_DIR="$SKILLS_DIR/untrusted/url-checker"
check_exists "$URL_DIR" "url-checker directory"
check_exists "$URL_DIR/skill-manifest.json" "skill-manifest.json"
check_exists "$URL_DIR/skill.ts" "skill.ts"

# Check manifest content
check_content "$URL_DIR/skill-manifest.json" '"trust_level":\s*"untrusted"' "trust_level is untrusted"
check_content "$URL_DIR/skill-manifest.json" '"name":\s*"url-checker"' "name is url-checker"
check_content "$URL_DIR/skill-manifest.json" '"network:fetch"' "requires network permissions"
check_content "$URL_DIR/skill-manifest.json" '"allowed_domains"' "has domain restrictions"

# Check skill implementation
check_content "$URL_DIR/skill.ts" 'export const name = "url-checker"' "skill name export"
check_content "$URL_DIR/skill.ts" 'export async function execute' "execute function"

echo ""
echo "📚 Documentation"
echo "---------------"

check_exists "$SKILLS_DIR/SKILL_EXAMPLES_GUIDE.md" "examples guide documentation"
check_exists "$SKILLS_DIR/test-skill-loading.js" "test script"

echo ""
echo "🔐 Security Validation"
echo "---------------------"

# Check for dangerous patterns in verified skill
((total++))
if ! grep -E "(eval\s*\(|\.exec\s*\(|require\s*\(.*\)|import\s*\()" "$JSON_DIR/skill.ts" >/dev/null 2>&1; then
    echo -e "✅ ${GREEN}JSON formatter has no dangerous patterns${NC}"
    ((success++))
else
    echo -e "❌ ${RED}JSON formatter contains dangerous patterns${NC}"
fi

# Check for network permissions in verified skill
((total++))
if ! grep -q "network:" "$JSON_DIR/skill-manifest.json"; then
    echo -e "✅ ${GREEN}JSON formatter requires no network access${NC}"
    ((success++))
else
    echo -e "❌ ${RED}JSON formatter should not require network access${NC}"
fi

# Check resource limits are appropriate
((total++))
if grep -q '"max_memory_mb":\s*[0-9]' "$JSON_DIR/skill-manifest.json" &&
   grep -q '"max_memory_mb":\s*[0-9]' "$URL_DIR/skill-manifest.json"; then
    echo -e "✅ ${GREEN}Resource limits are defined${NC}"
    ((success++))
else
    echo -e "❌ ${RED}Resource limits missing or invalid${NC}"
fi

echo ""
echo "📊 Summary"
echo "--------"

if [ $success -eq $total ]; then
    echo -e "🎉 ${GREEN}ALL CHECKS PASSED${NC} ($success/$total)"
    echo ""
    echo "✅ Skills are properly configured and ready for testing"
    echo "✅ Run 'node ~/.claude/skills/test-skill-loading.js' to test the lifecycle"
    echo "✅ Both examples follow golden-path patterns"
    exit 0
else
    failed=$((total - success))
    echo -e "⚠️ ${YELLOW}$success/$total checks passed${NC} ($failed failed)"
    echo ""
    echo "🔧 Fix the issues above and run this script again"
    exit 1
fi