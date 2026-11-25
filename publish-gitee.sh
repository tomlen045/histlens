#!/bin/bash
# histlens Gitee 发布脚本（pathlens/freshlens 已验证口径：form urlencode + 先 push 后置公开）
set -e
REPO="histlens"
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

TOKEN=$(cat /Users/len/.hermes/cache/scratch/gitee_token.txt 2>/dev/null)
[ -z "$TOKEN" ] && echo "NO VALID GITEE TOKEN" && exit 1

# 建仓（form urlencode，token 放 body）
code=$(curl -s -o /tmp/hl_create.json -w '%{http_code}' -X POST "https://gitee.com/api/v5/user/repos" \
  --data-urlencode "access_token=$TOKEN" --data-urlencode "name=$REPO" \
  --data-urlencode "description=histlens - shell 历史取证透镜：敏感残留/破坏性命令/习惯画像/跨机对比，4 类判决点名这台机器实际跑过什么" \
  --data-urlencode "private=true")
echo "create: $code $(head -c 120 /tmp/hl_create.json)"

# push（token 内嵌 URL 带用户名段；branch 固定 main）
if [ ! -d .git ]; then
  git init -q -b main 2>/dev/null || git init -q
fi
git add -A
git commit -q -m "histlens v1.0.0: shell history forensics lens, 26/26 selftest green" || echo "nothing to commit"
git branch -M main 2>/dev/null || true
git remote remove origin 2>/dev/null || true
git remote add origin "https://tomlen:$TOKEN@gitee.com/tomlen/$REPO.git"
export GIT_TERMINAL_PROMPT=0
git push -q -u origin main
echo "pushed (main)"

# 置公开（必须带 name 字段；空仓库禁止 PATCH，所以必须在 push 之后）
code=$(curl -s -o /tmp/hl_patch.json -w '%{http_code}' -X PATCH "https://gitee.com/api/v5/repos/tomlen/$REPO" \
  --data-urlencode "access_token=$TOKEN" --data-urlencode "name=$REPO" --data-urlencode "private=false")
echo "public-patch: $code $(head -c 120 /tmp/hl_patch.json)"

# GET 复核 private 字段
echo "api-check: $(curl -s "https://gitee.com/api/v5/repos/tomlen/$REPO?access_token=$TOKEN" | grep -o '"private":[a-z]*' | head -1)"

# 匿名读回验证
echo "--- anonymous readback ---"
echo "page:    $(curl -s -o /dev/null -w '%{http_code}' -L -m 15 https://gitee.com/tomlen/$REPO)"
echo "raw:     $(curl -s -o /dev/null -w '%{http_code}' -L -m 15 https://gitee.com/tomlen/$REPO/raw/main/README.md)"
