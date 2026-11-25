#!/bin/bash
# histlens GitHub 发布（GH_TOKEN 走钥匙串）
set -e
REPO="histlens"
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

export GH_TOKEN=$(security find-generic-password -s GH_TOKEN -a tomlen045 -w 2>/dev/null)
[ -z "$GH_TOKEN" ] && echo "NO GH_TOKEN (skip github)" && exit 0

# 建仓（已存在则 422，忽略）
code=$(curl -s -o /tmp/hl_gh.json -w '%{http_code}' -X POST \
  -H "Authorization: token $GH_TOKEN" \
  -H "Accept: application/vnd.github+json" \
  https://api.github.com/user/repos \
  -d '{"name":"histlens","description":"shell history forensics lens: leaked secrets, destructive commands, behavior profile, cross-machine diff - 4 verdicts, zero deps","private":false}')
echo "create: $code $(head -c 150 /tmp/hl_gh.json)"

git remote remove gh 2>/dev/null || true
git remote add gh "https://tomlen045:$GH_TOKEN@github.com/tomlen045/$REPO.git"
export GIT_TERMINAL_PROMPT=0
git push -q -u gh main
echo "pushed (main)"

echo "--- github anonymous readback ---"
echo "api:  $(curl -s -o /dev/null -w '%{http_code}' -m 15 https://api.github.com/repos/tomlen045/$REPO)"
echo "raw:  $(curl -s -o /dev/null -w '%{http_code}' -L -m 15 https://raw.githubusercontent.com/tomlen045/$REPO/main/README.md)"
echo "cdn:  $(curl -s -o /dev/null -w '%{http_code}' -L -m 15 https://gcore.jsdelivr.net/gh/tomlen045/$REPO@main/README.md)"
