$ErrorActionPreference='Continue'; $PSStyle.OutputRendering='PlainText'; $env:NO_COLOR='1'
$dir = 'D:\Download\dsh mod\dsh-destinywind-computer-user'
Set-Location -LiteralPath $dir
"=== gh auth ===" | Out-File -LiteralPath "$dir\.probe-init.log" -Encoding utf8
gh auth status *>> "$dir\.probe-init.log"
"=== gh user ===" | Out-File -LiteralPath "$dir\.probe-init.log" -Append -Encoding utf8
gh api user --jq '.login' *>> "$dir\.probe-init.log"
"=== git init ===" | Out-File -LiteralPath "$dir\.probe-init.log" -Append -Encoding utf8
git init -b main *>> "$dir\.probe-init.log"
git add -A *>> "$dir\.probe-init.log"
git -c user.name='destinywind' -c user.email='destinywind@users.noreply.github.com' commit -m 'feat: dsh-destinywind-computer-user v1.0.0 (computer use with permission gates)' *>> "$dir\.probe-init.log"
"=== files staged ===" | Out-File -LiteralPath "$dir\.probe-init.log" -Append -Encoding utf8
git ls-files *>> "$dir\.probe-init.log"
"=== done ===" | Out-File -LiteralPath "$dir\.probe-init.log" -Append -Encoding utf8
exit $LASTEXITCODE
