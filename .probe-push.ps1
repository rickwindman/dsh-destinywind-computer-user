$ErrorActionPreference='Continue'; $PSStyle.OutputRendering='PlainText'; $env:NO_COLOR='1'
$dir = 'D:\Download\dsh mod\dsh-destinywind-computer-user'
Set-Location -LiteralPath $dir
git rm --cached .probe-init.ps1 .probe-init.log *>> "$dir\.probe-init.log"
'---'
Remove-Item -LiteralPath "$dir\.probe-init.ps1" -Force
Remove-Item -LiteralPath "$dir\.probe-init.log" -Force
'.gitignore' | Set-Content -LiteralPath "$dir\.gitignore" -Encoding utf8 -NoNewline
git add -A *>> "$dir\.probe2.log"
git -c user.name='destinywind' -c user.email='destinywind@users.noreply.github.com' commit -m 'chore: remove probe artifacts, add .gitignore' *>> "$dir\.probe2.log"
"=== push ===" | Out-File -LiteralPath "$dir\.probe2.log" -Append -Encoding utf8
gh repo create dsh-destinywind-computer-user --public --source=. --push --description 'Computer Use for DSH: native Cua Driver SDK, permission groups in settings, AI must ask user for any disabled permission (allow-once only)' *>> "$dir\.probe2.log"
exit $LASTEXITCODE
