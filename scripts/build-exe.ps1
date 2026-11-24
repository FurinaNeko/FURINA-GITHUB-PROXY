<#
.SYNOPSIS
    一键打包 dist\FURINA-GITHUB-PROXY.exe（内嵌 assets\app.ico 图标）。
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\build-exe.ps1
#>
[CmdletBinding()]
param([switch]$InstallPyInstaller, [switch]$Clean)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

if (-not (Test-Path "assets\app.ico")) {
    throw "缺少 assets\app.ico，先运行：python tools\make_icon.py"
}

& python -c "import PyInstaller" 2>$null
if ($LASTEXITCODE -ne 0) {
    if (-not $InstallPyInstaller) {
        throw "未安装 PyInstaller。加 -InstallPyInstaller 由脚本安装，或手动 python -m pip install pyinstaller"
    }
    python -m pip install --disable-pip-version-check pyinstaller
}

$args = @("-m", "PyInstaller", "--noconfirm")
if ($Clean) { $args += "--clean" }
$args += "localproxy.spec"
& python @args | Select-Object -Last 6

$exe = Join-Path $root "dist\FURINA-GITHUB-PROXY.exe"
if (-not (Test-Path $exe)) { throw "打包失败，未生成 $exe" }

$info = Get-Item $exe
"`n完成：$($info.FullName)"
"  大小：{0:N0} 字节" -f $info.Length
"  图标：assets\app.ico（已嵌入 exe 资源）"
