<#
.SYNOPSIS
    在桌面（或指定目录）创建带自定义图标的启动快捷方式。

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\create-shortcut.ps1
    powershell -ExecutionPolicy Bypass -File scripts\create-shortcut.ps1 -Name "本地代理" -Target dist\LocalProxy.exe

.NOTES
    默认用 dist\LocalProxy.exe（已内嵌 assets\app.ico）；
    若还没打包，则回退到 python + run_localproxy.py，图标仍指向 assets\app.ico。
#>
[CmdletBinding()]
param(
    [string]$Name = "本地代理",
    [string]$Target = "",
    [string]$Arguments = "run -c config.json",
    [string]$Icon = "",
    [string]$Location = [Environment]::GetFolderPath("Desktop"),
    [switch]$Remove
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$iconPath = if ($Icon) { $Icon } else { Join-Path $root "assets\app.ico" }
$lnkPath = Join-Path $Location "$Name.lnk"

if ($Remove) {
    if (Test-Path $lnkPath) { Remove-Item $lnkPath -Force; "已删除：$lnkPath" }
    else { "没有找到：$lnkPath" }
    return
}

if (-not (Test-Path $iconPath)) { throw "图标不存在：$iconPath（先跑 tools\make_icon.py）" }

$exe = if ($Target) { $Target } else {
    $built = Join-Path $root "dist\LocalProxy.exe"
    if (Test-Path $built) { $built } else { "" }
}

if ($exe) {
    $exeFull = (Resolve-Path $exe).Path
    $arguments = ""
} else {
    # 未打包：用当前 python 解释器跑源码
    $exeFull = (Get-Command python).Source
    $arguments = "`"$root\run_localproxy.py`" $Arguments"
    Write-Warning "未找到 dist\LocalProxy.exe，回退到源码启动；先跑 scripts\build-exe.ps1 可获得独立 exe。"
}

$shell = New-Object -ComObject WScript.Shell
$lnk = $shell.CreateShortcut($lnkPath)
$lnk.TargetPath = $exeFull
$lnk.Arguments = $arguments
$lnk.WorkingDirectory = $root
$lnk.IconLocation = (Resolve-Path $iconPath).Path
$lnk.Description = "localproxy - 本地 SOCKS5/HTTP 代理（GitHub / HuggingFace 分流）"
$lnk.WindowStyle = 1
$lnk.Save()

"快捷方式：$lnkPath"
"  目标    ：$exeFull $arguments"
"  图标    ：$lnk.IconLocation"
"  工作目录：$root"
