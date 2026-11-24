<#
.SYNOPSIS
    给当前会话 / 当前用户配置代理环境变量，以及 git、npm、pip 的代理。
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\set-env.ps1
    powershell -ExecutionPolicy Bypass -File scripts\set-env.ps1 -Socks 7890 -Persist
    powershell -ExecutionPolicy Bypass -File scripts\set-env.ps1 -Clear
.NOTES
    只影响 HTTP(S) 环境变量与开发工具配置，不动系统 WinINET 设置；
    系统级开关用：python -m localproxy sysproxy on|off
#>
[CmdletBinding()]
param(
    [int]$Http = 7891,
    [int]$Socks = 7890,
    [switch]$Persist,
    [switch]$Clear,
    [switch]$SkipGit,
    [switch]$SkipNpm,
    [switch]$SkipPip
)

$ErrorActionPreference = "Continue"

if ($Clear) {
    foreach ($name in "http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY") {
        Remove-Item "Env:$name" -ErrorAction SilentlyContinue
        if ($Persist) { [Environment]::SetEnvironmentVariable($name, $null, "User") }
    }
    if (-not $SkipGit) {
        git config --global --unset http.proxy 2>$null
        git config --global --unset https.proxy 2>$null
    }
    "已清除代理环境变量（及 git 代理）"
    return
}

$httpUrl = "http://127.0.0.1:$Http"
$socksUrl = "socks5://127.0.0.1:$Socks"

foreach ($pair in @(
    @("http_proxy", $httpUrl), @("https_proxy", $httpUrl), @("all_proxy", $socksUrl),
    @("HTTP_PROXY", $httpUrl), @("HTTPS_PROXY", $httpUrl), @("ALL_PROXY", $socksUrl)
)) {
    Set-Item "Env:$($pair[0])" $pair[1]
    if ($Persist) { [Environment]::SetEnvironmentVariable($pair[0], $pair[1], "User") }
}

if (-not $SkipGit) {
    git config --global http.proxy $httpUrl
    git config --global https.proxy $httpUrl
    "git 代理 -> $httpUrl"
}
if (-not $SkipNpm) {
    npm config set proxy $httpUrl 2>$null | Out-Null
    npm config set https-proxy $httpUrl 2>$null | Out-Null
    "npm 代理 -> $httpUrl"
}
if (-not $SkipPip) {
    $pipIni = Join-Path $env:APPDATA "pip\pip.ini"
    New-Item -ItemType Directory -Force -Path (Split-Path $pipIni) | Out-Null
    @"
[global]
proxy = $httpUrl
"@ | Set-Content -Encoding ascii $pipIni
    "pip 代理 -> $httpUrl（$pipIni）"
}

"`n当前会话："
"  http_proxy  = $env:http_proxy"
"  https_proxy = $env:https_proxy"
"  all_proxy   = $env:all_proxy"
if ($Persist) { "`n已写入用户级环境变量（新开终端生效）。" }
