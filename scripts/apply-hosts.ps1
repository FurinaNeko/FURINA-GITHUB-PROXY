<#
.SYNOPSIS
    把小酱代理的加速域名写进系统 hosts（需要管理员）。

.DESCRIPTION
    采用带标记的块写入，重复执行不会产生重复行，卸载时只删自己那一段：
        # >>> localproxy accel >>>
        127.0.0.1   github.com
        ...
        # <<< localproxy accel <<<

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\apply-hosts.ps1 -Apply
    powershell -ExecutionPolicy Bypass -File scripts\apply-hosts.ps1 -Remove
#>
[CmdletBinding()]
param(
    [switch]$Apply,
    [switch]$Remove,
    [string]$ListFile = "",
    [string]$Target = "127.0.0.1"
)

$ErrorActionPreference = "Stop"
$Begin = "# >>> localproxy accel >>>"
$End = "# <<< localproxy accel <<<"
$HostsPath = Join-Path $env:SystemRoot "System32\drivers\etc\hosts"

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
    Write-Host "需要管理员权限，正在请求提权…"
    $argList = @(
        "-NoProfile", "-ExecutionPolicy", "Bypass",
        "-File", "`"$PSCommandPath`""
    )
    if ($Apply) { $argList += "-Apply" }
    if ($Remove) { $argList += "-Remove" }
    if ($ListFile) { $argList += @("-ListFile", "`"$ListFile`"") }
    $argList += @("-Target", $Target)
    Start-Process -FilePath "powershell.exe" -ArgumentList $argList -Verb RunAs
    exit 0
}

$defaultHosts = @(
    "github.com", "api.github.com", "codeload.github.com",
    "raw.githubusercontent.com", "gist.githubusercontent.com",
    "objects.githubusercontent.com", "avatars.githubusercontent.com",
    "uploads.github.com", "github.githubassets.com", "collector.github.com",
    "alive.github.com", "pkg-containers.githubusercontent.com",
    "huggingface.co", "cdn-lfs.huggingface.co", "cdn-lfs-us-1.huggingface.co",
    "cdn-lfs-eu-1.huggingface.co", "cas-server.huggingface.co",
    "datasets-server.huggingface.co", "transfer.xethub.hf.co",
    "cas-bridge.xethub.hf.co", "hf.co", "files.pythonhosted.org",
    "registry.npmjs.org"
)

if ($ListFile -and (Test-Path $ListFile)) {
    $domains = Get-Content -LiteralPath $ListFile -Encoding UTF8 |
        Where-Object { $_ -and -not $_.StartsWith("#") } |
        ForEach-Object { ($_ -split '\s+')[0] }
} else {
    $domains = $defaultHosts
}
$domains = $domains | Where-Object { $_ } | Select-Object -Unique

# 备份（只备份一次，避免覆盖最初的原始文件）
$backup = "$HostsPath.localproxy.bak"
if (-not (Test-Path $backup)) {
    Copy-Item -LiteralPath $HostsPath -Destination $backup -Force
    Write-Host "已备份原始 hosts -> $backup"
}

$lines = Get-Content -LiteralPath $HostsPath -Encoding UTF8
$kept = New-Object System.Collections.Generic.List[string]
$inside = $false
foreach ($line in $lines) {
    if ($line.Trim() -eq $Begin) { $inside = $true; continue }
    if ($line.Trim() -eq $End) { $inside = $false; continue }
    if (-not $inside) { $kept.Add($line) }
}

for ($i = $kept.Count - 1; $i -ge 0; $i--) {
    if ([string]::IsNullOrWhiteSpace($kept[$i]) -and $i -ge $kept.Count - 2) { $kept.RemoveAt($i) }
}

if (-not $Remove) {
    $kept.Add("")
    $kept.Add($Begin)
    foreach ($domain in $domains) {
        $kept.Add(("{0}`t{1}" -f $Target, $domain))
    }
    $kept.Add($End)
}

$content = ($kept -join "`r`n").TrimEnd() + "`r`n"
Set-Content -LiteralPath $HostsPath -Value $content -Encoding ASCII -Force

if ($Remove) {
    Write-Host "已从 hosts 移除小酱代理条目（域名恢复为系统解析）"
} else {
    Write-Host ("已写入 {0} 个域名 -> {1}" -f $domains.Count, $Target)
    Write-Host "记得启动小酱代理，否则这些域名会连不上（卸载时会自动清理）"
}

ipconfig /flushdns | Out-Null
Write-Host "DNS 缓存已刷新"
Start-Sleep -Seconds 2
