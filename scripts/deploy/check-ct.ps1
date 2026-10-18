# Cek versi yang terpasang di CT tanpa SSH: bandingkan build_sha di /ready dengan ujung branch di GitHub.
# Pakai: .\scripts\deploy\check-ct.ps1 [-Url http://172.16.83.208:8010] [-Branch prod/final-dashboard-demo]
param(
    [string]$Url = "http://172.16.83.208:8010",
    [string]$Branch = "prod/final-dashboard-demo"
)
$ErrorActionPreference = "Stop"
$ready = Invoke-RestMethod -Uri "$Url/ready" -TimeoutSec 10
$head = (git ls-remote origin "refs/heads/$Branch").Split("`t")[0]
$tag = git ls-remote --tags origin "release-*" | Where-Object { $_ -match "^$head" } | ForEach-Object { ($_ -split "`t")[1] -replace "refs/tags/|\^\{\}", "" } | Select-Object -Last 1
"ready={0} model={1}" -f $ready.ready, $ready.active_model_version
"terpasang : {0} ({1})" -f $ready.build_sha, $ready.release_tag
"ujung branch: {0} (tag: {1})" -f $head, ($tag ?? "belum ada tag")
if ($ready.build_sha -eq $head) { "STATUS: CT sudah di ujung branch" }
elseif (-not $tag) { "STATUS: menunggu tag release (CI belum selesai/gagal)" }
else { "STATUS: tag ada, CT belum menarik (cron <=5 menit) atau deploy gagal" }
