param(
    [Parameter(Mandatory = $true)][string]$Tag,
    [Parameter(Mandatory = $true)][string]$AssetDirectory
)

$ErrorActionPreference = "Stop"
$assetPath = (Resolve-Path -LiteralPath $AssetDirectory).Path
$files = @(Get-ChildItem -LiteralPath $assetPath -File | Where-Object Name -ne "SHA256SUMS")
if ($files.Count -eq 0) { throw "No installer assets found in $assetPath" }

$required = @("obs.exe", "anydesk.exe", "teamlogger.msi", "zoom.exe", "teams.exe", "winrar.exe", "office.exe", "rustdesk.exe")
$missing = @($required | Where-Object { -not (Test-Path -LiteralPath (Join-Path $assetPath $_)) })
if ($missing.Count -gt 0) { throw "Missing required assets: $($missing -join ', ')" }

$sums = foreach ($file in $files) {
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $file.FullName).Hash.ToLowerInvariant()
    "$hash  $($file.Name)"
}
$sumPath = Join-Path $assetPath "SHA256SUMS"
$sums | Set-Content -LiteralPath $sumPath -Encoding ascii

gh release view $Tag *> $null
if ($LASTEXITCODE -eq 0) { throw "Release $Tag already exists; use a new tag or delete the draft." }
gh release create $Tag --title "Installer bundle $Tag" --notes "Verified installer assets used by the toolkit." --draft
$uploadPaths = @($files.FullName) + $sumPath
gh release upload $Tag $uploadPaths
Write-Host "Draft release $Tag created. Review licensing and asset names, then publish it in GitHub."
