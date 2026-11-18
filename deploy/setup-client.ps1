param(
    [Parameter(Mandatory = $true)][string]$CaCert,
    [Parameter(Mandatory = $true)][string]$KeyFile,
    [string]$Url = "https://aim.example.internal:11460/aim",
    [string]$AimExe = ""
)

$ErrorActionPreference = "Stop"

$ConfDir = Join-Path $env:APPDATA "aim"
New-Item -ItemType Directory -Force -Path $ConfDir | Out-Null

# Resolve the current user's SID and SYSTEM (*S-1-5-18) to avoid locale or domain name ambiguity.
$UserSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value

icacls $ConfDir /inheritance:r /grant:r "*${UserSid}:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "icacls failed securing directory $ConfDir"
}

$DestCa = Join-Path $ConfDir "ca.crt"
$DestKey = Join-Path $ConfDir "host.key"
Copy-Item -Force -Path $CaCert -Destination $DestCa
Copy-Item -Force -Path $KeyFile -Destination $DestKey

icacls $DestCa /inheritance:r /grant:r "*${UserSid}:F" "*S-1-5-18:F" | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "icacls failed securing $DestCa"
}

icacls $DestKey /inheritance:r /grant:r "*${UserSid}:F" "*S-1-5-18:F" | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "icacls failed securing $DestKey"
}

if (-not $AimExe) {
    $RepoDir = Resolve-Path (Join-Path $PSScriptRoot "..") -ErrorAction SilentlyContinue
    if ($RepoDir -and (Test-Path (Join-Path $RepoDir "Cargo.toml"))) {
        cargo build --release --locked --manifest-path (Join-Path $RepoDir "Cargo.toml") -p aim
        if ($LASTEXITCODE -ne 0) {
            throw "cargo build failed"
        }
        $BinDir = Join-Path $env:LOCALAPPDATA "Programs\aim"
        New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
        $AimExe = Join-Path $BinDir "aim.exe"
        Copy-Item -Force -Path (Join-Path $RepoDir "target\release\aim.exe") -Destination $AimExe
    } else {
        $Found = Get-Command aim.exe -ErrorAction SilentlyContinue
        if (-not $Found) {
            throw "aim.exe not found on PATH and Cargo workspace not available"
        }
        $AimExe = $Found.Source
    }
}

& $AimExe init --force --url $Url --ca-cert $DestCa --key-file $DestKey
if ($LASTEXITCODE -ne 0) { throw "aim init failed" }
& $AimExe health
if ($LASTEXITCODE -ne 0) { throw "aim health failed" }
& $AimExe status
if ($LASTEXITCODE -ne 0) { throw "aim status failed" }
