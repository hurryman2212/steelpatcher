param()

$ScriptRoot = if ($PSScriptRoot) {
  $PSScriptRoot
} else {
  Split-Path -Parent $MyInvocation.MyCommand.Path
}
$FallbackVersion = "0.1.0"
$TagPattern = "^\d+\.\d+\.\d+(-rc\d+)?$"

function Write-FallbackVersion {
  $PackageInfo = Join-Path $ScriptRoot "PKG-INFO"
  if (Test-Path -LiteralPath $PackageInfo) {
    $VersionLine = Get-Content -LiteralPath $PackageInfo | Where-Object {
      $_.StartsWith("Version: ")
    } | Select-Object -First 1
    if ($VersionLine) {
      Write-Output $VersionLine.Substring(9)
      return
    }
  }
  Write-Output $FallbackVersion
}

if ($args.Count -eq 1 -and $args[0] -in @("-h", "--help")) {
  Write-Output "Usage: generate_version.ps1"
  Write-Output "Print a PEP 440 version derived from the nearest Git version tag."
  exit 0
}
if ($args.Count -ne 0) {
  Write-Error "unknown option: $($args[0])"
  exit 2
}

if (!(Get-Command git -ErrorAction SilentlyContinue)) {
  Write-FallbackVersion
  exit 0
}

& git -C $ScriptRoot rev-parse --is-inside-work-tree *> $null
if ($LASTEXITCODE -ne 0) {
  Write-FallbackVersion
  exit 0
}

$Description = & git -C $ScriptRoot describe --tags --long --abbrev=7 `
  --match "[0-9]*.[0-9]*.[0-9]*" HEAD 2>$null
if ($LASTEXITCODE -ne 0 -or
  $Description -notmatch "^(.+)-(\d+)-g([0-9A-Fa-f]{7,40})$") {
  Write-FallbackVersion
  exit 0
}

$Tag = $Matches[1]
[int]$Distance = $Matches[2]
$Sha = $Matches[3]
if ($Tag -notmatch $TagPattern) {
  Write-FallbackVersion
  exit 0
}

$Base = $Tag.Replace("-rc", "rc")
& git -C $ScriptRoot diff-index --quiet HEAD -- 2>$null
$Dirty = $LASTEXITCODE -ne 0

if ($Distance -eq 0) {
  if ($Dirty) {
    Write-Output "$Base+dirty"
  } else {
    Write-Output $Base
  }
  exit 0
}

if ($Dirty) {
  Write-Output "$Base.post0.dev$Distance+g$Sha.dirty"
} else {
  Write-Output "$Base.post0.dev$Distance+g$Sha"
}
