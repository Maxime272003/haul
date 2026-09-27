# Construit dist\Haul.exe (un seul fichier, sans console) avec l'environnement .venv.
# Usage : .\scripts\build.ps1
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$python = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path $python)) { throw "Environnement .venv introuvable : voir README.md, section Installation." }

$assets = Join-Path $root "src\haul\assets"
if (-not (Test-Path (Join-Path $assets "haul.ico"))) { & $python (Join-Path $root "scripts\make_icon.py") }

& $python -m PyInstaller --noconfirm --clean --onefile --windowed `
    --name Haul `
    --icon (Join-Path $assets "haul.ico") `
    --add-data "$assets;haul\assets" `
    --collect-all curl_cffi `
    --paths (Join-Path $root "src") `
    --distpath (Join-Path $root "dist") `
    --workpath (Join-Path $root "build") `
    --specpath (Join-Path $root "build") `
    (Join-Path $root "src\haul\__main__.py")
if ($LASTEXITCODE -ne 0) { throw "PyInstaller a échoué (code $LASTEXITCODE)." }
Write-Host "OK : $(Join-Path $root 'dist\Haul.exe')"
