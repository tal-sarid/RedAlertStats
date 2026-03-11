$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptDir

$venvDir = Join-Path $scriptDir ".venv"
if (-not (Test-Path $venvDir)) {
    Write-Error "Virtual environment not found. Run .\setup.ps1 first."
    exit 1
}

$activateScript = Join-Path $venvDir "Scripts\Activate.ps1"
if (-not (Test-Path $activateScript)) {
    Write-Error "Could not find activation script at $activateScript"
    exit 1
}

. $activateScript

Write-Host "Starting Flask app..."
python app.py @args
