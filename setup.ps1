$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptDir

$venvDir = Join-Path $scriptDir ".venv"

if (-not (Test-Path $venvDir)) {
    Write-Host "Creating virtual environment in .venv..."
    python -m venv $venvDir
}
else {
    Write-Host "Virtual environment already exists in .venv"
}

$activateScript = Join-Path $venvDir "Scripts\Activate.ps1"
if (-not (Test-Path $activateScript)) {
    Write-Error "Could not find activation script at $activateScript"
    exit 1
}

. $activateScript

Write-Host "Installing dependencies..."
python -m pip install --upgrade pip
pip install -r requirements.txt

Write-Host "Setup complete."
