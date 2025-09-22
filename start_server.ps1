# PowerShell script to start Django Enterprise Authentication Server
Write-Host "Starting Django Enterprise Authentication Server..." -ForegroundColor Green
Set-Location "G:\Codding\Developement\Stacks\Django\highlevel-django-authentication-app"
& ".\venv\Scripts\Activate.ps1"
$env:DJANGO_SETTINGS_MODULE = "enterprise_auth.settings.development"
Write-Host "Environment activated. Starting server..." -ForegroundColor Yellow
python manage.py runserver
Read-Host "Press Enter to continue..."