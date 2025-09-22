@echo off
echo Starting Django Enterprise Authentication Server...
cd /d "G:\Codding\Developement\Stacks\Django\highlevel-django-authentication-app"
call ".venv\Scripts\activate.bat"
set DJANGO_SETTINGS_MODULE=enterprise_auth.settings.development
echo Environment activated. Starting server...
python manage.py runserver
pause