@echo off
echo Installing dependencies...
pip install PySide6

echo Compiling MacChanger...
pyinstaller --onefile --windowed --name "MacChanger" --uac-admin main.py

echo.
echo Compilation complete!
echo Check the 'dist' folder for MacChanger.exe
pause