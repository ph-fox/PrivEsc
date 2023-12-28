@echo off
setlocal
for /F "usebackq delims=" %%a in (`wmic useraccount where 'name^="user"' get sid ^| find "S-"`) do (
    set sid=%%a
)
call :add_reg_keys %sid%
copy /Y C:\PrivEsc\AdminPaint.lnk C:\Users\user\Desktop >nul
reg save HKLM\SYSTEM C:\Windows\Repair\SYSTEM /y >nul
icacls C:\Windows\Repair\SYSTEM /grant user:R >nul
reg save HKLM\SAM C:\Windows\Repair\SAM /y >nul
icacls C:\Windows\Repair\SAM /grant user:R >nul
exit /b
:add_reg_keys
set parsed_sid=%~1
reg add HKEY_USERS\%parsed_sid%\Software\Policies\Microsoft\Windows\Installer /v "AlwaysInstallElevated" /t REG_DWORD /d 1 /f >nul
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v "AlwaysInstallElevated" /t REG_DWORD /d 1 /f >nul
reg add HKEY_USERS\%parsed_sid%\Software\SimonTatham\PuTTY\Sessions\BWP123F42 /v "ProxyUsername" /t REG_SZ /d admin /f >nul
reg add HKEY_USERS\%parsed_sid%\Software\SimonTatham\PuTTY\Sessions\BWP123F42 /v "ProxyPassword" /t REG_SZ /d password123 /f >nul
exit /b
