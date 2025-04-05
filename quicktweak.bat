if '%errorlevel%' NEQ '0' (
    set "batchPath=%~f0"
    start "" mshta "javascript:var shell=new ActiveXObject('shell.application');shell.ShellExecute('%batchPath%', '', '', 'runas', 1);close();"
    exit /b
)

@echo off
title !MADE BY LOFINSXDD ON GITHUB 2025!

REM Copyright (c) 2025 lofinsxd

REM Permission is hereby granted, free of charge, to any person obtaining a copy
REM of this software and associated documentation files (the "Software"), to deal
REM in the Software without restriction, including without limitation the rights
REM to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
REM copies of the Software, and to permit persons to whom the Software is
REM furnished to do so, subject to the following conditions:
REM The above copyright notice and this permission notice shall be included in all
REM copies or substantial portions of the Software.
REM THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
REM IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
REM FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
REM AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
REM LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
REM OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
REM SOFTWARE.

echo _______________________________________________________________
echo |                                                             |
echo | 01101001001100QuickTweakCMD10010100010001000110000100001110 |
echo | 1000001100101010100001000010000QuickTweakCMD001101000010111 |
echo | 0110000QuickTweakCMD101101110011011110110111101101111011001 |
echo | 0110111101101111011001000110000101QuickTweakCMD101110011011 |
echo | 011011QuickTweakCMD1101101111011001000110000101101110011011 |
echo | 011011110110111QuickTweakCMD1011001100110000101101110011011 |
echo | 01101QuickTweakCMD11101101111011001011100000101101110011011 |
echo | 0110111101101001011QuickTweakCMD010100010010010010001000111 |
echo |_____________________________________________________________|

echo 1. AUTOMATIC OPTIMIZATION
echo 2. Exit

set /p choice="Choose an option (1-3): "
if not "%choice%"=="1" if not "%choice%"=="2" exit

if "%choice%"=="1" goto :automatic_optimization
if "%choice%"=="2" exit

:automatic_optimization
REM Starting automatic optimization...
timeout /t 1 > nul

REM Running SFC and DISM scan...
sfc /scannow > nul
DISM /Online /Cleanup-Image /RestoreHealth > nul
REM SFC and DISM scans completed!
timeout /t 2 > nul

REM Clearing system logs...
wevtutil qe System /f:text > nul
wevtutil qe Application /f:text > nul
wevtutil cl System > nul
wevtutil cl Application > nul
REM System logs cleared.
timeout /t 2 > nul

REM Clearing temporary files...
del /q /f /s %temp%\* > nul
for /d %%i in (%temp%\*) do rd /s /q %%i > nul
del /q /f /s C:\Windows\Temp\* > nul
for /d %%i in (C:\Windows\Temp\*) do rd /s /q %%i > nul
del /q /f /s C:\Windows\Prefetch\* > nul
for /d %%i in (C:\Windows\Prefetch\*) do rd /s /q %%i > nul
REM Temporary files cleared!
timeout /t 2 > nul

REM Flushing DNS cache...
ipconfig /flushdns > nul
REM DNS cache flushed!
timeout /t 2 > nul

REM Disabling hibernation...
powercfg -h off > nul
REM Hibernation disabled!
timeout /t 2 > nul

REM Removing Telemetry...
REM Adjusting registry settings...
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v ContentDeliveryAllowed /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v OemPreInstalledAppsEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v PreInstalledAppsEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v PreInstalledAppsEverEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SilentInstalledAppsEnabled /t REG_DWORD /d 0 /f
for %%X in (338387 338388 338389 353698) do (
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-%%XEnabled /t REG_DWORD /d 0 /f
)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SystemPaneSuggestionsEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Siuf\Rules" /v NumberOfSIUFInPeriod /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Siuf\Rules" /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Privacy" /v TailoredExperiencesWithDiagnosticDataEnabled /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack" /v Start /t REG_DWORD /d 4 /f
reg add "HKCU\Software\Policies\Microsoft\Windows\DataCollection" /v DisableTailoredExperiencesWithDiagnosticData /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowTaskViewButton /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" /v PeopleBand /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v LongPathsEnabled /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v SystemResponsiveness /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v NetworkThrottlingIndex /t REG_DWORD /d 4294967295 /f
reg add "HKCU\Control Panel\Desktop" /v AutoEndTasks /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v ClearPageFileAtShutdown /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v EnableDeadGWDetect /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v EnableICMPRedirect /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v PerformRouterDiscovery /t REG_DWORD /d 0 /f

REM Disabling telemetry related scheduled tasks...
set tasks=(
    "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser"
    "Microsoft\Windows\Application Experience\ProgramDataUpdater"
    "Microsoft\Windows\Autochk\Proxy"
    "Microsoft\Windows\Customer Experience Improvement Program\Consolidator"
    "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip"
    "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector"
    "Microsoft\Windows\Feedback\Siuf\DmClient"
    "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload"
    "Microsoft\Windows\Windows Error Reporting\QueueReporting"
    "Microsoft\Windows\Application Experience\MareBackup"
    "Microsoft\Windows\Application Experience\StartupAppTask"
    "Microsoft\Windows\Application Experience\PcaPatchDbTask"
    "Microsoft\Windows\Maps\MapsUpdateTask"
)

for %%T in %tasks% do (
    schtasks /Change /TN %%~T /Disable 2>nul
)