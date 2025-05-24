cls
chcp 65001 >nul 2>&1

@echo off
title !MADE BY CAQQXD ON GITHUB 2025!

REM Copyright (c) 2025 caqqxd

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

echo.     _____________________________________________________________
echo.                                                                  
echo.      01101001001100QuickTweakCMD10010100010001000110000100001110 
echo.      1000001100101010100001000010000QuickTweakCMD001101000010111 
echo.      0110000QuickTweakCMD101101110011011110110111101101111011001 
echo.      0110111101101111011001000110000101QuickTweakCMD101110011011 
echo.      011011QuickTweakCMD1101101111011001000110000101101110011011 
echo.      011011110110111QuickTweakCMD1011001100110000101101110011011 
echo.      01101QuickTweakCMD11101101111011001011100000101101110011011 
echo.      0110111101101001011QuickTweakCMD010100010010010010001000111 
echo.     _____________________________________________________________

echo 1. AUTOMATIC OPTIMIZATION
echo 2. Exit

set /p choice="Choose an option (1-3): "
if not "%choice%"=="1" if not "%choice%"=="2" exit

if "%choice%"=="1" goto :automatic_optimization
if "%choice%"=="2" exit

:automatic_optimization
cls
echo Starting automatic optimization...
timeout /t 3 > nul
cls

echo Running SFC and DISM scan...
sfc /scannow > nul
DISM /Online /Cleanup-Image /RestoreHealth > nul
echo. SFC and DISM scans completed!
timeout /t 5 > nul
cls

echo Clearing system logs...
wevtutil qe System /f:text > nul
wevtutil qe Application /f:text > nul
wevtutil cl System > nul
wevtutil cl Application > nul
echo System logs cleared!
timeout /t 5 > nul
cls

echo Clearing temporary files...
del /q /f /s %temp%\* > nul
for /d %%i in (%temp%\*) do rd /s /q %%i > nul
del /q /f /s C:\Windows\Temp\* > nul
for /d %%i in (C:\Windows\Temp\*) do rd /s /q %%i > nul
del /q /f /s C:\Windows\Prefetch\* > nul
for /d %%i in (C:\Windows\Prefetch\*) do rd /s /q %%i > nul
echo Temporary files cleared!
timeout /t 5 > nul
cls

echo Flushing DNS cache...
ipconfig /flushdns > nul
echo DNS cache flushed!
timeout /t 5 > nul
cls

echo Disabling hibernation...
powercfg -h off > nul
echo Hibernation disabled!
timeout /t 5 > nul
cls

echo Removing Telemetry...
timeout /t 3 > nul
cls
echo Adjusting registry settings...
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v ContentDeliveryAllowed /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v OemPreInstalledAppsEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v PreInstalledAppsEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v PreInstalledAppsEverEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SilentInstalledAppsEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-%%XEnabled /t REG_DWORD /d 0 /f
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
cls
echo Telemetry related registry entries were disabled!
timeout /t 5 > nul

echo Disabling telemetry related scheduled tasks...
for %%T in (
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
    "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask"
    "Microsoft\Windows\Customer Experience Improvement Program\Uploader"
    "Microsoft\Windows\Customer Experience Improvement Program\BthSQM"
    "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip"
    "Microsoft\Windows\Autochk\Proxy"
    "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver"
    "Microsoft\Windows\DiskFootprint\Diagnostics"
    "Microsoft\Windows\Maintenance\WinSAT"
    "Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem"
    "Microsoft\Windows\Windows Error Reporting\WerFaultReporting"
    "Microsoft\Windows\Windows Error Reporting\WMR"
) do (
    schtasks /Change /TN %%~T /Disable 2 
)

echo Disabling telemetry related scheduled tasks successful!
timeout /t 5 > nul
cls

echo Adjust Registry Settings...
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v SystemResponsiveness /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v NetworkThrottlingIndex /t REG_DWORD /d 4294967295 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v Win32PrioritySeparation /t REG_DWORD /d 26 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v PowerThrottlingOff /t REG_DWORD /d 1 /f
reg add "HKCU\Control Panel\Mouse" /v MouseSpeed /t REG_SZ /d 0 /f
reg add "HKCU\Control Panel\Mouse" /v MouseThreshold1 /t REG_SZ /d 0 /f
reg add "HKCU\Control Panel\Mouse" /v MouseThreshold2 /t REG_SZ /d 0 /f
reg add "HKCU\Control Panel\Desktop" /v ForegroundFlashCount /t REG_DWORD /d 0 /f
reg add "HKCU\Control Panel\Desktop" /v ForegroundLockTimeout /t REG_DWORD /d 0 /f
reg add "HKCU\Control Panel\Desktop" /v MenuShowDelay /t REG_DWORD /d 0 /f
reg add "HKCU\Control Panel\Desktop" /v AutoEndTasks /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v EnableDeadGWDetect /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v EnableICMPRedirect /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v PerformRouterDiscovery /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v LongPathsEnabled /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v ClearPageFileAtShutdown /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" /v MouseBufferQueueSize /t REG_DWORD /d 20 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" /v KeyboardBufferQueueSize /t REG_DWORD /d 20 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\kbdhid\Parameters" /v KeyboardBufferQueueSize /t REG_DWORD /d 20 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\mouhid\Parameters" /v MouseBufferQueueSize /t REG_DWORD /d 20 /f

echo Registry settings modified!
timeout /t 5 > nul
cls
echo Disabling Defender!
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableBehaviorMonitoring /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableOnAccessProtection /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableScanOnRealtimeEnable /t REG_DWORD /d 1 /f
sc stop WinDefend
sc config WinDefend start= disabled
sc stop Sense
sc config Sense start= disabled
echo Windows Defender disabled!
timeout /t 5 > nul
cls

echo Deleting Bloatware...
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v AllowGameDVR /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v AppCaptureEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\GameBar" /v ShowGameBarTips /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\GameBar" /v AllowAutoGameMode /t REG_DWORD /d 0 /f
powershell -Command "Get-AppxPackage *OneDrive* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *Xbox* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *3DViewer* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *MixedReality.Portal* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *ZuneMusic* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *ZuneVideo* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *MicrosoftSolitaireCollection* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *People* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *SkypeApp* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *BingWeather* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *BingNews* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *BingSports* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *BingFinance* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *WindowsMaps* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *windowscommunicationsapps* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *YourPhone* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *GetHelp* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *Getstarted* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *WindowsFeedbackHub* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *549981C3F5F10* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *WindowsAlarms* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *WindowsCamera* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *SoundRecorder* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *MicrosoftStickyNotes* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *ScreenSketch* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *PowerAutomateDesktop* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *Whiteboard* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *Todos* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *Microsoft.MicrosoftEdge* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *Spotify* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *Instagram* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *TikTok* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *Disney* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *PrimeVideo* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *Facebook* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *Netflix* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *Messenger* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *Twitter* | Remove-AppxPackage"

for %%T in %tasks% do (
    schtasks /Change /TN %%~T /Disable 2>nul
)

timeout /t 5 > nul
cls
