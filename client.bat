@echo off
REM ======================================================
REM SAMSOFT OS - Windows 11 Enhanced Nuclear Optimization
REM Gaming FPS Boost Edition (Target: 60+ FPS smoothness)
REM ======================================================
setlocal enabledelayedexpansion

echo ================================================
echo SAMSOFT OS - Windows 11 Enhanced Nuclear Optimization
echo ================================================
echo WARNING: This will make significant system changes for gaming!
echo Press Ctrl+C within 10 seconds to abort...
ping 127.0.0.1 -n 11 >nul

:: [1/10] Power & Performance Settings
echo [1/10] Configuring Power & Performance for High FPS...
powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c >nul
powercfg /h off >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v DisablePagingExecutive /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v Win32PrioritySeparation /t REG_DWORD /d 38 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v ClearPageFileAtShutdown /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v HwSchMode /t REG_DWORD /d 2 /f >nul

:: [2/10] Windows Update Control
echo [2/10] Configuring Windows Update to Manual...
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v AUOptions /t REG_DWORD /d 2 /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v ScheduledInstallDay /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoRebootWithLoggedOnUsers /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v DODownloadMode /t REG_DWORD /d 0 /f >nul
sc config "wuauserv" start=demand >nul
sc stop "wuauserv" >nul

:: [3/10] Extended Bloatware Removal
echo [3/10] Removing Extended Bloatware...
set "bloat=Microsoft.BingNews Microsoft.BingWeather Microsoft.GamingApp Microsoft.GetHelp Microsoft.Getstarted Microsoft.MicrosoftOfficeHub Microsoft.MicrosoftSolitaireCollection Microsoft.PowerAutomateDesktop Microsoft.Todos Microsoft.Office.OneNote Microsoft.People Microsoft.SkypeApp Microsoft.Teams Microsoft.WindowsAlarms Microsoft.WindowsFeedbackHub Microsoft.WindowsMaps Microsoft.Xbox.TCUI Microsoft.XboxGameOverlay Microsoft.XboxGamingOverlay Microsoft.XboxIdentityProvider Microsoft.XboxSpeechToTextOverlay Microsoft.YourPhone Microsoft.ZuneMusic Microsoft.ZuneVideo Microsoft.MixedReality.Portal Microsoft.WindowsCamera Microsoft.WindowsSoundRecorder Microsoft.Microsoft3DViewer Microsoft.BingSearch Microsoft.WindowsNotepad Microsoft.Paint Microsoft.MSPaint Microsoft.MicrosoftStickyNotes Microsoft.ScreenSketch"
for %%i in (%bloat%) do (
    echo Removing %%i...
    powershell -Command "Get-AppxPackage -Name %%i -AllUsers | Remove-AppxPackage" >nul 2>&1
    powershell -Command "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -Like '%%i' | Remove-AppxProvisionedPackage -Online" >nul 2>&1
)
dism /online /disable-feature /featurename:WorkFolders-Client /NoRestart >nul
dism /online /disable-feature /featurename:Printing-Foundation-Features /NoRestart >nul
dism /online /disable-feature /featurename:FaxServicesClientPackage /NoRestart >nul
dism /online /disable-feature /featurename:VirtualMachinePlatform /NoRestart >nul

:: [4/10] Telemetry & Privacy
echo [4/10] Enhanced Telemetry & Privacy Hardening...
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v AITEnable /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisableInventory /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v DontOfferThroughWUAU /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v DisabledByGroupPolicy /t REG_DWORD /d 1 /f >nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsAccessLocation /t REG_DWORD /d 2 /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsAccessCamera /t REG_DWORD /d 2 /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsAccessMicrophone /t REG_DWORD /d 2 /f >nul

:: [5/10] Cortana & Search
echo [5/10] Disabling Cortana & Optimizing Search...
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortana /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v DisableWebSearch /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v ConnectedSearchUseWeb /t REG_DWORD /d 0 /f >nul

:: [6/10] Gaming Optimizations
echo [6/10] Gaming & Multimedia Optimizations...
reg add "HKCU\System\GameConfigStore" /v GameDVR_Enabled /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\GraphicsDrivers" /v HardwareAcceleratedScheduling /t REG_DWORD /d 1 /f >nul
reg add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v DirectXUserGlobalSettings /t REG_SZ /d "SwapEffectUpgradeEnable=1; VRROptimizeEnable=1;" /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v SystemResponsiveness /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d 8 /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v Priority /t REG_DWORD /d 6 /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v AppCaptureEnabled /t REG_DWORD /d 0 /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v HistoricalCaptureEnabled /t REG_DWORD /d 0 /f >nul
reg add "HKCU\Software\Microsoft\GameBar" /v AllowAutoGameMode /t REG_DWORD /d 1 /f >nul
reg add "HKCU\Software\Microsoft\GameBar" /v AutoGameModeEnabled /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v Enabled /t REG_DWORD /d 0 /f >nul

:: [7/10] Network Optimizations
echo [7/10] Network Stack Optimization...
netsh int tcp set global autotuninglevel=experimental >nul
netsh int tcp set global dca=enabled >nul
netsh int tcp set global netdma=enabled >nul
netsh int tcp set global rss=enabled >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v EnableRSS /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v DisableTaskOffload /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v TcpWindowSize /t REG_DWORD /d 372300 /f >nul
reg add "HKLM\SOFTWARE\Microsoft\MSMQ\TCPIP\Parameters" /v TcpNoDelay /t REG_DWORD /d 1 /f >nul

:: [8/10] Selective Service Optimization
echo [8/10] Selective Service Optimization...
set "safe_services=DiagTrack DmWappushservice diagnosticshub.standardcollector.service DPS WMPNetworkSvc WpcMonSvc RetailDemo UsoSvc MapsBroker WSearch RemoteAccess TabletInputService WbioSrvc"
for %%s in (%safe_services%) do (
    sc stop "%%s" 2>nul
    sc config "%%s" start=disabled >nul
)
echo NOTE: Defender & WiFi services preserved for security.

:: [9/10] Registry & Filesystem Tweaks
echo [9/10] Registry & Filesystem Tweaks...
reg add "HKCU\Control Panel\Desktop" /v MenuShowDelay /t REG_SZ /d 0 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v NtfsDisableLastAccessUpdate /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v LargeSystemCache /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v IRPStackSize /t REG_DWORD /d 30 /f >nul
reg add "HKCU\Control Panel\Desktop" /v AutoEndTasks /t REG_SZ /d 1 /f >nul
reg add "HKCU\Control Panel\Desktop" /v HungAppTimeout /t REG_SZ /d 1000 /f >nul
reg add "HKCU\Control Panel\Desktop" /v WaitToKillAppTimeout /t REG_SZ /d 2000 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v WaitToKillServiceTimeout /t REG_SZ /d 2000 /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f >nul
reg add "HKCU\Control Panel\Desktop\WindowMetrics" /v MinAnimate /t REG_SZ /d 0 /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v VisualFXSetting /t REG_DWORD /d 3 /f >nul

:: [10/10] Final Cleanup
echo [10/10] Final Cleanup...
cleanmgr /sagerun:1 >nul
ipconfig /flushdns >nul
netsh winsock reset >nul
sfc /scannow >nul

echo ================================================
echo SAMSOFT OS - Optimization Complete!
echo System Tuned for Really Fast Performance & 60+ FPS Gaming.
echo.
echo RESTART REQUIRED to apply all changes.
echo.
echo POST-RESTART RECOMMENDATIONS:
echo - Update GPU & chipset drivers manually
echo - Enable XMP/DOCP in BIOS
echo - Enable Above 4G decoding & Resizable BAR
echo - Check Windows Update manually
echo - Re-enable Memory Integrity if security is priority
echo.
pause
