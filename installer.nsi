Unicode True
!include "LogicLib.nsh"
!include "MUI2.nsh"
Name "CCS Lab Manager"
OutFile "CCS-Lab-Manager-Setup.exe"
InstallDir "$PROGRAMFILES64\CCS Lab Manager"
InstallDirRegKey HKLM "Software\CCSLabManager" "Install"
RequestExecutionLevel admin
SetCompressor /SOLID lzma
!define MUI_ICON "assets\icon.ico"
!define MUI_UNICON "assets\icon.ico"
!define MUI_FINISHPAGE_RUN "$INSTDIR\CCS-Lab-Manager.exe"
!define MUI_FINISHPAGE_RUN_TEXT "Launch CCS Lab Manager"
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"
VIProductVersion "1.3.0.0"
VIAddVersionKey "ProductName" "CCS Lab Manager"
VIAddVersionKey "FileDescription" "CCS Lab Manager Setup"
VIAddVersionKey "FileVersion" "1.3.0"
VIAddVersionKey "CompanyName" "College of Computer Studies"
VIAddVersionKey "LegalCopyright" "College of Computer Studies"
Section "Install"
  SetRegView 64
  SetShellVarContext all
  SetOutPath "$INSTDIR"
  File "stage\CCS-Lab-Manager.exe"
  File "stage\WebView2Loader.dll"
  File "stage\README.txt"
  File "assets\icon.ico"
  WriteUninstaller "$INSTDIR\Uninstall.exe"
  CreateDirectory "$SMPROGRAMS\CCS Lab Manager"
  CreateShortcut "$SMPROGRAMS\CCS Lab Manager\CCS Lab Manager.lnk" "$INSTDIR\CCS-Lab-Manager.exe" "" "$INSTDIR\icon.ico"
  CreateShortcut "$SMPROGRAMS\CCS Lab Manager\CCS Lab Manager (LAN server).lnk" "$INSTDIR\CCS-Lab-Manager.exe" "--lan" "$INSTDIR\icon.ico"
  CreateShortcut "$SMPROGRAMS\CCS Lab Manager\Read me.lnk" "$INSTDIR\README.txt"
  CreateShortcut "$SMPROGRAMS\CCS Lab Manager\Uninstall.lnk" "$INSTDIR\Uninstall.exe"
  CreateShortcut "$DESKTOP\CCS Lab Manager.lnk" "$INSTDIR\CCS-Lab-Manager.exe" "" "$INSTDIR\icon.ico"
  WriteRegStr HKLM "Software\CCSLabManager" "Install" "$INSTDIR"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\CCSLabManager" "DisplayName" "CCS Lab Manager"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\CCSLabManager" "DisplayVersion" "1.3.0"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\CCSLabManager" "Publisher" "College of Computer Studies"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\CCSLabManager" "DisplayIcon" "$INSTDIR\icon.ico"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\CCSLabManager" "UninstallString" '"$INSTDIR\Uninstall.exe"'
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\CCSLabManager" "NoModify" 1
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\CCSLabManager" "NoRepair" 1
  nsExec::Exec 'netsh advfirewall firewall add rule name="CCS Lab Manager (LAN)" dir=in action=allow program="$INSTDIR\CCS-Lab-Manager.exe" enable=yes profile=private,domain'
  ; WebView2 runtime check
  ReadRegStr $0 HKLM "SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}" "pv"
  ReadRegStr $1 HKCU "Software\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}" "pv"
  ${If} $0 == ""
  ${AndIf} $1 == ""
    DetailPrint "Downloading Microsoft Edge WebView2 Runtime..."
    nsExec::ExecToLog 'powershell -NoProfile -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -UseBasicParsing -Uri https://go.microsoft.com/fwlink/p/?LinkId=2124703 -OutFile $$env:TEMP\MicrosoftEdgeWebview2Setup.exe"'
    IfFileExists "$TEMP\MicrosoftEdgeWebview2Setup.exe" +3 0
      MessageBox MB_ICONEXCLAMATION "Could not download the Microsoft Edge WebView2 Runtime. Install it from https://developer.microsoft.com/microsoft-edge/webview2 before running the app."
      Goto done
    ExecWait '"$TEMP\MicrosoftEdgeWebview2Setup.exe" /silent /install'
    Delete "$TEMP\MicrosoftEdgeWebview2Setup.exe"
    done:
  ${EndIf}
SectionEnd
Section "Uninstall"
  SetRegView 64
  SetShellVarContext all
  nsExec::Exec 'netsh advfirewall firewall delete rule name="CCS Lab Manager (LAN)"'
  Delete "$INSTDIR\CCS-Lab-Manager.exe"
  Delete "$INSTDIR\WebView2Loader.dll"
  Delete "$INSTDIR\README.txt"
  Delete "$INSTDIR\icon.ico"
  Delete "$INSTDIR\Uninstall.exe"
  RMDir "$INSTDIR"
  Delete "$SMPROGRAMS\CCS Lab Manager\*.lnk"
  RMDir "$SMPROGRAMS\CCS Lab Manager"
  Delete "$DESKTOP\CCS Lab Manager.lnk"
  DeleteRegKey HKLM "Software\CCSLabManager"
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\CCSLabManager"
  MessageBox MB_ICONINFORMATION "CCS Lab Manager was removed. Your data (ccs_lab.db) was kept in %LOCALAPPDATA%\CCS Lab Manager."
SectionEnd
