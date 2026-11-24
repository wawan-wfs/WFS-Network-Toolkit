Unicode true
!include "MUI2.nsh"
!include "x64.nsh"
!ifndef BIN_DIR
  !define BIN_DIR "../target/x86_64-pc-windows-msvc/release"
!endif
!ifndef GUI_FILE
  !define GUI_FILE "${BIN_DIR}/WFS-Network-Toolkit.exe"
!endif
!ifndef CLI_FILE
  !define CLI_FILE "${BIN_DIR}/wfs-netctl.exe"
!endif
!ifndef READ_ME
  !define READ_ME "../README.md"
!endif
!ifndef HARDWARE_GUIDE
  !define HARDWARE_GUIDE "../docs/HARDWARE_ACCEPTANCE.md"
!endif
!ifndef OUT_FILE
  !define OUT_FILE "../dist/WFS-Network-Toolkit-1.3.0-rc.1-x64-Setup.exe"
!endif
Name "WFS Network Toolkit 1.3.0-rc.1"
OutFile "${OUT_FILE}"
InstallDir "$PROGRAMFILES64\WFS Network Toolkit"
InstallDirRegKey HKLM "Software\WFS\NetworkToolkit\Installer" "Path"
RequestExecutionLevel admin
!define MUI_ICON "../assets/WFS-Network-Toolkit.ico"
!define MUI_UNICON "../assets/WFS-Network-Toolkit.ico"
SetCompressor /SOLID lzma
VIProductVersion "1.3.0.0"
VIAddVersionKey "ProductName" "WFS Network Toolkit"
VIAddVersionKey "FileDescription" "Pemasang WFS Network Toolkit"
VIAddVersionKey "FileVersion" "1.3.0.0"
VIAddVersionKey "LegalCopyright" "© WFS Project"
VIAddVersionKey "CompanyName" "WFS Project"
VIAddVersionKey "ProductVersion" "1.3.0-rc.1"
!define MUI_WELCOMEPAGE_TITLE "WFS Network Toolkit"
!define MUI_WELCOMEPAGE_TEXT "Klik Berikutnya untuk memilih folder instalasi.$\r$\n$\r$\n© WFS Project"
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "Indonesian"

Function .onInit
  ${IfNot} ${IsNativeAMD64}
    MessageBox MB_OK|MB_ICONSTOP "Pemasang ini memerlukan Windows AMD64/x64."
    Abort
  ${EndIf}
  SetRegView 64
  SetShellVarContext all
FunctionEnd

Function un.onInit
  SetRegView 64
  SetShellVarContext all
FunctionEnd

Section "WFS Network Toolkit"
  SetOutPath "$INSTDIR"
  File "${GUI_FILE}"
  File "${CLI_FILE}"
  Delete "$INSTDIR\WebView2Loader.dll"
  Delete "$INSTDIR\WebView2Loader-LICENSE.txt"
  Delete "$INSTDIR\WebView2Loader-NOTICE.txt"
  File "${READ_ME}"
  File "${HARDWARE_GUIDE}"
  WriteRegStr HKLM "Software\WFS\NetworkToolkit\Installer" "Path" "$INSTDIR"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\WFSNetworkToolkit" "DisplayName" "WFS Network Toolkit"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\WFSNetworkToolkit" "DisplayVersion" "1.3.0-rc.1"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\WFSNetworkToolkit" "UninstallString" '"$INSTDIR\Uninstall.exe"'
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\WFSNetworkToolkit" "Publisher" "WFS Project"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\WFSNetworkToolkit" "DisplayIcon" "$INSTDIR\WFS-Network-Toolkit.exe"
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\WFSNetworkToolkit" "NoModify" 1
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\WFSNetworkToolkit" "NoRepair" 1
  WriteUninstaller "$INSTDIR\Uninstall.exe"
  CreateDirectory "$SMPROGRAMS\WFS Project"
  CreateShortCut "$SMPROGRAMS\WFS Project\WFS Network Toolkit.lnk" "$INSTDIR\WFS-Network-Toolkit.exe"
  Delete "$SMPROGRAMS\WFS Network Toolkit.lnk"
SectionEnd

Section "Uninstall"
  ; Keep adapter settings and recovery journals when uninstalling.
  Delete "$SMPROGRAMS\WFS Project\WFS Network Toolkit.lnk"
  RMDir "$SMPROGRAMS\WFS Project"
  Delete "$SMPROGRAMS\WFS Network Toolkit.lnk"
  Delete "$INSTDIR\WFS-Network-Toolkit.exe"
  Delete "$INSTDIR\wfs-netctl.exe"
  Delete "$INSTDIR\README.md"
  Delete "$INSTDIR\HARDWARE_ACCEPTANCE.md"
  Delete "$INSTDIR\Uninstall.exe"
  RMDir "$INSTDIR"
  DeleteRegKey HKLM "Software\WFS\NetworkToolkit\Installer"
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\WFSNetworkToolkit"
SectionEnd
