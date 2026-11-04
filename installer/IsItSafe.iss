#define MyAppName "IsItSafe"
#ifndef AppVersion
  #define AppVersion "0.1.0"
#endif
#ifndef SourceDir
  #define SourceDir "..\target\release"
#endif

[Setup]
AppId={{36D59620-2666-4F8F-9218-C97B05733690}
AppName={#MyAppName}
AppVersion={#AppVersion}
AppPublisher=IsItSafe
AppPublisherURL=https://github.com/
DefaultDirName={localappdata}\Programs\IsItSafe
DefaultGroupName=IsItSafe
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=..\dist
OutputBaseFilename=IsItSafe-{#AppVersion}-windows-x64-setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\isitsafe-ui.exe
CloseApplications=yes
RestartApplications=no
SetupLogging=yes
VersionInfoVersion={#AppVersion}
VersionInfoCompany=IsItSafe
VersionInfoDescription=IsItSafe Download Safety Checker Installer
VersionInfoProductName=IsItSafe

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"
Name: "autostart"; Description: "Start the download monitor when I sign in"; GroupDescription: "Background protection:"; Flags: checkedonce

[Files]
Source: "{#SourceDir}\isitsafe.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\isitsafe-native-host.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\isitsafe-ui.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\config.example.toml"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\rules\default.yar"; DestDir: "{app}\rules"; Flags: ignoreversion
Source: "..\extension\chromium\*"; DestDir: "{app}\extensions\chromium"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\extension\firefox\*"; DestDir: "{app}\extensions\firefox"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\IsItSafe"; Filename: "{app}\isitsafe-ui.exe"; Comment: "Open the IsItSafe download safety workspace"
Name: "{autodesktop}\IsItSafe"; Filename: "{app}\isitsafe-ui.exe"; Comment: "Open the IsItSafe download safety workspace"; Tasks: desktopicon
Name: "{userstartup}\IsItSafe Monitor"; Filename: "{app}\isitsafe-ui.exe"; Parameters: "--background"; Comment: "Monitor downloads for unsafe content"; Tasks: autostart

[Run]
Filename: "{app}\isitsafe.exe"; Parameters: "init"; Flags: runhidden waituntilterminated; StatusMsg: "Initializing download protection..."
Filename: "{app}\isitsafe-ui.exe"; Description: "Open IsItSafe"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
Type: filesandordirs; Name: "{app}\extensions"
