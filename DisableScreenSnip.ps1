<#	
  .Synopsis
    Disables Snipping Tool, Uninstalls Sketch & Snip, Disable Sketch & Snip Quick Access, Print Screen and Windows-Shift-S hotkey for Current and New Profiles
  .NOTES
	  Created:          March, 2021
	  Created by:       Phil Helmling, @philhelmling
	  Organization:     VMware, Inc.
	  Filename:         DisaleScreenSnip.ps1
	.DESCRIPTION
    Disables Snipping Tool, uninstalls Sketch & Snip, disables Sketch & Snip Quick Access, Print Screen and Windows-Shift-S hotkey for Current and New Profiles
    Requires machine to restart to take effect
    https://github.com/helmlingp/apps_DisableScreenSnip
    
    Install command: powershell.exe -ep bypass -file .\InstallOneDrive.ps1
    Uninstall command: .
    Install Complete: Registry exists - HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\TabletPC\DisableSnippingTool
    
  .EXAMPLE
    powershell.exe -ep bypass -file .\DisaleScreenSnip.ps1

#>

#Disable Snipping Tool
write-host "Disable Snipping Tool"
$key = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\TabletPC"
if(Get-Item -Path $key -ErrorAction Ignore) {$true} else {New-Item -Path $key -ErrorAction SilentlyContinue -Force}
New-ItemProperty -Path $key -Name DisableSnippingTool -PropertyType DWORD -Value 1 -ErrorAction SilentlyContinue -Force

#Disable Sketch & Snip Notifications
write-host "Disable Sketch & Snip Notifications"
$key = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Microsoft.ScreenSketch_8wekyb3d8bbwe!App"
if(Get-Item -Path $key -ErrorAction Ignore) {$true} else {New-Item -Path $key -ErrorAction SilentlyContinue -Force}
New-ItemProperty -Path $key -Name "Enabled" -Type DWord -Value 0 -ErrorAction SilentlyContinue -Force

#Disable PRT-SCN Button as it copies to clipboard
write-host "Disable PRT-SCN Button as it copies to clipboard"
$hexbinary = "00,00,00,00,00,00,00,00,04,00,00,00,2a,e0,37,e0,00,00,37,e0,00,00,54,00,00,00,00,00"
$hexified = $hexbinary.Split(',') | % {"0x$_"}
New-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Keyboard Layout" -Name "Scancode Map" -Type Binary -Value ([byte[]]$hexified) -ErrorAction SilentlyContinue -Force

#The Quick Actions Control Center settings for Pinned and Unpinned items is created on creation of new profile and therefore cannot be added to .Default profile
write-host "add run key"
$keyrun = "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run"
if(Get-Item -Path $keyrun -ErrorAction Ignore){$true}else{New-Item -Path $keyrun -ErrorAction SilentlyContinue -Force}
$keynamerun = "Unpin Screen Snip"
$keyvaluerun = "powershell.exe -Windowstyle Hidden New-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Control Panel\Quick Actions\Control Center\Unpinned' -Name 'Microsoft.QuickAction.ScreenClipping' -Type Binary -Value 0 -ErrorAction SilentlyContinue -Force"
New-ItemProperty -Path $keyrun -Name $keynamerun -Type String -Value $keyvaluerun -ErrorAction SilentlyContinue -Force

#Disable Sketch & Snip Quick Access, Print Screen and Windows-Shift-S hotkey for Current and New Profiles
#Load Default User Hive
<# Reg Load "HKU\DefaultHive" "C:\Users\Default\ntuser.dat"
#Disable Quick Access
$key = "Registry::HKEY_CURRENT_USER\Control Panel\Quick Actions\Control Center\Unpinned"
if(Get-Item -Path $key -ErrorAction Ignore){$true}else{New-Item -Path $key -ErrorAction SilentlyContinue -Force}
New-ItemProperty -Path $key -Name "Microsoft.QuickAction.ScreenClipping" -Type Binary -Value 0 -ErrorAction SilentlyContinue -Force
$key = "Registry::HKEY_USERS\DefaultHive\Control Panel\Quick Actions\Control Center\Unpinned"
if(Get-Item -Path $key -ErrorAction Ignore){$true}else{New-Item -Path $key -ErrorAction SilentlyContinue -Force}
New-ItemProperty -Path $key -Name "Microsoft.QuickAction.ScreenClipping" -Type Binary -Value 0 -ErrorAction SilentlyContinue -Force
$keyrunonce = "Registry::HKEY_USERS\DefaultHive\Software\Microsoft\Windows\CurrentVersion\RunOnce"
if(Get-Item -Path $keyrunonce -ErrorAction Ignore){$true}else{New-Item -Path $keyrunonce -ErrorAction SilentlyContinue -Force}
New-ItemProperty -Path $keyrunonce -Name "DefaultHive Unpinned" -Type String -Value "powershell.exe New-ItemProperty -Path 'Registry::HKEY_USERS\DefaultHive\Control Panel\Quick Actions\Control Center\Unpinned' -Name 'Microsoft.QuickAction.ScreenClipping' -Type Binary -Value 0 -ErrorAction SilentlyContinue -Force"
$key = "Registry::HKEY_USERS\.Default\Control Panel\Quick Actions\Control Center\Unpinned"
if(Get-Item -Path $key -ErrorAction Ignore){$true}else{New-Item -Path $key -ErrorAction SilentlyContinue -Force}
New-ItemProperty -Path $key -Name "Microsoft.QuickAction.ScreenClipping" -Type Binary -Value 0 -ErrorAction SilentlyContinue -Force

$keyrunonce = "Registry::HKEY_USERS\.Default\Software\Microsoft\Windows\CurrentVersion\RunOnce"
if(Get-Item -Path $keyrunonce -ErrorAction Ignore){$true}else{New-Item -Path $keyrunonce -ErrorAction SilentlyContinue -Force}
New-ItemProperty -Path $keyrunonce -Name "dotDefault Unpinned" -Type String -Value "powershell.exe New-ItemProperty -Path 'Registry::HKEY_USERS\.Default\Control Panel\Quick Actions\Control Center\Unpinned' -Name 'Microsoft.QuickAction.ScreenClipping' -Type Binary -Value 0 -ErrorAction SilentlyContinue -Force"

#Disable Print Screen
$key = "Registry::HKEY_CURRENT_USER\Control Panel\Keyboard"
if(Get-Item -Path $key -ErrorAction Ignore){$true}else{New-Item -Path $key -ErrorAction SilentlyContinue -Force}
New-ItemProperty -Path $key -Name "PrintScreenKeyForSnippingEnabled" -Type DWORD -Value 0 -ErrorAction SilentlyContinue -Force
$key = "Registry::HKEY_USERS\DefaultHive\Control Panel\Keyboard"
if(Get-Item -Path $key -ErrorAction Ignore){$true}else{New-Item -Path $key -ErrorAction SilentlyContinue -Force}
New-ItemProperty -Path $key -Name "PrintScreenKeyForSnippingEnabled" -Type DWORD -Value 0 -ErrorAction SilentlyContinue -Force
$key = "Registry::HKEY_USERS\.Default\Control Panel\Keyboard"
if(Get-Item -Path $key -ErrorAction Ignore){$true}else{New-Item -Path $key -ErrorAction SilentlyContinue -Force}
New-ItemProperty -Path $key -Name "PrintScreenKeyForSnippingEnabled" -Type DWORD -Value 0 -ErrorAction SilentlyContinue -Force

#Disable Windows-Shift-S hotkey
$key = "Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
if(Get-Item -Path $key -ErrorAction Ignore) {$true} else{New-Item -Path $key -ErrorAction SilentlyContinue -Force}
New-ItemProperty -Path $key -Name "DisabledHotkeys" -Type String -Value "S" -ErrorAction SilentlyContinue -Force
$key = "Registry::HKEY_USERS\DefaultHive\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
if(Get-Item -Path $key -ErrorAction Ignore) {$true} else {New-Item -Path $key -ErrorAction SilentlyContinue -Force}
New-ItemProperty -Path $key -Name "DisabledHotkeys" -Type String -Value "S" -ErrorAction SilentlyContinue -Force
$key = "Registry::HKEY_USERS\.Default\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
if(Get-Item -Path $key -ErrorAction Ignore) {$true} else {New-Item -Path $key -ErrorAction SilentlyContinue -Force}
New-ItemProperty -Path $key -Name "DisabledHotkeys" -Type String -Value "S" -ErrorAction SilentlyContinue -Force

#Unload Default User Hive
[gc]::Collect()
sleep 10
Reg Unload HKU\DefaultHive
write-host "Unloaded Default User Hive"

$profiles = Get-ChildItem -Path "C:\Users"
foreach ($p in $profiles){ 
    if($p.Name -eq "Public") {
        # Do nothing to the C:\Users\Public folder and the enrolled user profile folder
    } else {
        $profileid = $p.Name
        $profilepath = $p.FullName
        write-host "$profileid $profilepath"
        write-host "Loading Other Profile User Hive"
        reg load HKU\$profileid "$profilepath\ntuser.dat" | Out-Null
        #Disable Quick Access
        $key = "Registry::HKEY_USERS\$profileid\Control Panel\Quick Actions\Control Center\Unpinned";
        if(Get-Item -Path $key -ErrorAction Ignore){$true}else{New-Item -Path $key -ErrorAction SilentlyContinue -Force};
        New-ItemProperty $key -Name "Microsoft.QuickAction.ScreenClipping" -PropertyType Binary -ErrorAction SilentlyContinue -Force;
        #Disable Print Screen
        $key = "Registry::HKEY_USERS\$profileid\Control Panel\Keyboard";
        if(Get-Item -Path $key -ErrorAction Ignore){$true}else{New-Item -Path $key -ErrorAction SilentlyContinue -Force};
        New-ItemProperty -Path $key -Name "PrintScreenKeyForSnippingEnabled" -Type DWORD -Value 0 -ErrorAction SilentlyContinue -Force;
        #Disable Windows-Shift-S hotkey
        $key = "Registry::HKEY_USERS\$profileid\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced";
        if(Get-Item -Path $key -ErrorAction Ignore){$true}else{New-Item -Path $key -ErrorAction SilentlyContinue -Force};
        New-ItemProperty -Path $key -Name "DisabledHotkeys" -Type String -Value "S" -ErrorAction SilentlyContinue -Force;
        
        ### Garbage collection and closing of ntuser.dat ###
        [gc]::Collect()
        sleep 10
        reg unload HKU\$profileid
        write-host "Unloaded Other Profile User Hive $profilesid"
    }
} #>

#Do for Current User
#Disable Quick Access
write-host "Disable Quick Access"
$key = "Registry::HKEY_CURRENT_USER\Control Panel\Quick Actions\Control Center\Unpinned";
if(Get-Item -Path $key -ErrorAction Ignore){$true}else{New-Item -Path $key -ErrorAction SilentlyContinue -Force};
New-ItemProperty $key -Name "Microsoft.QuickAction.ScreenClipping" -PropertyType Binary -ErrorAction SilentlyContinue -Force;
#Disable Print Screen
write-host "Disable Print Screen"
$key = "Registry::HKEY_CURRENT_USER\Control Panel\Keyboard";
if(Get-Item -Path $key -ErrorAction Ignore){$true}else{New-Item -Path $key -ErrorAction SilentlyContinue -Force};
New-ItemProperty -Path $key -Name "PrintScreenKeyForSnippingEnabled" -Type DWORD -Value 0 -ErrorAction SilentlyContinue -Force;
#Disable Windows-Shift-S hotkey
write-host "Disable Windows-Shift-S hotkey"
$key = "Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced";
if(Get-Item -Path $key -ErrorAction Ignore){$true}else{New-Item -Path $key -ErrorAction SilentlyContinue -Force};
New-ItemProperty -Path $key -Name "DisabledHotkeys" -Type String -Value "S" -ErrorAction SilentlyContinue -Force;

# Get each user profile SID and Path to the profile
$UserProfiles = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*" | Where {$_.PSChildName -match "S-1-5-21-(\d+-?){4}$" } | Select-Object @{Name="SID"; Expression={$_.PSChildName}}, @{Name="UserHive";Expression={"$($_.ProfileImagePath)\NTuser.dat"}}

# Add in the .DEFAULT User Profile
$DefaultProfile = "" | Select-Object SID, UserHive
$DefaultProfile.SID = ".DEFAULT"
$DefaultProfile.Userhive = "C:\Users\Public\NTuser.dat"
$UserProfiles += $DefaultProfile

# Loop through each profile on the machine</p>
Foreach ($UserProfile in $UserProfiles) {
    # Load User ntuser.dat if it's not already loaded
    If (($ProfileWasLoaded = Test-Path "Registry::HKEY_USERS\$($UserProfile.SID)") -eq $false) {
        Start-Process -FilePath "CMD.EXE" -ArgumentList "/C REG.EXE LOAD HKU\$($UserProfile.SID) $($UserProfile.UserHive)" -Wait -WindowStyle Hidden
        write-host "loading hive for $($UserProfile.UserHive)"
    }

    #Disable Quick Access
    write-host "Disable Quick Access"
    $key = "Registry::HKEY_USERS\$($UserProfile.SID)\Control Panel\Quick Actions\Control Center\Unpinned";
    if(Get-Item -Path $key -ErrorAction Ignore){$true}else{New-Item -Path $key -ErrorAction SilentlyContinue -Force};
    New-ItemProperty $key -Name "Microsoft.QuickAction.ScreenClipping" -PropertyType Binary -ErrorAction SilentlyContinue -Force;
    #Disable Print Screen
    write-host "Disable Print Screen"
    $key = "Registry::HKEY_USERS\$($UserProfile.SID)\Control Panel\Keyboard";
    if(Get-Item -Path $key -ErrorAction Ignore){$true}else{New-Item -Path $key -ErrorAction SilentlyContinue -Force};
    New-ItemProperty -Path $key -Name "PrintScreenKeyForSnippingEnabled" -Type DWORD -Value 0 -ErrorAction SilentlyContinue -Force;
    #Disable Windows-Shift-S hotkey
    write-host "Disable Windows-Shift-S hotkey"
    $key = "Registry::HKEY_USERS\$($UserProfile.SID)\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced";
    if(Get-Item -Path $key -ErrorAction Ignore){$true}else{New-Item -Path $key -ErrorAction SilentlyContinue -Force};
    New-ItemProperty -Path $key -Name "DisabledHotkeys" -Type String -Value "S" -ErrorAction SilentlyContinue -Force;
    
    # Unload NTuser.dat        
    If ($ProfileWasLoaded -eq $false) {
        [gc]::Collect()
        Start-Sleep 1
        Start-Process -FilePath "CMD.EXE" -ArgumentList "/C REG.EXE UNLOAD HKU\$($UserProfile.SID)" -Wait -WindowStyle Hidden| Out-Null
    }
}

#Uninstall Sketch & Snip app Microsoft.ScreenSketch
Get-AppxPackage -AllUsers "Microsoft.ScreenSketch*" | Remove-AppxPackage -Allusers
