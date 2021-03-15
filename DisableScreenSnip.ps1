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
    
    https://github.com/helmlingp/apps_DisableScreenSnip
    
    Install command: powershell.exe -ep bypass -file .\InstallOneDrive.ps1
    Uninstall command: .
    Install Complete: Registry exists - HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\TabletPC\DisableSnippingTool
    
  .EXAMPLE
    powershell.exe -ep bypass -file .\DisaleScreenSnip.ps1

#>

#Disable Snipping Tool
New-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\TabletPC" -ErrorAction SilentlyContinue -Force
New-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\TabletPC" -Name DisableSnippingTool -PropertyType DWORD -Value 1 -ErrorAction SilentlyContinue -Force

#Disable Sketch & Snip Notifications
New-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Microsoft.ScreenSketch_8wekyb3d8bbwe!App" -ErrorAction SilentlyContinue -Force
New-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Microsoft.ScreenSketch_8wekyb3d8bbwe!App" -Name "Enabled" -Type DWord -Value 0 -ErrorAction SilentlyContinue -Force

#Disable Sketch & Snip Quick Access, Print Screen and Windows-Shift-S hotkey for Current and New Profiles
#Load Default User Hive
Reg Load "HKU\DefaultHive" "C:\Users\Default\NTUser.dat"
#Quick Access
New-ItemProperty -Path "Registry::HKEY_CURRENT_USER\Control Panel\Quick Actions\Control Center" -Name "Unpinned Microsoft.QuickAction.ScreenClipping" -Type REG_NONE -Value 0 -ErrorAction SilentlyContinue -Force
New-ItemProperty -Path "HKUDefaultHive:\DefaultHive\Control Panel\Quick Actions\Control Center" -Name "Unpinned Microsoft.QuickAction.ScreenClipping" -Type REG_NONE -Value 0 -ErrorAction SilentlyContinue -Force
#Print Screen
New-ItemProperty -Path "Registry::HKEY_CURRENT_USER\Control Panel\Keyboard" -Name "PrintScreenKeyForSnippingEnabled" -Type DWORD -Value 0 -ErrorAction SilentlyContinue -Force
New-ItemProperty -Path "HKUDefaultHive:\DefaultHive\Control Panel\Keyboard" -Name "PrintScreenKeyForSnippingEnabled" -Type DWORD -Value 0 -ErrorAction SilentlyContinue -Force
#Windows-Shift-S hotkey
New-ItemProperty -Path "Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisabledHotkeys" -Type REG_SZ -Value "S" -ErrorAction SilentlyContinue -Force
New-ItemProperty -Path "HKUDefaultHive:\DefaultHive\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisabledHotkeys" -Type REG_SZ -Value "S" -ErrorAction SilentlyContinue -Force
#Unload Hive
Reg Unload "HKU\DefaultHive\"
#Remove PSDrive HKUDefaultHive
#Remove-PSDrive "HKUDefaultHive"

#Disable Sketch & Snip Quick Access, Print Screen and Windows-Shift-S hotkey for Existing User Profiles
# Regex pattern for SIDs
$PatternSID = 'S-1-\d+-\d+-\d+-\d+\-\d+\-\d+$'
 
# Get Username, SID, and location of ntuser.dat for all users
$ProfileList = gp 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*' | Where-Object {$_.PSChildName -match $PatternSID} |
    Select  @{name="SID";expression={$_.PSChildName}},
            @{name="UserHive";expression={"$($_.ProfileImagePath)\ntuser.dat"}},
            @{name="Username";expression={$_.ProfileImagePath -replace '^(.*[\\\/])', ''}}
 
# Get all user SIDs found in HKEY_USERS (ntuder.dat files that are loaded)
$LoadedHives = gci Registry::HKEY_USERS | ? {$_.PSChildname -match $PatternSID} | Select @{name="SID";expression={$_.PSChildName}}
 
# Get all users that are not currently logged
$UnloadedHives = Compare-Object $ProfileList.SID $LoadedHives.SID | Select @{name="SID";expression={$_.InputObject}}, UserHive, Username
 
# Loop through each profile on the machine
Foreach ($item in $ProfileList) {
    # Load User ntuser.dat if it's not already loaded
    IF ($item.SID -in $UnloadedHives.SID) {
        reg load HKU\$($Item.SID) $($Item.UserHive) | Out-Null
    }
 
    #####################################################################
    # This is where you can read/modify a users portion of the registry
    #"{0}" -f $($item.Username) | Write-Output
    #Quck Access
    New-Item registry::HKEY_USERS\$($item.SID)"\Control Panel\Quick Actions\Control Center" -ErrorAction SilentlyContinue -Force
    New-Item registry::HKEY_USERS\$($item.SID)"\Control Panel\Quick Actions\Control Center\Unpinned" -ErrorAction SilentlyContinue -Force
    New-ItemProperty registry::HKEY_USERS\$($item.SID)"\Control Panel\Quick Actions\Control Center\Unpinned" -Name 'Microsoft.QuickAction.ScreenClipping' -PropertyType REG_NONE -ErrorAction SilentlyContinue -Force
    #Print Screen
    New-ItemProperty -Path "Registry::HKEY_USERS\$($item.SID)\Control Panel\Keyboard" -Name "PrintScreenKeyForSnippingEnabled" -Type DWORD -Value 0 -ErrorAction SilentlyContinue -Force
    #Windows-Shift-S hotkey
    New-ItemProperty -Path "Registry::HKEY_USERS\$($item.SID)\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisabledHotkeys" -Type REG_SZ -Value "S" -ErrorAction SilentlyContinue -Force


    #####################################################################
 
    # Unload ntuser.dat        
    IF ($item.SID -in $UnloadedHives.SID) {
        ### Garbage collection and closing of ntuser.dat ###
        [gc]::Collect()
        reg unload HKU\$($Item.SID) | Out-Null
    }
}

#Uninstall Sketch & Snip app Microsoft.ScreenSketch
Get-AppxPackage -AllUsers "Microsoft.ScreenSketch*" | Remove-AppxPackage
