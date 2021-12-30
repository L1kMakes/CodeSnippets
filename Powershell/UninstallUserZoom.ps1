####
# 
# Name: UninstallUserZoom
# Author: Joseph Gullo
# Last Modification: 2021.12.28
# Description: This script scans user folders for user installs
#   of Zoom.  We want Zoom installed to the system, not the user, 
#   and having multiple versions installed causes user issues.
#   If it finds one, it uninstalls it.
# References: 
#
####

Write-Verbose -Verbose -Message "Running Uninstall-ZoomCurrentUser function"
# Getting all user profiles on the computer
$userProfiles = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*" | Where-Object {$_.PSChildName -match "S-1-5-21-(\d+-?){4}$"} | Select-Object @{Name="SID"; Expression={$_.PSChildName}}, @{Name="UserHive";Expression={"$($_.ProfileImagePath)\NTuser.dat"}}
foreach ($userProfile in $userProfiles) {
	# Formatting the username in a separate variable
	$userName = $userProfile.UserHive.Split("\")[2]
	write-host $userName
	$registryPath = "Registry::HKEY_USERS\$($UserProfile.SID)\Software\Microsoft\Windows\CurrentVersion\Uninstall"
	if (Test-Path -Path $registryPath) {
		$installedZoomApps = Get-ChildItem -Path $registryPath -Recurse | Get-ItemProperty | Where-Object {$_.Publisher -like "Zoom*" } | Select-Object Displayname,UninstallString
		if ($installedZoomApps) {
			Write-Verbose -Verbose -Message "Installed Zoom applications found in HKCU for user: $userName"
			while (Get-Process | where {$_.ProcessName -like "Zoom*"}) { 
				$ZoomProcesses = (Get-Process | where {$_.ProcessName -like "Zoom*"})
				foreach ( $process in $ZoomProcesses ) { 
					Stop-Process $process 
				} 
			}
			Remove-Item -Recurse -Force "C:\Users\$userName\AppData\Roaming\Zoom\bin"
			Remove-Item -Recurse -Force "C:\Users\$userName\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Zoom"
			New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS
			$RegPath = "HKU:\$($UserProfile.SID)\Software\Microsoft\Windows\CurrentVersion\Uninstall\Zoom*"
			Remove-Item -Path $RegPath -Recurse
		}
		else {
			Write-Verbose -Verbose -Message "No Zoom applications found in HKCU for user: $userName"
		}
	}
	else {
		Write-Verbose -Verbose -Message "Registry path not found for user: $userName"
	}
}
