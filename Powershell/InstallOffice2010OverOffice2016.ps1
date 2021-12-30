####
# 
# Name: InstallOffice2010OverOffice2016
# Author: Joseph Gullo
# Last Modification: 2021.12.28
# Description: We have a requirement based on a CRM product to use
#   outlook 2010 for plugin compatability.  For most users, a new computer
#   gets Office 2016, but the need arises for some users to still have the
#   older version.  This uninstalls the newer office and re-installs
#   the older one with the required plugin.
# References: 
#
####

# Install Office 2010 ProPlus x86 OVER Office 2016 x64
Write-Host "Installing Microsoft Office 2010 ProPlus x86" -ForeGroundColor "Yellow"
$objCRM=Get-WmiObject -class Win32_product -filter "Name LIKE '%Dynamics CRM%'"
if ($objCRM -eq $null) {
	Write-Host "--Dynamics CRM plugin is not installed, proceeding!" -ForeGroundColor "Yellow"
	$obj=Get-WmiObject -class Win32_product -filter "Name LIKE 'Microsoft Office%Outlook%2010%'"
	if ($obj -eq $null) {
		Write-Host "--Office 2010 is NOT installed, checking if Office 2016 is installed!" -ForeGroundColor "Yellow"
		$obj2016=Get-WmiObject -class Win32_product -filter "Name LIKE 'Microsoft%Outlook%2016%'"
		if ($obj2016 -ne $null) {
			Write-Host "--Office 2016 is installed, uninstalling it!" -ForeGroundColor "Yellow"
			cd "\\ORGPREFIX-sharepointDSTORAGE.AD.DOMAIN.ORG\IT\Applications\Microsoft\Office\Office 2016 ProPlus x64\"
			Start-Process -Wait "./setup.exe" -ArgumentList "/uninstall ProPlus /config .\UninstallConfig.xml" -NoNewWindow
			Write-Host "--Office 2016 uninstall is complete!" -ForeGroundColor "Yellow"
			C:
		} else {
			Write-Host "--Office 2016 is NOT installed, proceeding!" -ForeGroundColor "Yellow"
		}
		Write-Host "--Office 2010 is NOT installed, installing it!" -ForeGroundColor "Yellow"
		cd "\\ORGPREFIX-sharepointDSTORAGE.AD.DOMAIN.ORG\IT\Applications\Microsoft\Office\Office 2010\Office 2010 proplus 32 bit\"
		Start-Process -Wait "./setup.exe" -ArgumentList "/adminfile DOMAIN.MSP" -NoNewWindow
		C:
		Write-Host "--Office 2010 install is complete, fixing shortcuts!" -ForeGroundColor "Yellow"
		Copy-Item -Path '\\ORGPREFIX-SCCM-01\SCCMPackageSources$\ORGPREFIX Packages\Windows 10 OSD Settings\Windows 10 OSD Settings 1809\Internet Explorer.lnk' -Destination 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories' -ErrorAction SilentlyContinue
		remove-item "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Office\Microsoft Excel.lnk" -ErrorAction SilentlyContinue
		remove-item "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Office\Microsoft OneNote.lnk" -ErrorAction SilentlyContinue
		remove-item "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Office\Microsoft Outlook.lnk" -ErrorAction SilentlyContinue
		remove-item "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Office\Microsoft PowerPoint.lnk" -ErrorAction SilentlyContinue
		remove-item "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Office\Microsoft Publisher.lnk" -ErrorAction SilentlyContinue
		remove-item "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Office\Microsoft Word.lnk" -ErrorAction SilentlyContinue
		mv "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Office\Microsoft Excel 2010.lnk" "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Office\Microsoft Excel.lnk" -ErrorAction SilentlyContinue
		mv "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Office\Microsoft OneNote 2010.lnk" "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Office\Microsoft OneNote.lnk" -ErrorAction SilentlyContinue
		mv "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Office\Microsoft Outlook 2010.lnk" "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Office\Microsoft Outlook.lnk" -ErrorAction SilentlyContinue
		mv "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Office\Microsoft PowerPoint 2010.lnk" "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Office\Microsoft PowerPoint.lnk" -ErrorAction SilentlyContinue
		mv "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Office\Microsoft Publisher 2010.lnk" "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Office\Microsoft Publisher.lnk" -ErrorAction SilentlyContinue
		mv "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Office\Microsoft Word 2010.lnk" "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Office\Microsoft Word.lnk" -ErrorAction SilentlyContinue
	} else {
		Write-Host "--Office 2010 IS installed, exiting!" -ForeGroundColor "Yellow"
	}
}

# Install Microsoft Dynamics CRM for Outlook
Write-Host "Installing Microsoft Dynamics CRM Plugin for Outlook" -ForeGroundColor "Yellow"
$obj=Get-WmiObject -class Win32_product -filter "Name LIKE '%Dynamics CRM%'"
if ($obj -eq $null) {
	Write-Host "--Dynamics plugin is NOT installed, proceeding!" -ForeGroundColor "Yellow"
	
	# Check that a reboot isn't pending
	$HKLM = [UInt32] "0x80000002"
	$WMI_Reg = [WMIClass] "\\localhost\root\default:StdRegProv" 
	$RegWUAURebootReq = $WMI_Reg.EnumKey($HKLM,"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\") 
	$WUAURebootReq = $RegWUAURebootReq.sNames -contains "RebootRequired"
	if ($WUAURebootReq -eq "True") {
		Write-Host "--A reboot is required to proceed, rebooting!" -ForeGroundColor "Yellow"
		Restart-Computer
		Sleep 10
	}
	
	# Confirm that the Windows Identity Foundation Optional Feature is installed
	if ( [environment]::OSVersion.Version.Major -eq 10 ) {
		Write-Host "--Checking that Windows Identity Foundation feature is installed!" -ForeGroundColor "Yellow"
		$WIFState=(Get-WindowsOptionalFeature -FeatureName "Windows-Identity-Foundation" -Online).State
		if ($WIFState -eq "Disabled") {
			write-host "--Windows Identity Foundation is not installed, enabling it!" -ForeGroundColor "Yellow"
			dism /online /Enable-Feature /FeatureName:Windows-Identity-Foundation
		}
	}
	
	# Check that a reboot isn't pending
	$HKLM = [UInt32] "0x80000002"
	$WMI_Reg = [WMIClass] "\\localhost\root\default:StdRegProv" 
	$RegWUAURebootReq = $WMI_Reg.EnumKey($HKLM,"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\") 
	$WUAURebootReq = $RegWUAURebootReq.sNames -contains "RebootRequired"
	if ($WUAURebootReq -eq "True") {
		Write-Host "--A reboot is required to proceed, rebooting!" -ForeGroundColor "Yellow"
		Restart-Computer
		Sleep 10
	}
	
	# Install Microsoft Online Services Sign On Assistant
	Write-Host "Installing Microsoft Online Services Sign On Assistant x64" -ForeGroundColor "Yellow"
	cd "\\ORGPREFIX-sharepointDSTORAGE.AD.DOMAIN.ORG\IT\Applications\Microsoft\Microsoft Online Services Sign-In Assistant"
	Start-Process -Wait "msiexec" -ArgumentList "/i msoidcli_64.msi /qn" -NoNewWindow
	C:
	
	# Install the actual CRM plugin
	$bitness=Get-ItemProperty -path 'hklm:\Software\Microsoft\Office\14.0\Outlook\' | Select-Object -ExpandProperty Bitness -ErrorAction SilentlyContinue
	If ($bitness -eq 'x86') {
		Write-Host "--This is a 32-bit Office install, so we're installing the 32-bit plugin!" -ForeGroundColor "Yellow"
		cd "\\ORGPREFIX-sharepointDSTORAGE.AD.DOMAIN.ORG\IT\Applications\Microsoft\CRM Outlook Plugin\CRM2011-Client-ENU-i386"
		$obj=Get-WmiObject -class Win32_product -filter "Name LIKE '%Dynamics CRM%'"
		if ($obj -eq $null) {
			Write-Host "--Running the actual plugin install!" -ForeGroundColor "Yellow"
			Start-Process -Wait "./SetupClient.exe" -ArgumentList "/quiet /norestart /passive" -NoNewWindow
		}
		cp \\AD.DOMAIN.ORG\sysvol\AD.DOMAIN.org\scripts\Default_Client_Config.xml "c:\Program Files (x86)\Microsoft Dynamics CRM\Default_Client_Config.xml"
		C:
		cd "C:\Program Files (x86)\Microsoft Dynamics CRM\Client\ConfigWizard"
		./Microsoft.Crm.Application.Outlook.ConfigWizard.exe /q /xa
		./Microsoft.Crm.Application.Outlook.ConfigWizard.exe /q /i "C:\Program Files (x86)\Microsoft Dynamics CRM\Default_Client_Config.xml"
	} ElseIf ($bitness -eq 'x64') {
		Write-Host "--This is a 64-bit Office install, so we're installing the 64-bit plugin!" -ForeGroundColor "Yellow"
		cd "\\ORGPREFIX-sharepointDSTORAGE.AD.DOMAIN.ORG\IT\Applications\Microsoft\CRM Outlook Plugin\CRM2011-Client-ENU-amd64"
		Start-Process -Wait "./SetupClient.exe" -ArgumentList "/quiet /norestart /passive" -NoNewWindow
		cp \\AD.DOMAIN.ORG\sysvol\AD.DOMAIN.org\scripts\Default_Client_Config.xml "c:\Program Files\Microsoft Dynamics CRM\Default_Client_Config.xml"
		C:
		cd "C:\Program Files\Microsoft Dynamics CRM\Client\ConfigWizard"
		./Microsoft.Crm.Application.Outlook.ConfigWizard.exe /q /xa
		./Microsoft.Crm.Application.Outlook.ConfigWizard.exe /q /i "C:\Program Files\Microsoft Dynamics CRM\Default_Client_Config.xml"
	}
	C:
}


# Remove GPO connection to the WSUS server for the duration of this operation since we'll be contacting windows update directly.
Set-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "UseWUServer" -Value "0"

# Sometimes, despite Office being installed, windows update only installs updates for windows.  This tricks it into including office and other updates
$objServiceManager = New-Object -ComObject "Microsoft.Update.ServiceManager"
$objService = $objServiceManager.AddService2("7971f918-a847-4430-9279-4a52d1efe18d",7,"")
$objService.PSTypeNames.Clear()
$objService.PSTypeNames.Add('PSWindowsUpdate.WUServiceManager')
Restart-Service wuauserv

# Install Windows Updates
$UpdateCollection = New-Object -ComObject Microsoft.Update.UpdateColl
$Searcher = New-Object -ComObject Microsoft.Update.Searcher
$Session = New-Object -ComObject Microsoft.Update.Session
Write-Host "Initialising and Checking for Applicable Updates. Please wait ..." -ForeGroundColor "Yellow"
# Search for all windows updates ready to be installed.  Find skype in that list, then build a query string that excludes the current skype install.
$querystring="IsInstalled=0"
$Result = $Searcher.search("$querystring")
For ($Counter = 0; $Counter -LT $Result.Updates.Count; $Counter++) {
	if (
		( $Result.Updates.Item($Counter).Title -like "*LaserJet*") -OR (
			#( $Result.Updates.Item($Counter).Title -like "*Skype*") -OR (
				#( $Result.Updates.Item($Counter).Title -like "*Security Essentials*") -OR (
					( $Result.Updates.Item($Counter).Title -like "*DOT4PAR*") -OR ($Result.Updates.Item($Counter).Title -like "*Printer*")
				#)
			#)
		)
	) {
		$querystring="$($querystring) AND UpdateID!='$($Result.Updates.Item($Counter).Identity.UpdateID)'"
	}
}
$Result = $Searcher.search("$querystring")
$updateCount=$Result.Updates.Count
Write-Host "There are $updateCount Updates to Install" -ForeGroundColor "Yellow"
# Now that you have the remaining non-skype updates selected, install them and repeat until none are left
while ($Result.Updates.Count -ne 0)
{
	Write-Host "Preparing List of Applicable Updates For This Computer ..." -ForeGroundColor "Yellow"
	For ($Counter = 0; $Counter -LT $Result.Updates.Count; $Counter++) {
		$DisplayCount = $Counter + 1
			$Update = $Result.Updates.Item($Counter)
		$UpdateTitle = $Update.Title
		Write-Host "$DisplayCount -- $UpdateTitle"
	}
	$Counter = 0
	$DisplayCount = 0
	Write-Host "Initialising Download of Applicable Updates ..." -ForeGroundColor "Yellow"
	$Downloader = $Session.CreateUpdateDownloader()
	$UpdatesList = $Result.Updates
	For ($Counter = 0; $Counter -LT $Result.Updates.Count; $Counter++) {
		$UpdateCollection.Add($UpdatesList.Item($Counter)) | Out-Null
		$ShowThis = $UpdatesList.Item($Counter).Title
		$DisplayCount = $Counter + 1
		Write-Host "$DisplayCount -- Downloading Update $ShowThis `r"
		$Downloader.Updates = $UpdateCollection
		$Track = $Downloader.Download()
		If (($Track.HResult -EQ 0) -AND ($Track.ResultCode -EQ 2)) {
			Write-Host "Download Status: SUCCESS"
		} Else {
			Write-Host "Download Status: FAILED With Error -- $Error()" -ForeGroundColor "Yellow"
			$Error.Clear()
		}	
	}
	$Counter = 0
	$DisplayCount = 0
	Write-Host "Starting Installation of Downloaded Updates ..." -ForeGroundColor "Yellow"
	$Installer = New-Object -ComObject Microsoft.Update.Installer
	For ($Counter = 0; $Counter -LT $UpdateCollection.Count; $Counter++) {
		$Track = $Null
		$DisplayCount = $Counter + 1
		$WriteThis = $UpdateCollection.Item($Counter).Title
		$EulaResultPre = $UpdateCollection.Item($Counter).EulaAccepted
		$UpdateCollection.Item($Counter).AcceptEula()
		$EulaResultPost = $UpdateCollection.Item($Counter).EulaAccepted
		Write-Host "$DisplayCount -- Installing Update: $WriteThis, Eula was $EulaResultPre and is now $EulaResultPost"
		$Installer.Updates = $UpdateCollection
		Try {
			$Track = $Installer.Install()
			Write-Host "Update Installation Status: SUCCESS"
		}
		Catch {
			[System.Exception]
			Write-Host "Update Installation Status: FAILED With Error -- $Error()" -ForeGroundColor "Yellow"
			$Error.Clear()
		}	
	}
	#Reboot if required
	$HKLM = [UInt32] "0x80000002"
	$WMI_Reg = [WMIClass] "\\localhost\root\default:StdRegProv" 
	$RegWUAURebootReq = $WMI_Reg.EnumKey($HKLM,"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\") 
	$WUAURebootReq = $RegWUAURebootReq.sNames -contains "RebootRequired"
	if ($WUAURebootReq -eq "True") {
		Write-Host "Hey you need to restart" -ForeGroundColor "Yellow"
		Restart-Computer
	}
	$UpdateCollection = New-Object -ComObject Microsoft.Update.UpdateColl
	$Searcher = New-Object -ComObject Microsoft.Update.Searcher
	$Session = New-Object -ComObject Microsoft.Update.Session
	# Search for all windows updates ready to be installed.  Find skype in that list, then build a query string that excludes the current skype install.
	$Result = $Searcher.search("IsInstalled=0")
	$querystring="IsInstalled=0"
	For ($Counter = 0; $Counter -LT $Result.Updates.Count; $Counter++) {
		if (
			( $Result.Updates.Item($Counter).Title -like "*LaserJet*" ) -OR (
				#( $Result.Updates.Item($Counter).Title -like "*Skype*" ) -OR (
					#( $Result.Updates.Item($Counter).Title -like "*Security Essentials*" ) -OR (
						( $Result.Updates.Item($Counter).Title -like "*DOT4PAR*" ) -OR ($Result.Updates.Item($Counter).Title -like "*Printer*")
					#)
				#)
			)
		) {
			$querystring="$($querystring) AND UpdateID!='$($Result.Updates.Item($Counter).Identity.UpdateID)'"
		}
	}
	$Result = $Searcher.search("$querystring")
	$updateCount=$Result.Updates.Count
	Write-Host "There are $updateCount Updates to Install" -ForeGroundColor "Yellow"
}
Write-Host "There are no applicable updates for this computer." -ForeGroundColor "Yellow"
Restart-Service wuauserv

