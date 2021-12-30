####
# 
# Name: WindowsUpdates.Manual
# Author: Joseph Gullo
# Last Modification: 2021.12.28
# Description: This script checks for all windows updates (outside of 
#   an exclusion list) and then installs them, prompting for a reboot 
#   if needed.  If there are no more updates from windows update, 
#   then install updates for our preferred suite of apps.
# References: 
#
####

function installServerUpdates () {
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
			($Result.Updates.Item($Counter).Title -like "*LaserJet*") -OR (
				#($Result.Updates.Item($Counter).Title -like "*Skype*") -OR (
					($Result.Updates.Item($Counter).Title -like "*Security Essentials*") -OR (
						($Result.Updates.Item($Counter).Title -like "*DOT4*") -OR (
							($Result.Updates.Item($Counter).Title -like "*Printer*") -OR (
								($Result.Updates.Item($Counter).Title -like "*KYOCERA*") -OR (
									$Result.Updates.Item($Counter).Title -like "*Feature update to Windows 10*"
								)
							)
						)
					)
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
			}
			Else {
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
			Exit
		}
		$UpdateCollection = New-Object -ComObject Microsoft.Update.UpdateColl
		$Searcher = New-Object -ComObject Microsoft.Update.Searcher
		$Session = New-Object -ComObject Microsoft.Update.Session
		# Search for all windows updates ready to be installed.  Find skype in that list, then build a query string that excludes the current skype install.
		$Result = $Searcher.search("IsInstalled=0")
		$querystring="IsInstalled=0"
		For ($Counter = 0; $Counter -LT $Result.Updates.Count; $Counter++) {
			if (
				($Result.Updates.Item($Counter).Title -like "*LaserJet*") -OR (
					#($Result.Updates.Item($Counter).Title -like "*Skype*") -OR (
						($Result.Updates.Item($Counter).Title -like "*Security Essentials*") -OR (
							($Result.Updates.Item($Counter).Title -like "*DOT4*") -OR (
								($Result.Updates.Item($Counter).Title -like "*Printer*") -OR (
									($Result.Updates.Item($Counter).Title -like "*KYOCERA*") -OR (
										$Result.Updates.Item($Counter).Title -like "*Feature update to Windows 10*"
									)
								)
							)
						)
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
	
	# Install Notepad++
	Write-Host "Installing Notepad++" -ForeGroundColor "Yellow"
	cd "\\ORGPREFIX-sharepointDSTORAGE.AD.DOMAIN.ORG\IT\Applications\Notepad++\"
	Start-Process -Wait "./Notepad++.Current.exe" -ArgumentList "/S" -NoNewWindow
	cp \\ORGPREFIX-sharepointDSTORAGE.AD.DOMAIN.ORG\IT\Applications\Notepad++\config.model.xml "c:\Program Files\Notepad++\config.model.xml"
	C:

	# Install 7-Zip
	Write-Host "Installing 7-Zip" -ForeGroundColor "Yellow"
	cd "\\ORGPREFIX-sharepointDSTORAGE.AD.DOMAIN.ORG\IT\Applications\7-Zip\"
	Start-Process -Wait "./7-Zip.Current.exe" -ArgumentList "/S" -NoNewWindow
	C:

	if ( ! ( ( Get-WMIObject win32_operatingsystem ).name -like "*Server*" ) ) {
		# Install Google Chrome
		Write-Host "Installing Google Chrome" -ForeGroundColor "Yellow"
		cd "\\ORGPREFIX-sharepointDSTORAGE.AD.DOMAIN.ORG\IT\Applications\Google\Chrome\"
		Start-Process -Wait "msiexec" -ArgumentList "/i GoogleChrome.x64.Current.msi /qn" -NoNewWindow
		C:
	
		# Adobe Acrobat Reader DC
		Write-Host "Installing Adobe Acrobat Reader DC" -ForeGroundColor "Yellow"
		cd "\\ORGPREFIX-sharepointDSTORAGE.ad.DOMAIN.org\it\Applications\Adobe\Acrobat Reader"
		Start-Process -Wait "./AcrobatReaderCurrent.exe" -ArgumentList "/SAll /rs" -NoNewWindow
		# Delete shortcuts on the desktop
		if ( Test-Path "C:\Users\Public\Desktop\" ) {
			remove-item -Path "C:\Users\Public\Desktop\*Acrobat*.lnk"
		}
		if ( Test-Path "C:\Users\All Users\Desktop\" ) {
			remove-item -Path "C:\Users\All Users\Desktop\*Acrobat*.lnk"
		}
		C:
		
		# Install VLC
		Write-Host "Installing VLC" -ForeGroundColor "Yellow"
		cd "\\ORGPREFIX-sharepointDSTORAGE.AD.DOMAIN.ORG\IT\Applications\VLC\"
		Start-Process -Wait ".\VLC.Current.exe" -ArgumentList "/S" -NoNewWindow
		# Delete shortcuts on the desktop
		if ( Test-Path "C:\Users\Public\Desktop\" ) {
			remove-item -Path "C:\Users\Public\Desktop\*VLC*.lnk"
		}
		if ( Test-Path "C:\Users\All Users\Desktop\" ) {
			remove-item -Path "C:\Users\All Users\Desktop\*VLC*.lnk"
		}
		C:
	
		# Zoom
		Write-Host "Installing Zoom" -ForeGroundColor "Yellow"
		cd "\\ORGPREFIX-sharepointDSTORAGE.AD.DOMAIN.ORG\IT\Applications\Zoom\"
		Start-Process -Wait "msiexec" -ArgumentList "/i ZoomInstallerFull.Current.msi /qn" -NoNewWindow
		C:
	}
}
#gpupdate /force
#invoke-gpupdate -Force -Logoff:$false
installServerUpdates

