####
# 
# Name: SCCM.WindowsUpdates.Manual
# Author: Joseph Gullo
# Last Modification: 2021.12.28
# Description: This script checks for all windows updates (outside of 
#   an exclusion list) and then installs them, prompting for a reboot 
#   if needed.  If there are no more updates from windows update, 
#   then install updates for our preferred suite of apps.
#
#   This version of the script is specifically configured to install 
#   from SCCM with a routine of tattooing some things to the registry 
#   and forcing the computer to re-run the script when rebooted, even 
#   if off the VPN and with no connection to the home server.
# References: 
#
####

###
# This function does the updates; it doesn't run until called by the main code block at the bottom
###
function installWindowsUpdates () {
	$dateStrMin = Get-Date -UFormat "%Y.%m.%d-%H.%M.%S"
	echo "Starting updates at $dateStrMin" >> C:\ORGPREFIX\UpdatesLog.txt

	###
	# Remove GPO connection to the WSUS server for the duration of this operation since we'll be contacting windows update directly.
	# WSUS doesn't exist anymore, but this is staying in place just in case as it does no harm
	###
	Set-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "UseWUServer" -Value "0"

	###
	# Sometimes, despite Office being installed, windows update only installs updates for windows.  This tricks it into including office and other updates
	###
	$objServiceManager = New-Object -ComObject "Microsoft.Update.ServiceManager"
	$objService = $objServiceManager.AddService2("7971f918-a847-4430-9279-4a52d1efe18d",7,"")
	$objService.PSTypeNames.Clear()
	$objService.PSTypeNames.Add('PSWindowsUpdate.WUServiceManager')
	Restart-Service wuauserv

	###
	# Install Windows Updates
	###
	$UpdateCollection = New-Object -ComObject Microsoft.Update.UpdateColl
	$Searcher = New-Object -ComObject Microsoft.Update.Searcher
	$Session = New-Object -ComObject Microsoft.Update.Session
	echo "Initialising and Checking for Applicable Updates. Please wait ..." >> C:\ORGPREFIX\UpdatesLog.txt
	# Search for all windows updates ready to be installed.  
	$querystring="IsInstalled=0"
	$Result = $Searcher.search("$querystring")
	For ($Counter = 0; $Counter -LT $Result.Updates.Count; $Counter++) {
		# Filter out certain updates, mostly these are ones that historically caused the process to hang as even when successful they return a failed error code
		# We used to block Skype as it installed skype consumer edition, but now we need to enable it to update skype for business.
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
	$dateStrMin = Get-Date -UFormat "%Y.%m.%d-%H.%M.%S"
	echo "There are $updateCount Updates to Install at $dateStrMin" >> C:\ORGPREFIX\UpdatesLog.txt
	# Now that you have the remaining non-skype updates selected, install them and repeat until none are left
	while ($Result.Updates.Count -ne 0)
	{
	
		# Test if we have already cycled 5 times; if so, we're stuck in a cycle and should write-output an error and abort.
		if ( Get-ItemProperty -path 'hklm:\Software\DOMAIN\' | Select-Object -ExpandProperty WindowsUpdatesRound5 -ErrorAction SilentlyContinue ) {
			echo "5 cycles are completed, something is wrong!" >> C:\ORGPREFIX\UpdatesLog.txt
			$dateStrMin = Get-Date -UFormat "%Y.%m.%d-%H.%M.%S"
			$LogPath = 'filesystem::\\ORGPREFIX-sharepointDSTORAGE.AD.DOMAIN.ORG\ORGPREFIXComputerLoginTracking$\WindowsUpdateLog.txt'
			If ( Test-path -Path $LogPath ) {
				echo "$hostname $dateStrMin ABORT" >> \\ORGPREFIX-sharepointDSTORAGE.AD.DOMAIN.ORG\ORGPREFIXComputerLoginTracking$\WindowsUpdateLog.txt
				if ( Get-ScheduledTask -TaskName "WriteAbortToNetworkedLog" -ErrorAction SilentlyContinue ) {
					schtasks /delete /f /tn "WriteAbortToNetworkedLog"
				}
			} else {
				echo "Creating a scheduled task to try to write to the networked log hourly, letting it know we aborted" >> C:\ORGPREFIX\UpdatesLog.txt
				if ( -not ( Get-ScheduledTask -TaskName "WriteAbortToNetworkedLog" -ErrorAction SilentlyContinue ) ) {
					schtasks /create /tn "WriteAbortToNetworkedLog" /sc HOURLY /rl highest /ru system /tr "powershell.exe -file C:\ORGPREFIX\SCCM.WindowsUpdates.Manual.ps1"
				}
			}
			exit
		}
	
		echo "Preparing List of Applicable Updates For This Computer ..." >> C:\ORGPREFIX\UpdatesLog.txt
		For ($Counter = 0; $Counter -LT $Result.Updates.Count; $Counter++) {
			$DisplayCount = $Counter + 1
				$Update = $Result.Updates.Item($Counter)
			$UpdateTitle = $Update.Title
			echo "$DisplayCount -- $UpdateTitle" >> C:\ORGPREFIX\UpdatesLog.txt
		}
		$Counter = 0
		$DisplayCount = 0
		echo "Initialising Download of Applicable Updates ..." >> C:\ORGPREFIX\UpdatesLog.txt
		$Downloader = $Session.CreateUpdateDownloader()
		$UpdatesList = $Result.Updates
		For ($Counter = 0; $Counter -LT $Result.Updates.Count; $Counter++) {
			$UpdateCollection.Add($UpdatesList.Item($Counter)) | Out-Null
			$ShowThis = $UpdatesList.Item($Counter).Title
			$DisplayCount = $Counter + 1
			echo "$DisplayCount -- Downloading Update $ShowThis `r" >> C:\ORGPREFIX\UpdatesLog.txt
			$Downloader.Updates = $UpdateCollection
			$Track = $Downloader.Download()
			If (($Track.HResult -EQ 0) -AND ($Track.ResultCode -EQ 2)) {
				echo "Download Status: SUCCESS" >> C:\ORGPREFIX\UpdatesLog.txt
			}
			Else {
				echo "Download Status: FAILED With Error -- $Error()" >> C:\ORGPREFIX\UpdatesLog.txt
				$Error.Clear()
			}	
		}
		$Counter = 0
		$DisplayCount = 0
		$dateStrMin = Get-Date -UFormat "%Y.%m.%d-%H.%M.%S"
		echo "Starting Installation of Downloaded Updates  at $dateStrMin" >> C:\ORGPREFIX\UpdatesLog.txt
		$Installer = New-Object -ComObject Microsoft.Update.Installer
		For ($Counter = 0; $Counter -LT $UpdateCollection.Count; $Counter++) {
			$Track = $Null
			$DisplayCount = $Counter + 1
			$WriteThis = $UpdateCollection.Item($Counter).Title
			$EulaResultPre = $UpdateCollection.Item($Counter).EulaAccepted
			$UpdateCollection.Item($Counter).AcceptEula()
			$EulaResultPost = $UpdateCollection.Item($Counter).EulaAccepted
			echo "$DisplayCount -- Installing Update: $WriteThis, Eula was $EulaResultPre and is now $EulaResultPost" >> C:\ORGPREFIX\UpdatesLog.txt
			$Installer.Updates = $UpdateCollection
			Try {
				$Track = $Installer.Install()
				echo "Update Installation Status: SUCCESS" >> C:\ORGPREFIX\UpdatesLog.txt
			}
			Catch {
				[System.Exception]
				echo "Update Installation Status: FAILED With Error -- $Error()" >> C:\ORGPREFIX\UpdatesLog.txt
				$Error.Clear()
			}	
		}

		# Tattoo the registry with tags indicating which of 5 rounds of updates we are on.  Each cycle, iterate the counter by 1
		if ( -not ( Get-ItemProperty -path 'hklm:\Software\DOMAIN\' | Select-Object -ExpandProperty WindowsUpdatesRound1 -ErrorAction SilentlyContinue ) ) {
			echo "-Creating HKLM:\SOFTWARE\DOMAIN\WindowsUpdatesRound1" >> C:\ORGPREFIX\UpdatesLog.txt
			new-itemproperty -path HKLM:\Software\DOMAIN -name WindowsUpdatesRound1 -value TRUE
		} elseif ( -not ( Get-ItemProperty -path 'hklm:\Software\DOMAIN\' | Select-Object -ExpandProperty WindowsUpdatesRound2 -ErrorAction SilentlyContinue ) ) {
			echo "-Creating HKLM:\SOFTWARE\DOMAIN\WindowsUpdatesRound2" >> C:\ORGPREFIX\UpdatesLog.txt
			new-itemproperty -path HKLM:\Software\DOMAIN -name WindowsUpdatesRound2 -value TRUE
		} elseif ( -not ( Get-ItemProperty -path 'hklm:\Software\DOMAIN\' | Select-Object -ExpandProperty WindowsUpdatesRound3 -ErrorAction SilentlyContinue ) ) {
			echo "-Creating HKLM:\SOFTWARE\DOMAIN\WindowsUpdatesRound3" >> C:\ORGPREFIX\UpdatesLog.txt
			new-itemproperty -path HKLM:\Software\DOMAIN -name WindowsUpdatesRound3 -value TRUE
		} elseif ( -not ( Get-ItemProperty -path 'hklm:\Software\DOMAIN\' | Select-Object -ExpandProperty WindowsUpdatesRound4 -ErrorAction SilentlyContinue ) ) {
			echo "-Creating HKLM:\SOFTWARE\DOMAIN\WindowsUpdatesRound4" >> C:\ORGPREFIX\UpdatesLog.txt
			new-itemproperty -path HKLM:\Software\DOMAIN -name WindowsUpdatesRound4 -value TRUE
		} elseif ( -not ( Get-ItemProperty -path 'hklm:\Software\DOMAIN\' | Select-Object -ExpandProperty WindowsUpdatesRound5 -ErrorAction SilentlyContinue ) ) {
			echo "-Creating HKLM:\SOFTWARE\DOMAIN\WindowsUpdatesRound5" >> C:\ORGPREFIX\UpdatesLog.txt
			new-itemproperty -path HKLM:\Software\DOMAIN -name WindowsUpdatesRound5 -value TRUE
		}
		
		###
		# Reboot if required
		###
		$HKLM = [UInt32] "0x80000002"
		$WMI_Reg = [WMIClass] "\\localhost\root\default:StdRegProv" 
		$RegWUAURebootReq = $WMI_Reg.EnumKey($HKLM,"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\") 
		$WUAURebootReq = $RegWUAURebootReq.sNames -contains "RebootRequired"
		if ($WUAURebootReq -eq "True") {
			# Copy the script to a temporary location on the C drive
			if ( -not ( Test-Path C:\ORGPREFIX ) ) {
				echo "Creating C:\ORGPREFIX!" >> C:\ORGPREFIX\UpdatesLog.txt
				mkdir C:\ORGPREFIX
			}
			if ( -not ( Test-Path C:\ORGPREFIX\SCCM.WindowsUpdates.Manual.ps1 ) ) {
				echo "Copying script to C:\ORGPREFIX\SCCM.WindowsUpdates.Manual.ps1" >> C:\ORGPREFIX\UpdatesLog.txt
				copy-item \\ORGPREFIX-sccm-01.ad.DOMAIN.org\SCCMMisc$\SCCM.WindowsUpdates.Manual.ps1 C:\ORGPREFIX\SCCM.WindowsUpdates.Manual.ps1
			}
			# Create a startup task to re-run this script
			if ( -not ( Get-ScheduledTask -TaskName "UpdateScriptAtStartup" -ErrorAction SilentlyContinue ) ) {
				schtasks /create /tn "UpdateScriptAtStartup" /sc onstart /delay 0000:30 /rl highest /ru system /tr "powershell.exe -file C:\ORGPREFIX\SCCM.WindowsUpdates.Manual.ps1"
			}
			
			$dateStrMin = Get-Date -UFormat "%Y.%m.%d-%H.%M.%S"
			echo "Triggering reboot at $dateStrMin" >> C:\ORGPREFIX\UpdatesLog.txt
	
			Restart-Computer -Force
		}
		
		$UpdateCollection = New-Object -ComObject Microsoft.Update.UpdateColl
		$Searcher = New-Object -ComObject Microsoft.Update.Searcher
		$Session = New-Object -ComObject Microsoft.Update.Session
		# Search for all windows updates ready to be installed.  Find skype in that list, then build a query string that excludes the current skype install.
		$Result = $Searcher.search("IsInstalled=0")
		$querystring="IsInstalled=0"
		For ($Counter = 0; $Counter -LT $Result.Updates.Count; $Counter++) {
			# Filter out certain updates, mostly these are ones that historically caused the process to hang as even when successful they return a failed error code
			# We used to block Skype as it installed skype consumer edition, but now we need to enable it to update skype for business.
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
		$dateStrMin = Get-Date -UFormat "%Y.%m.%d-%H.%M.%S"
		echo "There are $updateCount Updates to Install at $dateStrMin" >> C:\ORGPREFIX\UpdatesLog.txt
		Restart-Service wuauserv
	}
	$dateStrMin = Get-Date -UFormat "%Y.%m.%d-%H.%M.%S"
	echo "There are no applicable updates for this computer at $dateStrMin ." >> C:\ORGPREFIX\UpdatesLog.txt

	Restart-Service wuauserv
	
	# Purge the registry tattoos
	echo "Purge the registry tattoos" >> C:\ORGPREFIX\UpdatesLog.txt
	if ( Get-ItemProperty -path 'hklm:\Software\DOMAIN\' | Select-Object -ExpandProperty WindowsUpdatesRound1 -ErrorAction SilentlyContinue ) {
		echo "-Removing HKLM:\SOFTWARE\DOMAIN\WindowsUpdatesRound1" >> C:\ORGPREFIX\UpdatesLog.txt
		Remove-ItemProperty -path HKLM:\Software\DOMAIN -name WindowsUpdatesRound1
	} 
	if ( Get-ItemProperty -path 'hklm:\Software\DOMAIN\' | Select-Object -ExpandProperty WindowsUpdatesRound2 -ErrorAction SilentlyContinue ) {
		echo "-Removing HKLM:\SOFTWARE\DOMAIN\WindowsUpdatesRound2" >> C:\ORGPREFIX\UpdatesLog.txt
		Remove-ItemProperty -path HKLM:\Software\DOMAIN -name WindowsUpdatesRound2
	}
	if ( Get-ItemProperty -path 'hklm:\Software\DOMAIN\' | Select-Object -ExpandProperty WindowsUpdatesRound3 -ErrorAction SilentlyContinue ) {
		echo "-Removing HKLM:\SOFTWARE\DOMAIN\WindowsUpdatesRound3" >> C:\ORGPREFIX\UpdatesLog.txt
		Remove-ItemProperty -path HKLM:\Software\DOMAIN -name WindowsUpdatesRound3
	}
	if ( Get-ItemProperty -path 'hklm:\Software\DOMAIN\' | Select-Object -ExpandProperty WindowsUpdatesRound4 -ErrorAction SilentlyContinue ) {
		echo "-Removing HKLM:\SOFTWARE\DOMAIN\WindowsUpdatesRound4" >> C:\ORGPREFIX\UpdatesLog.txt
		Remove-ItemProperty -path HKLM:\Software\DOMAIN -name WindowsUpdatesRound4
	}
	if ( Get-ItemProperty -path 'hklm:\Software\DOMAIN\' | Select-Object -ExpandProperty WindowsUpdatesRound5 -ErrorAction SilentlyContinue ) {
		echo "-Removing HKLM:\SOFTWARE\DOMAIN\WindowsUpdatesRound5" >> C:\ORGPREFIX\UpdatesLog.txt
		Remove-ItemProperty -path HKLM:\Software\DOMAIN -name WindowsUpdatesRound5
	}

	# Clear the auto-update-at-reboot scheduled task if it exists, we don't want it to accidentally run unless we need it to.
	echo "Remove the scheduled task to re-run the script on reboot" >> C:\ORGPREFIX\UpdatesLog.txt
	if ( Get-ScheduledTask -TaskName "UpdateScriptAtStartup" -ErrorAction SilentlyContinue ) {
		schtasks /delete /f /tn "UpdateScriptAtStartup"
	}
	
	# Adobe Acrobat Reader DC
	Write-Host "Installing Adobe Acrobat Reader DC" -ForeGroundColor "Yellow"
	cd "C:\ORGPREFIX\"
	Start-Process -Wait "./AcrobatReaderCurrent.exe" -ArgumentList "/SAll /rs" -NoNewWindow
	# Delete shortcuts on the desktop
	if ( Test-Path "C:\Users\Public\Desktop\" ) {
		remove-item -Path "C:\Users\Public\Desktop\*Acrobat*.lnk"
	}
	if ( Test-Path "C:\Users\All Users\Desktop\" ) {
		remove-item -Path "C:\Users\All Users\Desktop\*Acrobat*.lnk"
	}
	C:
	
	# Install Notepad++
	echo "Installing Notepad++" >> C:\ORGPREFIX\UpdatesLog.txt
	cd "C:\ORGPREFIX\"
	Start-Process -Wait "./Notepad++.Current.exe" -ArgumentList "/S" -NoNewWindow
	cp C:\ORGPREFIX\config.model.xml "c:\Program Files\Notepad++\config.model.xml"
	C:

	# Install 7-Zip
	echo "Installing 7-Zip" >> C:\ORGPREFIX\UpdatesLog.txt
	cd "C:\ORGPREFIX\"
	Start-Process -Wait "./7-Zip.Current.exe" -ArgumentList "/S" -NoNewWindow
	C:
	
	# Install VLC
	echo "Installing VLC" >> C:\ORGPREFIX\UpdatesLog.txt
	cd "C:\ORGPREFIX\"
	Start-Process -Wait ".\VLC.Current.exe" -ArgumentList "/S" -NoNewWindow
	# Delete shortcuts on the desktop
	if ( Test-Path "C:\Users\Public\Desktop\" ) {
		remove-item -Path "C:\Users\Public\Desktop\*VLC*.lnk"
	}
	if ( Test-Path "C:\Users\All Users\Desktop\" ) {
		remove-item -Path "C:\Users\All Users\Desktop\*VLC*.lnk"
	}
	C:

	# Install Google Chrome
	echo "Installing Google Chrome" >> C:\ORGPREFIX\UpdatesLog.txt
	cd "C:\ORGPREFIX\"
	Start-Process -Wait "msiexec" -ArgumentList "/i GoogleChrome.x64.Current.msi /qn" -NoNewWindow
	C:

	# Zoom
	Write-Host "Installing Zoom" -ForeGroundColor "Yellow"
	cd "C:\ORGPREFIX\"
	Start-Process -Wait "msiexec" -ArgumentList "/i ZoomInstallerFull.Current.msi /qn" -NoNewWindow
	C:
	
	# Remove local install files
	Remove-Item -Path "C:\ORGPREFIX\AcrobatReaderCurrent.exe"
	Remove-Item -Path "C:\ORGPREFIX\7-Zip.Current.exe"
	Remove-Item -Path "C:\ORGPREFIX\Notepad++.Current.exe"
	Remove-Item -Path "C:\ORGPREFIX\config.model.xml"
	Remove-Item -Path "C:\ORGPREFIX\VLC.Current.exe"
	Remove-Item -Path "C:\ORGPREFIX\GoogleChrome.x64.Current.msi"
	Remove-Item -Path "C:\ORGPREFIX\ZoomInstallerFull.Current.msi"
	
	$dateStrMin = Get-Date -UFormat "%Y.%m.%d-%H.%M.%S"
	echo "Updates process complete at $dateStrMin" >> C:\ORGPREFIX\UpdatesLog.txt
}

###
# Start of main execution cycle for the script
###

$hostname = $env:computername

$dateStrMin = Get-Date -UFormat "%Y.%m.%d-%H.%M.%S"
echo "Starting update script at $dateStrMin" >> C:\ORGPREFIX\UpdatesLog.txt
	
# Build the ORGPREFIX Registry hive for tattooing status positions
if ( -not ( Test-Path 'HKLM:\SOFTWARE\DOMAIN' -ErrorAction SilentlyContinue ) ) {
	echo  "Creating HKLM:\SOFTWARE\DOMAIN" >> C:\ORGPREFIX\UpdatesLog.txt
	New-Item -Path 'HKLM:\SOFTWARE' -Name DOMAIN
}

# Clear the auto-update-at-reboot scheduled task if it exists, we don't want it to accidentally run unless we need it to.
if ( Get-ScheduledTask -TaskName "UpdateScriptAtStartup" -ErrorAction SilentlyContinue ) {
	$dateStrMin = Get-Date -UFormat "%Y.%m.%d-%H.%M.%S"
	echo "Successfully rebooted, removing the scheduled task to run at reboot for the next cycle" >> C:\ORGPREFIX\UpdatesLog.txt
	$LogPath = 'filesystem::\\ORGPREFIX-sharepointDSTORAGE.AD.DOMAIN.ORG\ORGPREFIXComputerLoginTracking$\WindowsUpdateLog.txt'
	If(Test-path -Path $LogPath){
		echo "$hostname $dateStrMin REBOOTED" >> \\ORGPREFIX-sharepointDSTORAGE.AD.DOMAIN.ORG\ORGPREFIXComputerLoginTracking$\WindowsUpdateLog.txt
	}
	schtasks /delete /f /tn "UpdateScriptAtStartup"
}

# If we previously completed the script but did NOT get to write to the network log, we need to try again.  If it works, delete the second scheduled task.
if ( Get-ItemProperty -path 'hklm:\Software\DOMAIN\' | Select-Object -ExpandProperty WriteCompleteFlag -ErrorAction SilentlyContinue ) {
	echo "We previously completed the script but haven't been able to write to the network log, let's try again." >> C:\ORGPREFIX\UpdatesLog.txt
	$dateStrMin = Get-Date -UFormat "%Y.%m.%d-%H.%M.%S"
	$LogPath = 'filesystem::\\ORGPREFIX-sharepointDSTORAGE.AD.DOMAIN.ORG\ORGPREFIXComputerLoginTracking$\WindowsUpdateLog.txt'
	If ( Test-path -Path $LogPath ) {
		echo "$hostname $dateStrMin COMPLETE" >> \\ORGPREFIX-sharepointDSTORAGE.AD.DOMAIN.ORG\ORGPREFIXComputerLoginTracking$\WindowsUpdateLog.txt
		if ( Get-ScheduledTask -TaskName "WriteCompleteToNetworkedLog" -ErrorAction SilentlyContinue ) {
			schtasks /delete /f /tn "WriteCompleteToNetworkedLog"
		}
		echo "-Removing HKLM:\SOFTWARE\DOMAIN\WriteCompleteFlag" >> C:\ORGPREFIX\UpdatesLog.txt
		Remove-ItemProperty -path HKLM:\Software\DOMAIN -name WriteCompleteFlag
		# Remove the local copy of the update script
		if ( Test-Path C:\ORGPREFIX\SCCM.WindowsUpdates.Manual.ps1 ) {
			echo "Removing C:\ORGPREFIX\SCCM.WindowsUpdates.Manual.ps1" >> C:\ORGPREFIX\UpdatesLog.txt
			remove-item C:\ORGPREFIX\SCCM.WindowsUpdates.Manual.ps1
		}
	} else {
		echo "Still can't write to the networked log, will try again in an hour." >> C:\ORGPREFIX\UpdatesLog.txt
		exit
	}
} 

$LogPath = 'filesystem::\\ORGPREFIX-sharepointDSTORAGE.AD.DOMAIN.ORG\ORGPREFIXComputerLoginTracking$\WindowsUpdateLog.txt'
if ( Test-path -Path $LogPath ) {
	echo "$hostname $dateStrMin START" >> \\ORGPREFIX-sharepointDSTORAGE.AD.DOMAIN.ORG\ORGPREFIXComputerLoginTracking$\WindowsUpdateLog.txt
}

# Test if we have already rebooted 5 times; if so, we're stuck in a cycle and should write-output an error and abort.
if ( Get-ItemProperty -path 'hklm:\Software\DOMAIN\' | Select-Object -ExpandProperty WindowsUpdatesRound5 -ErrorAction SilentlyContinue ) {
	echo "5 cycles are completed, something is wrong!" >> C:\ORGPREFIX\UpdatesLog.txt
	$dateStrMin = Get-Date -UFormat "%Y.%m.%d-%H.%M.%S"
	$LogPath = 'filesystem::\\ORGPREFIX-sharepointDSTORAGE.AD.DOMAIN.ORG\ORGPREFIXComputerLoginTracking$\WindowsUpdateLog.txt'
	If ( Test-path -Path $LogPath ) {
		echo "$hostname $dateStrMin ABORT" >> \\ORGPREFIX-sharepointDSTORAGE.AD.DOMAIN.ORG\ORGPREFIXComputerLoginTracking$\WindowsUpdateLog.txt
		if ( Get-ScheduledTask -TaskName "WriteAbortToNetworkedLog" -ErrorAction SilentlyContinue ) {
			schtasks /delete /f /tn "WriteAbortToNetworkedLog"
		}
	} else {
		echo "Creating a scheduled task to try to write to the networked log hourly, letting it know we aborted" >> C:\ORGPREFIX\UpdatesLog.txt
		if ( -not ( Get-ScheduledTask -TaskName "WriteAbortToNetworkedLog" -ErrorAction SilentlyContinue ) ) {
			schtasks /create /f /tn "WriteAbortToNetworkedLog" /sc HOURLY  /rl highest /ru system /tr "powershell.exe -file C:\ORGPREFIX\SCCM.WindowsUpdates.Manual.ps1"
		}
	}
	exit
}

# Copy all program installers locally as the sharepoint won't be accessible after a reboot for VPN clients
$AppPath = 'filesystem::\\ORGPREFIX-SCCM-01.AD.DOMAIN.ORG\SCCMPackageSources$'
If(Test-path -Path $AppPath){
	Copy-Item -Path "\\ORGPREFIX-sccm-01.ad.DOMAIN.org\SCCMPackageSources$\Adobe\Acrobat Reader\AcrobatReaderCurrent.exe" -Destination "C:\ORGPREFIX\"
	Copy-Item -Path "\\ORGPREFIX-sccm-01.ad.DOMAIN.org\SCCMPackageSources$\7-Zip\7-Zip.Current.exe" -Destination "C:\ORGPREFIX\"
	Copy-Item -Path "\\ORGPREFIX-sccm-01.ad.DOMAIN.org\SCCMPackageSources$\Notepad++\Notepad++.Current.exe" -Destination "C:\ORGPREFIX\"
	Copy-Item -Path "\\ORGPREFIX-sccm-01.ad.DOMAIN.org\SCCMPackageSources$\Notepad++\config.model.xml" -Destination "C:\ORGPREFIX\"
	Copy-Item -Path "\\ORGPREFIX-sccm-01.ad.DOMAIN.org\SCCMPackageSources$\VideoLAN\VLC\VLC.Current.exe" -Destination "C:\ORGPREFIX\"
	Copy-Item -Path "\\ORGPREFIX-sccm-01.ad.DOMAIN.org\SCCMPackageSources$\Google\Chrome\GoogleChrome.x64.Current.msi" -Destination "C:\ORGPREFIX\"
	Copy-Item -Path "\\ORGPREFIX-sccm-01.ad.DOMAIN.org\SCCMPackageSources$\Zoom\ZoomInstallerFull.Current.msi" -Destination "C:\ORGPREFIX\"
}

installWindowsUpdates >> C:\ORGPREFIX\UpdatesLog.txt

$dateStrMin = Get-Date -UFormat "%Y.%m.%d-%H.%M.%S"
echo "Updates script complete at $dateStrMin" >> C:\ORGPREFIX\UpdatesLog.txt
$LogPath = 'filesystem::\\ORGPREFIX-sharepointDSTORAGE.AD.DOMAIN.ORG\ORGPREFIXComputerLoginTracking$\WindowsUpdateLog.txt'
If ( Test-path -Path $LogPath ) {
	echo "$hostname $dateStrMin COMPLETE" >> \\ORGPREFIX-sharepointDSTORAGE.AD.DOMAIN.ORG\ORGPREFIXComputerLoginTracking$\WindowsUpdateLog.txt
	if ( Get-ScheduledTask -TaskName "WriteCompleteToNetworkedLog" -ErrorAction SilentlyContinue ) {
		schtasks /delete /f /tn "WriteCompleteToNetworkedLog"
	}
	# Remove the local copy of the update script
	if ( Test-Path C:\ORGPREFIX\SCCM.WindowsUpdates.Manual.ps1 ) {
		echo "Removing C:\ORGPREFIX\SCCM.WindowsUpdates.Manual.ps1" >> C:\ORGPREFIX\UpdatesLog.txt
		remove-item C:\ORGPREFIX\SCCM.WindowsUpdates.Manual.ps1
	}
} else {
	if ( -not ( Get-ScheduledTask -TaskName "WriteCompleteToNetworkedLog" -ErrorAction SilentlyContinue ) ) {
		echo "Creating a scheduled task to try to write to the networked log hourly, letting it know we completed" >> C:\ORGPREFIX\UpdatesLog.txt
		schtasks /create /tn "WriteCompleteToNetworkedLog" /sc HOURLY /rl highest /ru system /tr "powershell.exe -file C:\ORGPREFIX\SCCM.WindowsUpdates.Manual.ps1"
	}
	# Make sure there is a local copy of the script
	if ( -not ( Test-Path C:\ORGPREFIX\SCCM.WindowsUpdates.Manual.ps1 ) ) {
		echo  "Copying script to C:\ORGPREFIX\SCCM.WindowsUpdates.Manual.ps1" >> C:\ORGPREFIX\UpdatesLog.txt
		copy-item \\ORGPREFIX-sccm-01.ad.DOMAIN.org\SCCMMisc$\SCCM.WindowsUpdates.Manual.ps1 C:\ORGPREFIX\SCCM.WindowsUpdates.Manual.ps1
	}
	if ( -not ( Get-ItemProperty -path 'hklm:\Software\DOMAIN\' | Select-Object -ExpandProperty WriteCompleteFlag -ErrorAction SilentlyContinue ) ) {
		echo "-Creating HKLM:\SOFTWARE\DOMAIN\WriteCompleteFlag" >> C:\ORGPREFIX\UpdatesLog.txt
		new-itemproperty -path HKLM:\Software\DOMAIN -name WriteCompleteFlag -value TRUE
	}
}
