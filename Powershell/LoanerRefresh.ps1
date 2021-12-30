####
# 
# Name: LoanerRefresh
# Author: Joseph Gullo
# Last Modification: 2021.12.28
# Description: This is a catch-all script for updating computers 
#   targeted at generic users that are often found in drawers of 
#   remote offices.  If we find a computer somewhere, this script
#   revives and updates it without the need for reimaging if that's
#   the desired result.  Since writing this, we have relied more
#   heavily on reimaging as a solution as we have better SCCM
#   infrastructure in our remote offices.
# References: 
#
####

# Permit execution of powershell scripts in the future
Write-Host "Permitting future execution of PowerShell scripts"
Set-ExecutionPolicy RemoteSigned -Force

# Create a registry hive for tracking progress for future executions
if (!(Test-Path 'HKLM:\SOFTWARE\DOMAIN')) {
	New-Item -Path 'HKLM:\SOFTWARE' -Name DOMAIN
}

# Remove GPO connection to the WSUS server for the duration of this operation since we'll be contacting windows update directly.
Set-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "UseWUServer" -Value "0"

# Sometimes, despite Office being installed, windows update only installs updates for windows.  This tricks it into including office and other updates
$objServiceManager = New-Object -ComObject "Microsoft.Update.ServiceManager"
$objService = $objServiceManager.AddService2("7971f918-a847-4430-9279-4a52d1efe18d",7,"")
$objService.PSTypeNames.Clear()
$objService.PSTypeNames.Add('PSWindowsUpdate.WUServiceManager')
Restart-Service wuauserv

if (!(Get-ItemProperty -path 'hklm:\Software\DOMAIN\' | Select-Object -ExpandProperty ComputerRefreshCompletedStage1 -ErrorAction SilentlyContinue)) {
	# Install hotfix update to improve windows update speed #1
	if (!(get-hotfix -id KB3102810 -EA SilentlyContinue)) {
		Stop-Service wuauserv
		cd "\\ORGPREFIX-sharepointDSTORAGE.AD.DOMAIN.ORG\IT\Applications\Microsoft\Windows Updates\"
		Start-Process -Wait wusa -ArgumentList "Windows6.1-KB3102810-x64.msu /quiet /norestart" -NoNewWindow
		Start-Service wuauserv
		C:
	}
	
	# Write to the registry that this step has completed
	new-itemproperty -path HKLM:\Software\DOMAIN -name ComputerRefreshCompletedStage1 -value TRUE
	
	#Reboot if required
	$HKLM = [UInt32] "0x80000002"
	$WMI_Reg = [WMIClass] "\\localhost\root\default:StdRegProv" 
	$RegWUAURebootReq = $WMI_Reg.EnumKey($HKLM,"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\") 
	$WUAURebootReq = $RegWUAURebootReq.sNames -contains "RebootRequired"
	if ($WUAURebootReq -eq "True") {
		Restart-Computer
	}
}

if (!(Get-ItemProperty -path 'hklm:\Software\DOMAIN\' | Select-Object -ExpandProperty ComputerRefreshCompletedStage2 -ErrorAction SilentlyContinue)) {
	# Install hotfix update to improve windows update speed #2
	if (!(get-hotfix -id KB3172605 -EA SilentlyContinue)) {
		Stop-Service wuauserv
		cd "\\ORGPREFIX-sharepointDSTORAGE.AD.DOMAIN.ORG\IT\Applications\Microsoft\Windows Updates\"
		Start-Process -Wait wusa -ArgumentList "Windows6.1-KB3172605-x64.msu /quiet /norestart" -NoNewWindow
		Start-Service wuauserv
		C:
	}

	# Write to the registry that this step has completed
	new-itemproperty -path HKLM:\Software\DOMAIN -name ComputerRefreshCompletedStage2 -value TRUE

	#Reboot if required
	$HKLM = [UInt32] "0x80000002"
	$WMI_Reg = [WMIClass] "\\localhost\root\default:StdRegProv" 
	$RegWUAURebootReq = $WMI_Reg.EnumKey($HKLM,"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\") 
	$WUAURebootReq = $RegWUAURebootReq.sNames -contains "RebootRequired"
	if ($WUAURebootReq -eq "True") {
		Restart-Computer
	}
}

if (!(Get-ItemProperty -path 'hklm:\Software\DOMAIN\' | Select-Object -ExpandProperty ComputerRefreshCompletedStage3 -ErrorAction SilentlyContinue)) {
	# Install WinRM Hotfix to get Powershell 5.0
	$OSVersion = (get-itemproperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name ProductName).ProductName
	if ( ( !( get-hotfix -id KB3191566 -EA SilentlyContinue ) ) -AND ( $OSVersion -like "*Windows 7*" ) ) {
		Stop-Service wuauserv
		cd "\\ORGPREFIX-sharepointDSTORAGE.AD.DOMAIN.ORG\it\Applications\Microsoft\Windows Management Framework\5.1\Win7AndW2K8R2-KB3191566-x64"
		Start-Process -Wait wusa -ArgumentList "Win7AndW2K8R2-KB3191566-x64.msu /quiet /norestart" -NoNewWindow
		Start-Service wuauserv
		C:
	}

	# Write to the registry that this step has completed
	new-itemproperty -path HKLM:\Software\DOMAIN -name ComputerRefreshCompletedStage3 -value TRUE

	#Reboot if required
	$HKLM = [UInt32] "0x80000002"
	$WMI_Reg = [WMIClass] "\\localhost\root\default:StdRegProv" 
	$RegWUAURebootReq = $WMI_Reg.EnumKey($HKLM,"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\") 
	$WUAURebootReq = $RegWUAURebootReq.sNames -contains "RebootRequired"
	if ($WUAURebootReq -eq "True") {
		Restart-Computer
	}
}

if (!(Get-ItemProperty -path 'hklm:\Software\DOMAIN\' | Select-Object -ExpandProperty ComputerRefreshCompletedStage4 -ErrorAction SilentlyContinue)) {
	# If the local DOMAIN account doesn't exist, create it
	$checkAcct=get-wmiobject Win32_UserAccount -Filter "LocalAccount='true' and Name='DOMAIN'"
	if ($checkAcct -eq $null) {
		# Store security policies to a file
		$seceditpath="secedit"
		Start-Process -Wait "secedit" -ArgumentList "/export /cfg c:\secpol.cfg"
		# Replace stored security policies with one permitting poor passwords
		(Get-Content C:\secpol.cfg) -replace 'PasswordComplexity = 1', 'PasswordComplexity = 0' | Set-Content C:\secpol.cfg
		# Set the modified policy in the file to active
		$seceditargs="/configure /db c:\windows\security\local.sdb /cfg c:\secpol.cfg /areas SECURITYPOLICY"
		Start-Process -Wait $seceditpath $seceditargs
		# Create the user account
		$objOu = [ADSI]"WinNT://$env:COMPUTERNAME"
		$objUser = $objOU.Create("User", "DOMAIN")
		$objUser.setpassword("DOMAIN")
		$objUser.SetInfo()
		$objUser.description = "Local user account for loaner computers"
		$objUser.SetInfo()
		# Below code is from here: https://stackoverflow.com/questions/17616816/changing-user-properties-in-powershell
		$objUser.UserFlags = 64 + 65536 # ADS_UF_PASSWD_CANT_CHANGE + ADS_UF_DONT_EXPIRE_PASSWD
		$objUser.SetInfo()
		# Modify the stored policies to re-enable password complexity rules
		(Get-Content C:\secpol.cfg) -replace 'PasswordComplexity = 0', 'PasswordComplexity = 1' | Set-Content C:\secpol.cfg
		# Enact original stored policy with password complexity rules
		$seceditargs="/configure /db c:\windows\security\local.sdb /cfg c:\secpol.cfg /areas SECURITYPOLICY"
		Start-Process -Wait $seceditpath $seceditargs
		# Delete stored policies file
		rm -force c:\secpol.cfg -confirm:$false
	}

	# Write to the registry that this step has completed
	new-itemproperty -path HKLM:\Software\DOMAIN -name ComputerRefreshCompletedStage4 -value TRUE
}

if (!(Get-ItemProperty -path 'hklm:\Software\DOMAIN\' | Select-Object -ExpandProperty ComputerRefreshCompletedStage5 -ErrorAction SilentlyContinue)) {

	# Install Java
	#Write-Host "Installing Java Runtime Environment" -ForeGroundColor "Yellow"
	#$javapath="\\ORGPREFIX-sharepointDSTORAGE.AD.DOMAIN.ORG\IT\Applications\Java\Java.Current.exe"
	#$javaargs="/s"
	#Start-Process -Wait $javapath $javaargs -NoNewWindow
	
	# Uninstall ALL Older Java
	#Write-Host "Uninstalling Older Java Runtime Environment" -ForeGroundColor "Yellow"
	#$Java = @()
	#$Versions = @()
	# Perform WMI query to find installed Java Updates
	#$Java += Get-WmiObject -Class Win32_Product | Where-Object { 
		#$_.Name -match "(?i)Java(\(TM\))*\s\d+(\sUpdate\s\d+)*.*$"
	#}
	##Also find Java version 5, but handled slightly different as CPU bit is only distinguishable by the GUID
	#$Java += Get-WmiObject -Class Win32_Product | Where-Object { 
		#($_.Name -match "(?i)J2SE\sRuntime\sEnvironment\s\d[.]\d(\sUpdate\s\d+)*.*$") 
	#}
	## Enumerate and populate array of versions
	#Foreach ($app in $Java) {
		#if ($app -ne $null) { $Versions += $app.Version }
	#}
	##Create an array that is sorted correctly by the actual Version (as a System.Version object) rather than by value.
	#$sortedVersions = $Versions | %{ New-Object System.Version ($_) } | sort
	##If a single result is returned, convert the result into a single value array so we don't run in to trouble calling .GetUpperBound later
	#if($sortedVersions -isnot [system.array]) { $sortedVersions = @($sortedVersions)}
	## Grab the value of the newest version from the array, first converting 
	#$newestVersion = $sortedVersions[$sortedVersions.GetUpperBound(0)]
	#Foreach ($app in $Java) {
		#if ($app -ne $null)
		#{
			## Remove all versions of Java, where the version does not match the newest version.
			#if (($app.Version -ne $newestVersion) -and ($newestVersion -ne $null)) {
				#$appGUID = $app.Properties["IdentifyingNumber"].Value.ToString()
				#Start-Process -FilePath "msiexec.exe" -ArgumentList "/qn /norestart /x $($appGUID)" -Wait -Passthru -NoNewWindow
				##Write-Host "Uninstalling version: " $app
			#}
		#}
	#}

	# Install Acrobat Reader
	Write-Host "Installing Adobe Acrobat Reader" -ForeGroundColor "Yellow"
	$acrobatpath="\\ORGPREFIX-sharepointDSTORAGE.AD.DOMAIN.ORG\IT\Applications\Adobe\Acrobat Reader\AcrobatReaderCurrent.exe"
	$acrobatargs="/sAll /rs"
	Start-Process -Wait $acrobatpath $acrobatargs -NoNewWindow
	# Delete shortcuts on the desktop
	if ( Test-Path "C:\Users\Public\Desktop\" ) {
		remove-item -Path "C:\Users\Public\Desktop\*Acrobat*.lnk"
	}
	if ( Test-Path "C:\Users\All Users\Desktop\" ) {
		remove-item -Path "C:\Users\All Users\Desktop\*Acrobat*.lnk"
	}

	
	# Install Adobe Flash Player Plugins
	Write-Host "Installing Adobe Flash Player Plugins" -ForeGroundColor "Yellow"
	cd "\\ORGPREFIX-sharepointDSTORAGE.AD.DOMAIN.ORG\IT\Applications\Adobe\Adobe Flash Player\"
	Start-Process -Wait "./FlashPlayerPluginCurrent.ActiveX.exe" -ArgumentList "-install" -NoNewWindow
	Start-Process -Wait "./FlashPlayerPluginCurrent.NPAPI.exe" -ArgumentList "-install" -NoNewWindow
	Start-Process -Wait "./FlashPlayerPluginCurrent.PPAPI.exe" -ArgumentList "-install" -NoNewWindow
	# Disable Flash Auto-Updater
	if ( Test-Path "C:\Windows\SysWOW64\Macromed\Flash\mms.cfg" -PathType Leaf ) {
		copy-item "\\ORGPREFIX-SCCM-01\SCCMPackageSources$\Adobe\Flash Player\ORGPREFIX.Auto-Update.Disable\mms.cfg" -Destination "C:\Windows\SysWOW64\Macromed\Flash\" -ErrorAction SilentlyContinue
	}
	if ( Test-Path "C:\Windows\System32\Macromed\Flash\mms.cfg" -PathType Leaf ) {
		copy-item "\\ORGPREFIX-SCCM-01\SCCMPackageSources$\Adobe\Flash Player\ORGPREFIX.Auto-Update.Disable\mms.cfg" -Destination "C:\Windows\System32\Macromed\Flash\" -ErrorAction SilentlyContinue
	}
	C:
	
	# Install Adobe Shockwave Player
#	Write-Host "Installing Adobe Shockwave Player" -ForeGroundColor "Yellow"
#	cd "\\ORGPREFIX-sharepointDSTORAGE.AD.DOMAIN.ORG\IT\Applications\Adobe\Adobe Shockwave Player"
#	Start-Process -Wait "./AdobeShockwaveCurrentInstaller.exe" -ArgumentList "/S" -NoNewWindow
#	C:
	
	# Install Citrix Receiver
	#Write-Host "Installing Citrix Receiver" -ForeGroundColor "Yellow"
	#cd "\\ORGPREFIX-sharepointDSTORAGE.AD.DOMAIN.ORG\IT\Applications\Citrix\Receiver\"
	#Start-Process -Wait "./CitrixReceiver.Current.Windows.exe" -ArgumentList "/noreboot /silent /EnableCEIP=false /ALLOWADDSTORE=N" -NoNewWindow
#	Write-Host "Installing Citrix Workspace" -ForeGroundColor "Yellow"
#	cd "\\ORGPREFIX-sharepointDSTORAGE.AD.DOMAIN.ORG\IT\Applications\Citrix\Citrix Workspace for Windows\"
#	$CitrixVersionCurrent = (Get-Item CitrixWorkspaceApp.Current.exe).VersionInfo.FileVersion
#	$CitrixVersionInstalled = (Get-WMIObject -Class Win32_Product -Filter "Name LIKE '%Citrix%Workspace%Aero%'").Version
#	$CitrixReceiverInstalled = (Get-WMIObject -Class Win32_Product -Filter "Name LIKE '%Citrix%Receiver%Aero%'").Version
#	if ( -not ( [string]::IsNullOrEmpty( $CitrixReceiverInstalled ) ) ) {
#		Write-Host "----Uninstalling Citrix Receiver $CitrixReceiverInstalled" -ForeGroundColor "Yellow"
#		cd "\\ORGPREFIX-sharepointDSTORAGE.AD.DOMAIN.ORG\IT\Applications\Citrix\Receiver\"
#		Start-Process -Wait "./CitrixReceiver.Current.Windows.exe" -ArgumentList "/silent /uninstall" -NoNewWindow
#		cd "\\ORGPREFIX-sharepointDSTORAGE.AD.DOMAIN.ORG\IT\Applications\Citrix\Citrix Workspace for Windows\"
#	}
#	if ( [string]::IsNullOrEmpty( $CitrixVersionInstalled ) ) {
#		Write-Host "----Citrix Workspace Isn't Installed, Installing Citrix Workspace $CitrixVersionCurrent" -ForeGroundColor "Yellow"
#		Start-Process -Wait "./CitrixWorkspaceApp.Current.exe" -ArgumentList "/noreboot /silent EnableCEIP=false ALLOWADDSTORE=N SELFSERVICEMODE=False /AutoUpdateCheck=disabled /DeferUpdateCount=-1 /ALLOW_BIDIRCONTENTREDIRECTION=1 /FORCE_LAA=1" -NoNewWindow
#	} elseif ( $CitrixVersionCurrent -ne $CitrixVersionInstalled ) {
#		Write-Host "----Upgrading Citrix Workspace $CitrixVersionCurrent" -ForeGroundColor "Yellow"
#		Start-Process -Wait "./CitrixWorkspaceApp.Current.exe" -ArgumentList "/RCU /noreboot /silent EnableCEIP=false ALLOWADDSTORE=N SELFSERVICEMODE=False /AutoUpdateCheck=disabled /DeferUpdateCount=-1 /ALLOW_BIDIRCONTENTREDIRECTION=1 /FORCE_LAA=1" -NoNewWindow
#	} else {
#		Write-Host "----Citrix Workspace is already at the right version, doing nothing!" -ForeGroundColor "Yellow"
#	}
#	C:

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

	# Install Google Chrome
	Write-Host "Installing Google Chrome" -ForeGroundColor "Yellow"
	cd "\\ORGPREFIX-sharepointDSTORAGE.AD.DOMAIN.ORG\IT\Applications\Google\Chrome\"
	Start-Process -Wait "msiexec" -ArgumentList "/i GoogleChrome.x64.Current.msi /qn" -NoNewWindow
	C:
	
	# Install VLC
	Write-Host "Installing VLC" -ForeGroundColor "Yellow"
	cd "\\ORGPREFIX-sharepointDSTORAGE.AD.DOMAIN.ORG\it\Applications\VLC"
	Start-Process -Wait ".\VLC.Current.exe" -ArgumentList "/S" -NoNewWindow
	# Delete shortcuts on the desktop
	if ( Test-Path "C:\Users\Public\Desktop\" ) {
		remove-item -Path "C:\Users\Public\Desktop\*VLC*.lnk"
	}
	if ( Test-Path "C:\Users\All Users\Desktop\" ) {
		remove-item -Path "C:\Users\All Users\Desktop\*VLC*.lnk"
	}
	C:
<#
	# Install Office 2016 ProPlus x64
	Write-Host "Installing Microsoft Office 2016 ProPlus x64" -ForeGroundColor "Yellow"
	$objCRM=Get-WmiObject -class Win32_product -filter "Name LIKE '%Dynamics CRM%'"
	if ($objCRM -eq $null) {
		Write-Host "--Dynamics CRM plugin is not installed, proceeding!" -ForeGroundColor "Yellow"
		$obj=Get-WmiObject -class Win32_product -filter "Name LIKE 'Microsoft Office%Outlook%2016%'"
		if ($obj -eq $null) {
			Write-Host "--Office 2016 is NOT installed, installing it!" -ForeGroundColor "Yellow"
			$obj2010=Get-WmiObject -class Win32_product -filter "Name LIKE 'Microsoft Office%Outlook%2010%'"
			if ($obj2010 -ne $null) {
				Write-Host "--Office 2010 is installed, uninstalling it!" -ForeGroundColor "Yellow"
				cd "\\ORGPREFIX-sharepointDSTORAGE.AD.DOMAIN.ORG\IT\Applications\Microsoft\Office\Office 2010\Office 2010 proplus 32 bit\"
				Start-Process -Wait "./setup.exe" -ArgumentList "/uninstall ProPlus /config .\UninstallConfig.xml" -NoNewWindow
				C:
			} else {
				Write-Host "--Office 2010 is NOT installed, proceeding!" -ForeGroundColor "Yellow"
			}
			cd "\\ORGPREFIX-sharepointDSTORAGE.AD.DOMAIN.ORG\it\Applications\Microsoft\Office\Office 2016 ProPlus x64\"
			Start-Process -Wait "./setup.exe" -ArgumentList "/adminfile DOMAIN.MSP" -NoNewWindow
			C:
			Copy-Item -Path '\\ORGPREFIX-SCCM-01\SCCMPackageSources$\ORGPREFIX Packages\Windows 10 OSD Settings\Windows 10 OSD Settings 1809\Internet Explorer.lnk' -Destination 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories' -ErrorAction SilentlyContinue
			mkdir "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Office"
			remove-item "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Office\Microsoft Excel.lnk" -ErrorAction SilentlyContinue
			remove-item "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Office\Microsoft OneNote.lnk" -ErrorAction SilentlyContinue
			remove-item "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Office\Microsoft Outlook.lnk" -ErrorAction SilentlyContinue
			remove-item "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Office\Microsoft PowerPoint.lnk" -ErrorAction SilentlyContinue
			remove-item "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Office\Microsoft Publisher.lnk" -ErrorAction SilentlyContinue
			remove-item "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Office\Microsoft Word.lnk" -ErrorAction SilentlyContinue
			mv "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Excel 2016.lnk" "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Office\Microsoft Excel.lnk" -ErrorAction SilentlyContinue
			mv "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\OneNote 2016.lnk" "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Office\Microsoft OneNote.lnk" -ErrorAction SilentlyContinue
			mv "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Outlook 2016.lnk" "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Office\Microsoft Outlook.lnk" -ErrorAction SilentlyContinue
			mv "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\PowerPoint 2016.lnk" "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Office\Microsoft PowerPoint.lnk" -ErrorAction SilentlyContinue
			mv "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Publisher 2016.lnk" "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Office\Microsoft Publisher.lnk" -ErrorAction SilentlyContinue
			mv "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Word 2016.lnk" "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Office\Microsoft Word.lnk" -ErrorAction SilentlyContinue
		} else {
			Write-Host "--Office 2016 IS installed, exiting!" -ForeGroundColor "Yellow"
		}
	} else {
		Write-Host "--Dynamics CRM plugin is installed, this is not a candidate for Office 2016!" -ForeGroundColor "Yellow"
	}
#>

	# Install Skype for Business 2016 Client
<#	Write-Host "Installing Microsoft Skype for Business 2015" -ForeGroundColor "Yellow"
	# Detect if Skype for Business is already installed:
	if ( ( Get-WmiObject -class Win32_product -filter "Name LIKE '%Skype%for%Business%'" ) -eq $null ) {
		while ( ( Get-Process OUTLOOK -ErrorAction SilentlyContinue ) -ne $null ) {
			Stop-Process -Name OUTLOOK -Force
			sleep 10
		}
		New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT
		if ( ( Get-WmiObject -class Win32_product -filter "Name LIKE 'Microsoft Office%Outlook%2010%'" ) -ne $null) {
			$bitness=Get-ItemProperty -path 'hklm:\Software\Microsoft\Office\14.0\Outlook\' | Select-Object -ExpandProperty Bitness -ErrorAction SilentlyContinue
			If ( $bitness -eq 'x86' ) {
				cd "\\ORGPREFIX-sharepointDSTORAGE.AD.DOMAIN.ORG\IT\Applications\Microsoft\Skype For Business 2016 Client\lyncentry_4417-1000_x86_en-us\"
				Start-Process -Wait "./setup.exe" -ArgumentList "/config config.xml" -NoNewWindow
				rm "C:\Program Files (x86)\Microsoft Office\Office16\UCAddin.dll"
			} ElseIf ( $bitness -eq 'x64' ) {
				cd "\\ORGPREFIX-sharepointDSTORAGE.AD.DOMAIN.ORG\IT\Applications\Microsoft\Skype For Business 2016 Client\lyncentry_4417-1000_x64_en-us\"
				Start-Process -Wait "./setup.exe" -ArgumentList "/config config.xml" -NoNewWindow
				rm "C:\Program Files\Microsoft Office\Office16\UCAddin.dll"
			}
			while ( ( Get-Process setup -ErrorAction SilentlyContinue ) -ne $null ) {
				sleep 10
			}
			If ( $bitness -eq 'x86' ) {
				C:
				cd "C:\Program Files (x86)\Microsoft Office\Office14\"
				./OUTLOOK.EXE
			} ElseIf ( $bitness -eq 'x64' ) {
				C:
				cd "C:\Program Files\Microsoft Office\Office14\"
				./OUTLOOK.EXE
			}
			sleep 30
			while ( ( Get-Process OUTLOOK -ErrorAction SilentlyContinue ) -ne $null ) {
				Stop-Process -Name OUTLOOK -Force
				sleep 10
			}
			if ( ( Get-Item -path 'HKCR:\TypeLib\{2DF8D04C-5BFA-101B-BDE5-00AA0044DE52}\2.8' -ErrorAction SilentlyContinue ) -ne $null ) {
				Remove-Item -Path "HKCR:\TypeLib\{2DF8D04C-5BFA-101B-BDE5-00AA0044DE52}\2.8" -Force -Recurse
			}
		} ElseIf ( ( Get-WmiObject -class Win32_product -filter "Name LIKE 'Microsoft%Outlook%2016%'" ) -ne $null) {
			$bitness=Get-ItemProperty -path 'hklm:\Software\Microsoft\Office\16.0\Outlook\' | Select-Object -ExpandProperty Bitness -ErrorAction SilentlyContinue
			If ( $bitness -eq 'x86' ) {
				cd "\\ORGPREFIX-sharepointDSTORAGE.AD.DOMAIN.ORG\IT\Applications\Microsoft\Skype For Business 2016 Client\lyncentry_4417-1000_x86_en-us\"
				Start-Process -Wait "./setup.exe" -ArgumentList "/config config.xml" -NoNewWindow
				rm "C:\Program Files (x86)\Microsoft Office\Office16\UCAddin.dll"
			} ElseIf ( $bitness -eq 'x64' ) {
				cd "\\ORGPREFIX-sharepointDSTORAGE.AD.DOMAIN.ORG\IT\Applications\Microsoft\Skype For Business 2016 Client\lyncentry_4417-1000_x64_en-us\"
				Start-Process -Wait "./setup.exe" -ArgumentList "/config config.xml" -NoNewWindow
				rm "C:\Program Files\Microsoft Office\Office16\UCAddin.dll"
			}
			while ( ( Get-Process setup -ErrorAction SilentlyContinue ) -ne $null ) {
				sleep 10
			}
			If ( $bitness -eq 'x86' ) {
				C:
				cd "C:\Program Files (x86)\Microsoft Office\Office16\"
				./OUTLOOK.EXE
			} ElseIf ( $bitness -eq 'x64' ) {
				C:
				cd "C:\Program Files\Microsoft Office\Office16\"
				./OUTLOOK.EXE
			}
			sleep 30
			while ( ( Get-Process OUTLOOK -ErrorAction SilentlyContinue ) -ne $null ) {
				Stop-Process -Name OUTLOOK -Force
				sleep 10
			}
			if ( ( Get-Item -path 'HKCR:\TypeLib\{2DF8D04C-5BFA-101B-BDE5-00AA0044DE52}\2.5' -ErrorAction SilentlyContinue ) -ne $null ) {
				Remove-Item -Path "HKCR:\TypeLib\{2DF8D04C-5BFA-101B-BDE5-00AA0044DE52}\2.5" -Force -Recurse
			}
		} 
		if ( ( Get-Item -path 'HKCR:\TypeLib\{2DF8D04C-5BFA-101B-BDE5-00AA0044DE52}\2.4' -ErrorAction SilentlyContinue ) -ne $null ) {
			Remove-Item -Path "HKCR:\TypeLib\{2DF8D04C-5BFA-101B-BDE5-00AA0044DE52}\2.4" -Force -Recurse
		}
		if ( ( Get-Item -path 'HKCR:\TypeLib\{2DF8D04C-5BFA-101B-BDE5-00AA0044DE52}\2.6' -ErrorAction SilentlyContinue ) -ne $null ) {
			Remove-Item -Path "HKCR:\TypeLib\{2DF8D04C-5BFA-101B-BDE5-00AA0044DE52}\2.6" -Force -Recurse
		}
		if ( ( Get-Item -path 'HKCR:\TypeLib\{2DF8D04C-5BFA-101B-BDE5-00AA0044DE52}\2.7' -ErrorAction SilentlyContinue ) -ne $null ) {
			Remove-Item -Path "HKCR:\TypeLib\{2DF8D04C-5BFA-101B-BDE5-00AA0044DE52}\2.7" -Force -Recurse
		}
		C:
	} 
#>

<#	
	# Install Trend Micro OfficeScan
	Write-Host "Installing TrendMicro OfficeScan" -ForeGroundColor "Yellow"
	$obj=Get-WmiObject -class Win32_product -filter "Name LIKE '%OfficeScan%'"
	if ($obj -eq $null) {
		cd "\\ORGPREFIX-sharepointDSTORAGE.AD.DOMAIN.ORG\IT\Applications\Trend-AV\"
		Start-Process -Wait "./clientpackXG.Current.msi" -NoNewWindow
		C:
	}
#>
	
	# Write to the registry that this step has completed
	new-itemproperty -path HKLM:\Software\DOMAIN -name ComputerRefreshCompletedStage5 -value TRUE
}

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
		( $Result.Updates.Item($Counter).Title -like "*LaserJet*" ) -OR (
			#( $Result.Updates.Item($Counter).Title -like "*Skype*" ) -OR (
				( $Result.Updates.Item($Counter).Title -like "*Security Essentials*" ) -OR (
					$Result.Updates.Item($Counter).Title -like "*DOT4PAR*"
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
					( $Result.Updates.Item($Counter).Title -like "*Security Essentials*" ) -OR ( 
						$Result.Updates.Item($Counter).Title -like "*DOT4PAR*"
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
Write-Host "There are no applicable updates for this computer."

$OSVersion = (get-itemproperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name ProductName).ProductName
If($OSVersion -like "*Windows 10*")
{

	Write-Host "Restoring Windows Photo Viewer" -ForeGroundColor "Yellow"
	if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\Applications\photoviewer.dll") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\Applications\photoviewer.dll" -force -ea SilentlyContinue };
	if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\Applications\photoviewer.dll\shell") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\Applications\photoviewer.dll\shell" -force -ea SilentlyContinue };
	if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\Applications\photoviewer.dll\shell\open") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\Applications\photoviewer.dll\shell\open" -force -ea SilentlyContinue };
	if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\Applications\photoviewer.dll\shell\open\command") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\Applications\photoviewer.dll\shell\open\command" -force -ea SilentlyContinue };
	if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\Applications\photoviewer.dll\shell\open\DropTarget") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\Applications\photoviewer.dll\shell\open\DropTarget" -force -ea SilentlyContinue };
	if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\Applications\photoviewer.dll\shell\print") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\Applications\photoviewer.dll\shell\print" -force -ea SilentlyContinue };
	if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\Applications\photoviewer.dll\shell\print\command") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\Applications\photoviewer.dll\shell\print\command" -force -ea SilentlyContinue };
	if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\Applications\photoviewer.dll\shell\print\DropTarget") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\Applications\photoviewer.dll\shell\print\DropTarget" -force -ea SilentlyContinue };
	New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Applications\photoviewer.dll\shell\open' -Name 'MuiVerb' -Value "@photoviewer.dll,-3043" -PropertyType String -Force -ea SilentlyContinue;
	New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Applications\photoviewer.dll\shell\open\command' -Name '(default)' -Value '%SystemRoot%\System32\rundll32.exe "%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll", ImageView_Fullscreen %1' -PropertyType ExpandString -Force -ea SilentlyContinue;
	New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Applications\photoviewer.dll\shell\open\DropTarget' -Name 'Clsid' -Value "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}" -PropertyType String -Force -ea SilentlyContinue;
	New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Applications\photoviewer.dll\shell\print\command' -Name '(default)' -Value '%SystemRoot%\System32\rundll32.exe "%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll", ImageView_Fullscreen %1' -PropertyType ExpandString -Force -ea SilentlyContinue;
	New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Applications\photoviewer.dll\shell\print\DropTarget' -Name 'Clsid' -Value "{60fd46de-f830-4894-a628-6fa81bc0190d}" -PropertyType String -Force -ea SilentlyContinue;

	Write-Host "Removing Built-In Windows 10 Apps" -ForeGroundColor "Yellow"
	Get-AppxPackage -AllUsers -name "*Actipro*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
	Get-AppxPackage -AllUsers -name "*DuoLingo*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
	Get-AppxPackage -AllUsers -name "*Eclipse*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
	Get-AppxPackage -AllUsers -name "*PhotoshopExpress*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
	Get-AppxPackage -AllUsers -name Microsoft.3DBuilder | Remove-AppxPackage  -AllUsers -ErrorAction SilentlyContinue                             # Gone In 1709
	Get-AppxPackage -AllUsers -name Microsoft.Advertising.Xaml | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
	<# Get-AppxPackage -AllUsers -name Microsoft.AsyncTextService | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue                    # New In 1809 # Part Of Windows #>
	Get-AppxPackage -AllUsers -name Microsoft.BingFinance | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue                            # Gone
	Get-AppxPackage -AllUsers -name Microsoft.BingNews | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue                               # Gone
	Get-AppxPackage -AllUsers -name Microsoft.BingSports | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue                             # Gone
	Get-AppxPackage -AllUsers -name Microsoft.BingWeather | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
	Get-AppxPackage -AllUsers -name Microsoft.BingWeather | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
	<# Get-AppxPackage -AllUsers -name Microsoft.BioEnrollment | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue                       # New In 1809 # Part Of Windows #>
	<# Get-AppxPackage -AllUsers -name Microsoft.CredDialogHost | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue                      # Part Of Windows #>
	<# Get-AppxPackage -AllUsers -name Microsoft.DesktopAppInstaller | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue                 # Reinstated to re-enable Windows Store #>
	<# Get-AppxPackage -AllUsers -name Microsoft.ECApp | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue                               # New In 1709 # Part Of Windows #>
	Get-AppxPackage -AllUsers -name Microsoft.FreshPaint | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue                             # Gone
	Get-AppxPackage -AllUsers -name Microsoft.GetHelp | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue                                # New In 1709
	Get-AppxPackage -AllUsers -name Microsoft.Getstarted | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
	Get-AppxPackage -AllUsers -name Microsoft.HEIFImageExtension | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue                     # New In 1809
	Get-AppxPackage -AllUsers -name Microsoft.Messaging | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
	Get-AppxPackage -AllUsers -name Microsoft.Microsoft3DViewer | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
	<# Get-AppxPackage -AllUsers -name Microsoft.MicrosoftEdge | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue                       # Part Of Windows #>
	<# Get-AppxPackage -AllUsers -name Microsoft.MicrosoftEdgeDevToolsClient | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue         # New In 1803 # Part Of Windows #>
	Get-AppxPackage -AllUsers -name Microsoft.MicrosoftOfficeHub | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
	Get-AppxPackage -AllUsers -name Microsoft.MicrosoftSolitaireCollection | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
	Get-AppxPackage -AllUsers -name Microsoft.MicrosoftStickyNotes | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
	Get-AppxPackage -AllUsers -name Microsoft.MixedReality.Portal | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue                    # New In 1809
	Get-AppxPackage -AllUsers -name Microsoft.MSPaint | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
	Get-AppxPackage -AllUsers -name Microsoft.NetworkSpeedTest | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
	Get-AppxPackage -AllUsers -name Microsoft.Office.OneNote | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
	Get-AppxPackage -AllUsers -name Microsoft.Office.Sway | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue                            # Gone
	Get-AppxPackage -AllUsers -name Microsoft.OneConnect | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
	Get-AppxPackage -AllUsers -name Microsoft.People | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
	<# Get-AppxPackage -AllUsers -name Microsoft.PPIProjection | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue                       # Part Of Windows #>
	Get-AppxPackage -AllUsers -name Microsoft.Print3D | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue                                # New In 1709
	Get-AppxPackage -AllUsers -name Microsoft.RemoteDesktop | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue                          # Gone In 1803
	<# Get-AppxPackage -AllUsers -name Microsoft.ScreenSketch | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue                        # New In 1809 # Reinstated to re-enable Windows Store #>
	Get-AppxPackage -AllUsers -name Microsoft.Services.Store.Engagement | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue              # New In 1709
	Get-AppxPackage -AllUsers -name Microsoft.SkypeApp | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
	Get-AppxPackage -AllUsers -name Microsoft.StorePurchaseApp | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
	Get-AppxPackage -AllUsers -name Microsoft.Wallet | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
	Get-AppxPackage -AllUsers -name Microsoft.WebMediaExtensions | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue                     # New In 1803
	Get-AppxPackage -AllUsers -name Microsoft.WebpImageExtension | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue                     # New In 1809
	<# Get-AppxPackage -AllUsers -name Microsoft.Windows.Apprep.ChxApp | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue               # Part Of Windows #>
	<# Get-AppxPackage -AllUsers -name Microsoft.Windows.AssignedAccessLockApp | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue       # Part Of Windows #>
	<# Get-AppxPackage -AllUsers -name Microsoft.Windows.CapturePicker | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue               # New In 1803 # Part Of Windows #>
	<# Get-AppxPackage -AllUsers -name Microsoft.Windows.CloudExperienceHost | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue         # Part Of Windows #>
	<# Get-AppxPackage -AllUsers -name Microsoft.Windows.ContentDeliveryManager | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue      # Part Of Windows #>
	<# Get-AppxPackage -AllUsers -name Microsoft.Windows.Cortana | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue                     # Part Of Windows #>
	<# Get-AppxPackage -AllUsers -name Microsoft.Windows.NarratorQuickStart | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue          # Part Of Windows #>
	<# Get-AppxPackage -AllUsers -name Microsoft.Windows.ParentalControls | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue            # Part Of Windows #>
	<# Get-AppxPackage -AllUsers -name Microsoft.Windows.PeopleExperienceHost | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue        # Part Of Windows #>
	<# Get-AppxPackage -AllUsers -name Microsoft.Windows.Photos | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue                      # Reinstated to re-enable Windows Store #>
	<# Get-AppxPackage -AllUsers -name Microsoft.Windows.PinningConfirmationDialog | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue   # Part Of Windows #>
	<# Get-AppxPackage -AllUsers -name Microsoft.Windows.SecHealthUI | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue                 # Part Of Windows #>
	<# Get-AppxPackage -AllUsers -name Microsoft.Windows.SecureAssessmentBrowser | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue     # Part Of Windows #>
	<# Get-AppxPackage -AllUsers -name Microsoft.Windows.ShellExperienceHost | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue         # Part Of Windows #>
	<# Get-AppxPackage -AllUsers -name Microsoft.Windows.XGpuEjectDialog | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue             # Part Of Windows #>
	Get-AppxPackage -AllUsers -name Microsoft.WindowsAlarms | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
	<# Get-AppxPackage -AllUsers -name Microsoft.WindowsCalculator | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue                   # Reinstated to re-enable Windows Store #>
	Get-AppxPackage -AllUsers -name Microsoft.WindowsCamera | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
	Get-AppxPackage -AllUsers -name microsoft.windowscommunicationsapps | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
	Get-AppxPackage -AllUsers -name microsoft.WindowsFeedbackHub | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
	Get-AppxPackage -AllUsers -name Microsoft.WindowsMaps | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
	Get-AppxPackage -AllUsers -name Microsoft.WindowsPhone | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue                           # Gone
	Get-AppxPackage -AllUsers -name Microsoft.WindowsSoundRecorder | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
	<# Get-AppxPackage -AllUsers -name Microsoft.WindowsStore | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue                        # Reinstated to re-enable Windows Store #>
	Get-AppxPackage -AllUsers -name Microsoft.Xbox.TCUI | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
	Get-AppxPackage -AllUsers -name Microsoft.XboxApp | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
	<# Get-AppxPackage -AllUsers -name Microsoft.XboxGameCallableUI | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue                  # Part Of Windows #>
	Get-AppxPackage -AllUsers -name Microsoft.XboxGameOverlay | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
	Get-AppxPackage -AllUsers -name Microsoft.XboxGamingOverlay | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
	Get-AppxPackage -AllUsers -name Microsoft.XboxIdentityProvider | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
	Get-AppxPackage -AllUsers -name Microsoft.XboxSpeechToTextOverlay | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
	Get-AppxPackage -AllUsers -name Microsoft.YourPhone | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue                              # New In 1809
	Get-AppxPackage -AllUsers -name Microsoft.ZuneMusic | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
	Get-AppxPackage -AllUsers -name Microsoft.ZuneVideo | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
	<# Get-AppxPackage -AllUsers -name Windows.CBSPreview | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue                            # Part Of Windows #>
	<# Get-AppxPackage -AllUsers -name Windows.immersivecontrolpanel | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue                 # Part Of Windows #>
	<# Get-AppxPackage -AllUsers -name Windows.PrintDialog | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue                           # Part Of Windows #>
}

# Set-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "UseWUServer" -Value "1"
Restart-Service wuauserv

# Perform Disk Cleanup on C:
# Create reg keys
$volumeCaches = Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches"
foreach($key in $volumeCaches)
{
    New-ItemProperty -Path "$($key.PSPath)" -Name StateFlags0099 -Value 2 -Type DWORD -Force | Out-Null
}
# Run Disk Cleanup 
Start-Process -Wait "$env:SystemRoot\System32\cleanmgr.exe" -ArgumentList "/sagerun:99"
# Delete the keys
$volumeCaches = Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches"
foreach($key in $volumeCaches)
{
    Remove-ItemProperty -Path "$($key.PSPath)" -Name StateFlags0099 -Force | Out-Null
}

# Defragment C:
#Use WMI to get the disk volume via the Win32_Volume class 
$Volume = Get-WmiObject -ComputerName 'localhost' -Class win32_volume -Filter "DriveLetter='C:'" 
Write-Verbose "Volume retrieved successfully.."     
#Call the defrag method on the wmi object 
$Defrag = $Volume.Defrag($false) 
#Check the defragmentation results and inform the user of any errors 
Switch ($Defrag.ReturnValue) { 
	0 { Write-Verbose "Defragmentation completed successfully..." } 
	1 { Write-Error -Message "Defragmentation of volume $DriveLetter on $ComputerName failed: Access Denied" } 
	2 { Write-Error -Message "Defragmentation of volume $DriveLetter on $ComputerName failed: Defragmentation is not supported for this volume" } 
	3 { Write-Error -Message "Defragmentation of volume $DriveLetter on $ComputerName failed: Volume dirty bit is set" } 
	4 { Write-Error -Message "Defragmentation of volume $DriveLetter on $ComputerName failed: Insufficient disk space" } 
	5 { Write-Error -Message "Defragmentation of volume $DriveLetter on $ComputerName failed: Corrupt master file table detected" } 
	6 { Write-Error -Message "Defragmentation of volume $DriveLetter on $ComputerName failed: The operation was cancelled" } 
	7 { Write-Error -Message "Defragmentation of volume $DriveLetter on $ComputerName failed: The operation was cancelled" } 
	8 { Write-Error -Message "Defragmentation of volume $DriveLetter on $ComputerName failed: A disk defragmentation is already in process" } 
	9 { Write-Error -Message "Defragmentation of volume $DriveLetter on $ComputerName failed: Unable to connect to the defragmentation engine" } 
	10 { Write-Error -Message "Defragmentation of volume $DriveLetter on $ComputerName failed: A defragmentation engine error occurred" } 
	11 { Write-Error -Message "Defragmentation of volume $DriveLetter on $ComputerName failed: Unknown error" } 
}  

# Delete registry hive for tracking progress for future executions
Remove-Item -Path HKLM:\Software\DOMAIN

Write-Host "Everything completed!  Reboot into the .\DOMAIN account to make sure it works."

