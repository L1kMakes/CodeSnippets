####
# 
# Name: Audit.UserProfileSize
# Author: Joseph Gullo
# Last Modification: 2021.12.28
# Description: This searches the various repositories of user
#   data to aggregate a complete filesize of a user's data
# References: Various snippets of code adapted from many web 
#   searches, the sources of which are long lost
#
####

#clear-host
$dateStrMin = Get-Date -UFormat "%Y.%m.%d-%H.%M.%S"
$Today = (Get-Date)
$outFile = "Audit.UserStorageQuotas.$dateStrMin.log"
$csvOutFile = "Audit.UserStorageQuotas.$dateStrMin.csv"
#write-output "FullName,Username,ProfileSize(GB),VDIProfileSize(GB),EMAILangeMailboxSize(GB),TotalSize(GB)"
#write-output "FullName,Username,ProfileSize(GB),VDIProfileSize(GB),EMAILangeMailboxSize(GB),TotalSize(GB)" | Out-File -FilePath $outFile
$users = get-aduser -filter { 
	( 
		( 
			( 
				Description -notlike "Service Account -*" 
			) -AND ( 
				Description -notlike "Admin Account -*" 
			) 
		) -AND ( 
			( 
				Description -notlike "Mailbox -*" 
			) -AND ( 
				Description -notlike "Test Account -*" 
			) 
		) 
	) -AND ( 
		( 
			( 
				Enabled -eq $true 
			) -AND ( 
				AccountExpirationDate -ge $Today 
			) 
		) -OR ( 
			( 
				Enabled -eq $true 
			) -AND ( 
				-not ( 
					AccountExpirationDate -like "*" 
				) 
			) 
		) 
	) } -Property * | sort Surname
	
# Engage a powershell session of the EMAILange management shell if one is not already active
if ( -not ( Get-Command Get-Mailbox -ErrorAction SilentlyContinue ) ) { 
	$ExOPSession = New-PSSession -ConfigurationName Microsoft.EMAILange -ConnectionUri http://ORGPREFIX-EMAIL-01.ad.DOMAIN.org/PowerShell/ -Authentication Kerberos
	Import-PSSession $ExOPSession *>&1 | out-null
}

#$users = Get-ADUser -filter { SAMAccountName -eq 'jgullo' } -Properties *

foreach ( $user in $users ) {
	$username = $user.SAMAccountName
	$firstName = $user.GivenName
	$lastName = $user.Surname
	$fullName = "$firstName $lastName"
	$profileDirPath = "\\ORGPREFIX-sharepointDSTORAGE.AD.DOMAIN.ORG\users`$\" + $username
	$totalSize = 0
	if ( Test-Path -Path $profileDirPath ) {
		$profileDir = Get-ChildItem -Recurse -Force $profileDirPath -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum
		$profileDirRawSize = $profileDir.Sum
		$profileDirSize = $($profileDirRawSize/1024/1024/1024)
		$profileDirSize = [math]::Round($profileDirSize,3)
		$totalSize = $($totalSize+$profileDirSize) 
	} else {
		$profileDirSize = "N\A"
	}
	$vdiProfileDirPath = "\\ORGPREFIX-sharepointDSTORAGE.AD.DOMAIN.ORG\users_vdiprofiles`$\" + $username
	if ( Test-Path -Path $vdiProfileDirPath ) {
		$vdiProfileDir = Get-ChildItem -Recurse -Force $vdiProfileDirPath -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum
		$vdiProfileDirRawSize = $vdiProfileDir.Sum
		$vdiProfileDirSize = $($vdiProfileDirRawSize/1024/1024/1024)
		$vdiProfileDirSize = [math]::Round($vdiProfileDirSize,3)
		$totalSize = $($totalSize+$vdiProfileDirSize) 
	} else {
		$vdiProfileDirSize = "N\A"
	}
	$mailbox = get-mailbox -identity $username -ErrorAction SilentlyContinue
	if ( $mailbox -ne $null ) {
		$rawMailboxSize = ( Get-MailboxStatistics -Identity $username -ErrorAction SilentlyContinue ).TotalItemSize.ToString().Split("(")[1].Split(" ")[0].Replace(",","")/1GB
		$mailboxSize = [math]::Round( $rawMailboxSize,3 )
		$totalSize = $($totalSize+$mailboxSize) 
	} else {
		$mailboxSize = "N\A"
	}
	#$output = "$fullName,$username,$profileDirSize,$vdiProfileDirSize,$mailboxSize,$totalSize"
	#write-output $output
	[pscustomobject]@{'Full Name'=$fullName;'User name'=$username;'Profile Size (GB)'=$profileDirSize;'VDI Profile Size (GB)'=$vdiProfileDirSize;'EMAILange Mailbox Size (GB)'=$mailboxSize;'Total Size (GB)'=$totalSize} | export-csv -Path $csvOutFile -Append -NoTypeInformation
	#write-output $output | Out-File -Append -FilePath $outFile
}

# End the EMAILange session
Remove-PSSession $ExOPSession
Exit-PSSession
