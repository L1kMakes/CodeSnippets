####
# 
# Name: Audit.DisabledAccountMailboxes
# Author: Joseph Gullo
# Last Modification: 2021.12.28
# Description: Look through all mailboxes to see if any are no longer being used
# References: Various snippets of code adapted from many web 
#   searches, the sources of which are long lost
#
####

clear-host
$dateStrMin = Get-Date -UFormat "%Y.%m.%d-%H.%M.%S"
$Today = (Get-Date)
$outFile = "Audit.DisabledAccountMailboxes.$dateStrMin.log"
$csvOutFile = "Audit.DisabledAccountMailboxes.$dateStrMin.csv"

# Engage a powershell session of the EMAILange management shell if one is not already active
if ( -not ( Get-Command Get-Mailbox -ErrorAction SilentlyContinue ) ) { 
	$ExOPSession = New-PSSession -ConfigurationName Microsoft.EMAILange -ConnectionUri http://ORGPREFIX-EMAIL-01.ad.DOMAIN.org/PowerShell/ -Authentication Kerberos
	Import-PSSession $ExOPSession *>&1 | out-null
}

$allUsers = Get-ADUser -Filter { 
	( 
		Enabled -eq $false 
	) -OR ( 
		AccountExpirationDate -le $Today 
	) 
} -Property * | sort SAMAccountName

foreach ( $user in $allUsers ) { 
	
	$username = $user.SAMAccountName
	$lastLogon = $user.LastLogonDate
	$mailbox = $null
	# Check if mailbox exists
	$mailbox = Get-mailbox -identity $username -erroraction SilentlyContinue
	
	if ( $mailbox ) {
		$rawMailboxSize = 0
		$mailboxSize = 0
		# If mailbox exists, get mailbox size
		$rawMailboxSize = ( Get-MailboxStatistics -Identity $username -ErrorAction SilentlyContinue ).TotalItemSize.ToString().Split("(")[1].Split(" ")[0].Replace(",","")/1MB
		$mailboxSize = [math]::Round( $rawMailboxSize,2 )
		$disabledMailboxes = [pscustomobject]@{'Account Name'=$username;'Last Logon Date'=$lastLogon;'Mailbox Size (MB)'=$mailboxSize}
		$disabledMailboxes | export-csv -Path $csvOutFile -Append -NoTypeInformation
		#$disabledMailboxes | Out-File -FilePath $outFile -Append
	}
}

# End the EMAILange session
Remove-PSSession $ExOPSession
Exit-PSSession
