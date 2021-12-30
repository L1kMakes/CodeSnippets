####
# 
# Name: Audit.Mailboxes
# Author: Joseph Gullo
# Last Modification: 2021.12.28
# Description: This audit crawls all AD accounts and looks
#   for mailboxes that are idle or unused.
# References: Various snippets of code adapted from many web 
#   searches, the sources of which are long lost
#
####

# Get all potential mailbox accounts
clear-host
$dateStrMin = Get-Date -UFormat "%Y.%m.%d-%H.%M.%S"
$Today = (Get-Date)
$outFile = "Audit.Mailboxes.$dateStrMin.log"
$csvOutFile = "Audit.Mailboxes.$dateStrMin.csv"

# Engage a powershell session of the EMAILange management shell if one is not already active
if ( -not ( Get-Command Get-Mailbox -ErrorAction SilentlyContinue ) ) { 
	$ExOPSession = New-PSSession -ConfigurationName Microsoft.EMAILange -ConnectionUri http://ORGPREFIX-EMAIL-01.ad.DOMAIN.org/PowerShell/ -Authentication Kerberos
	Import-PSSession $ExOPSession *>&1 | out-null
}

$allUsers = Get-ADUser -Filter { 
	( 
		(
			Description -like "Service Account -*" 
		) -OR (
			Description -like "Mailbox -*"
		)
	)
} -Property * | sort SAMAccountName

<#
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
#>

# We need the oldest message log in the system; itsupport is a good canary for that
#$itsupportMailbox = Get-mailbox -identity itsupport -erroraction SilentlyContinue
#$itsupportMessageLogs = Get-MessageTrackingLog -ResultSize Unlimited -Sender $itsupportMailbox.PrimarySmtpAddress -ErrorAction silentlyContinue -WarningAction silentlyContinue | sort timestamp
#$oldestMailLog = $itsupportMessageLogs[0].timestamp

# For each account
foreach ( $user in $allUsers ) { 
	
	$username = $user.SAMAccountName
	$isEnabled = $user.Enabled
	# Check if mailbox exists
	$mailbox = Get-mailbox -identity $username -erroraction SilentlyContinue
	if ( $mailbox -ne $null ) {
		$rawMailboxSize = 0
		$mailboxSize = 0
		#$lastLogon = (get-mailboxstatistics $username).lastlogontime
	
		# If mailbox exists, get most recent sent mail
		$messageLogs = Get-MessageTrackingLog -ResultSize Unlimited -Sender $mailbox.PrimarySmtpAddress -ErrorAction silentlyContinue -WarningAction silentlyContinue | sort timestamp
		if ( $messageLogs -ne $null ) {
			$lastSentDate = ( $messageLogs[-1] ).timestamp
			$lastSentOutput = "-- Last Sent Mail: $lastSentDate"
		} else {
			$lastSentDate = "None in 30 days"
			$lastSentOutput = "-- Hasn't sent a message in 30 days!"
		}

		# If mailbox exists, get most recent received mail
		$messageLogs = Get-MessageTrackingLog -ResultSize Unlimited -Recipients $mailbox.PrimarySmtpAddress -ErrorAction silentlyContinue -WarningAction silentlyContinue | sort timestamp
		if ( $messageLogs -ne $null ) {
			$lastReceivedDate = ( $messageLogs[-1] ).timestamp
			$lastReceivedOutput = "-- Last Received Mail: $lastReceivedDate"
		} else {
			$lastReceivedDate = "None in 30 days"
			$lastReceivedOutput = "-- Hasn't received a message in 30 days!"
		}

		# If mailbox exists, get mailbox size
		$rawMailboxSize = ( Get-MailboxStatistics -Identity $username -ErrorAction SilentlyContinue ).TotalItemSize.ToString().Split("(")[1].Split(" ")[0].Replace(",","")/1MB
		$mailboxSize = [math]::Round( $rawMailboxSize,2 )
		
		# If mailbox exists, get sendas list
		$sendAsUsers = (Get-Mailbox -identity $username | Get-ADPermission | where { ($_.ExtendedRights -like "*Send-As*") -and -not ($_.User -like "NT AUTHORITY\SELF")}).User | Sort

		# If mailbox exists, get full access list
		$fullAccessUsers = (Get-Mailbox -identity $username | Get-MailboxPermission | where { ($_.AccessRights -eq "FullAccess") -and -not ($_.User -like "NT AUTHORITY\SELF")}).User | Sort

<#		
		write-host "$username"
		write-host "-- Is Enabled: $isEnabled"
		write-host "-- Last Logon: $lastLogon"
		write-host "$lastSentOutput"
		write-host "$lastReceivedOutput"
		write-host "-- Mailbox Size: $mailboxSize MB"
		write-host "-- Users with SendAs Permissions:"
		$sendAsUsers
		write-host "-- Users with Full Access Permissions:"
		$fullAccessUsers
		write-host "`n"
#>
		
		$ofs = '; '
		#$MailboxAudit = [pscustomobject]@{'AccountName'=$username;'IsEnabled'=$isEnabled;'Last Logon'=$lastLogon;'Last Sent Mail'=$lastSentDate;'Last Received Mail'=$lastReceivedDate;'Mailbox Size (MB)'=$mailboxSize;'Users With SendAs'=[String]$sendAsUsers;'Users With FullAccess'=[String]$fullAccessUsers}
		$MailboxAudit = [pscustomobject]@{'AccountName'=$username;'IsEnabled'=$isEnabled;'Last Sent Mail'=$lastSentDate;'Last Received Mail'=$lastReceivedDate;'Mailbox Size (MB)'=$mailboxSize;'Users With SendAs'=[String]$sendAsUsers;'Users With FullAccess'=[String]$fullAccessUsers}

		
		$MailboxAudit | export-csv -Path $csvOutFile -Append -NoTypeInformation
		$MailboxAudit | Out-File -FilePath $outFile -Append

	}
}

# End the EMAILange session
Remove-PSSession $ExOPSession
Exit-PSSession
		
