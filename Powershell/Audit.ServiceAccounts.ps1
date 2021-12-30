####
# 
# Name: Audit.ServiceAccounts
# Author: Joseph Gullo
# Last Modification: 2021.12.28
# Description: This script goes through all active accounts
#   and audits information about them.  THe key is the descriptor
#   "Service Account - " in the description
# References: Various snippets of code adapted from many web 
#   searches, the sources of which are long lost
#
####

#clear-host
$dateStrMin = Get-Date -UFormat "%Y.%m.%d-%H.%M.%S"
$Today = (Get-Date)
$outFile = "Audit.ServiceAccount.$dateStrMin.log"
$csvOutFile = "Audit.ServiceAccount.$dateStrMin.csv"
$allUsers = Get-ADUser -Filter { 
	( 
		Description -like "Service Account -*" 
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
	)
} -Property * | sort SAMAccountName
# $allUsers = Get-ADUser -Filter { SAMAccountName -eq 'jgullo'} -Properties *
$userString = ""
foreach ( $user in $allUsers ) { 
	$userName = $user.SAMAccountName
	$groupList = $user.MemberOf | sort
	$groupNameList = ""
	foreach ( $group in $groupList ) {
		$groupName = ( Get-ADGroup $group ).Name
		if ( $groupNameList -eq "" ) {
			$groupNameList = "$groupName"
		} else {
			$groupNameList = "$groupNameList`n$groupName"
		}
	}
	$ServiceAudit = [pscustomobject]@{'AccountName'=$user.SAMAccountName;'Description'=$user.Description;'Date Created'=$user.Created;'Last Logon'=$user.LastLogonDate;'Password Last Set'=$user.PasswordLastSet;'Manager'=$user.Manager;'OU'=$user.CanonicalName; 'Groups'=$groupNameList}
	$ServiceAudit | export-csv -Path $csvOutFile -Append -NoTypeInformation
	$ServiceAudit | Out-File -FilePath $outFile -Append
	if ( $userString -eq "" ) {
		$userString = "$userName"
	} else {
		$userString = "$userString,$userName"
	}
}
write-host $userString
cscript .\Audit.ServiceAccountUsage.vbs $userString
	
