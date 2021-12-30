####
# 
# Name: Audit.GroupsListsandMailboxesForLeadership
# Author: Joseph Gullo
# Last Modification: 2021.12.28
# Description: This script crawls through AD and finds
#   groups and distribution lists, then parses them in a
#   way for leadership to review 
# References: Various snippets of code adapted from many web 
#   searches, the sources of which are long lost
#
####

# Timestamp for the filename
$dateStrMin = Get-Date -UFormat "%Y.%m.%d-%H.%M.%S"
$Today = (Get-Date)

# Indicate a file to write the output to
$csvOutFile = "Audit.GroupsListsAndMailboxesForLeadership.$dateStrMin.csv"

# Populate an object with all groups in active directory
$allGroups = get-adgroup -filter '*' -Property * | Sort Name

#$fullAudit = $null

# Iterate through all AD groups
foreach ( $group in $allGroups ) {
	# Populate a variable with the current group's name
	$groupName = $group.Name
	# Populate and format a variable with the current group's canonical name
	$groupCanonicalName = $group.CanonicalName
	$groupCanonicalName = $groupCanonicalName -replace "AD.DOMAIN.org/", ""
	$groupCanonicalName = $groupCanonicalName -replace "/$groupName", ""
	# Populate a variable with the current group's category/class
	$groupCategory = $group.groupCategory
	# Store the array of user objects representing the members of the group into a variable
	$groupMembers = $group.Members	
	# Sort the object by name
	$groupMembers = $groupMembers | sort-object 
	$memberNames = ""
	$memberCount = $groupMembers.Count
	# Iterate through the members of the group, testing if it's a user, computer, or sub group
	foreach ( $member in $groupMembers ) {
		# By default, set the member's name to nothing
		$memberName = ""
		# Test if the group member is a user
		try {
			$memberObj = Get-ADUser -identity "$member" -Property DisplayName -ErrorAction SilentlyContinue
			$memberName = $memberObj.DisplayName
		}
		Catch { }
		# Test if the group member is a computer
		if ( $memberName -eq "") {
			try {
				$memberObj = Get-ADComputer -identity "$member" -Property DisplayName -ErrorAction SilentlyContinue
				$memberName = $memberObj.Name
			}
			Catch { }
		}
		# Test if the group member is a sub group
		if ( $memberName -eq "" ) {
			try {
				$memberObj = Get-ADGroup -identity "$member" -Property DisplayName -ErrorAction SilentlyContinue
				$memberName = $memberObj.Name
			}
			Catch { }
		}
		# Test if the group member is a contact
		if ( $memberName -eq "" ) {
			try {
				$memberObj = Get-ADObject -Identity "$member" -Filter {ObjectClass -eq 'contact'} -ErrorAction SilentlyContinue
				$memberName = $memberObj.DistinguishedName
			}
			Catch { }
		}
		# If the member was identified, output it
		if ( $memberName -ne [string]::Empty ) {
			if (
				(
					( 
						(
							$memberName -ne "EMAILange Organization Administrators" 
						) -AND (
							$memberName -ne "Backup Exec"
						)
					) -AND ( 
						(
							$memberName -ne "Enterprise Admins" 
						) -AND (
							$memberName -ne "Administrator" 
						)
					) 
				) -AND ( 
					( 
						(
							$memberName -ne "Organization Management" 
						) -AND (
							$memberName -ne "Admin, BES"
						)
					) -AND ( 
						(
							$memberName -ne "Domain Admins" 
						) -AND (
							$memberName -ne "Test, Account" 
						)
					) 
				)
			) {
				if ( $memberNames -eq "" ) {
					$memberNames = $memberName
				} 
				else {
					$memberNames += "; $memberName"
				}
			}
		}
	}
	# Populate a variable with the current group's manager
	$groupManagedBy = $group.ManagedBy
	# By default, set the manager's name to nothing in case a manager is not listed
	$managerName = ""
	# Logic to test if the manager of the group is set, then if it is, extract the full name
	if ( ( $groupManagedBy -ne [string]::Empty ) -AND ( $groupManagedBy ) ) {
		try {
			# Pull a user object that matches the distinguished name of the manager
			$managerObj = Get-ADUser -identity "$groupManagedBy" -Property DisplayName -ErrorAction SilentlyContinue
			# Store the DisplayName of the manager object in a variable
			$managerName = $managerObj.DisplayName
		} 
		Catch { }
	}
	
	$leadershipAudit = [pscustomobject]@{ `
		'AccountName'=$group.Name; `
		'Type'=$groupCategory; `
		'Enabled'="N/A"; `
		'Date Created'=$group.Created; `
		'Manager'=$managerName; `
		'Description'=$group.Description; `
		'OU'=$group.CanonicalName; `
		'MemberCount'='=LEN(H2)-LEN(SUBSTITUTE(H2,";",""))+IF(H2="",0,1)'; `
		'Members'=$memberNames; `
	}

	$leadershipAudit | export-csv -Path $csvOutFile -Append -NoTypeInformation
	#$fullAudit =+ $leadershipAudit
}

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

# For each account
foreach ( $user in $allUsers ) { 
	
	$username = $user.SAMAccountName
	$isEnabled = $user.Enabled
	# Check if mailbox exists
	$mailbox = Get-mailbox -identity $username -erroraction SilentlyContinue
	if ( $mailbox -ne $null ) {
	
		# Populate a variable with the current user's manager
		$userManagedBy = $user.Manager
		# By default, set the manager's name to nothing in case a manager is not listed
		$managerName = ""
		# Logic to test if the manager of the group is set, then if it is, extract the full name
		if ( ( $userManagedBy -ne [string]::Empty ) -AND ( $userManagedBy ) ) {
			try {
				# Pull a user object that matches the distinguished name of the manager
				$managerObj = Get-ADUser -identity "$userManagedBy" -Property DisplayName -ErrorAction SilentlyContinue
				# Store the DisplayName of the manager object in a variable
				$managerName = $managerObj.DisplayName
			} 
			Catch { }
		}
		# If mailbox exists, get full access list
		$fullAccessMembers = (Get-Mailbox -identity $username | Get-MailboxPermission | Where-Object { ($_.AccessRights -like "*FullAccess*") -and ( ($_.IsInherited -eq $False) -and -not ($_.User -like "NT AUTHORITY\SELF"))}).User | Sort
		$memberNames = ""
		$memberCount = $fullAccessMembers.Count
		# Iterate through the members of the group, testing if it's a user, computer, or sub group
		foreach ( $member in $fullAccessMembers ) {
			$member = $member -replace "DOMAIN\\", ""
			# By default, set the member's name to nothing
			$memberName = ""
			# Test if the group member is a user
			try {
				$memberObj = Get-ADUser -identity "$member" -Property DisplayName -ErrorAction SilentlyContinue
				$memberName = $memberObj.DisplayName
			}
			Catch { }
			# Test if the group member is a computer
			if ( $memberName -eq "") {
				try {
					$memberObj = Get-ADComputer -identity "$member" -Property DisplayName -ErrorAction SilentlyContinue
					$memberName = $memberObj.Name
				}
				Catch { }
			}
			# Test if the group member is a sub group
			if ( $memberName -eq "" ) {
				try {
					$memberObj = Get-ADGroup -identity "$member" -Property DisplayName -ErrorAction SilentlyContinue
					$memberName = $memberObj.Name
				}
				Catch { }
			}
			# Test if the group member is a contact
			if ( $memberName -eq "" ) {
				try {
					$memberObj = Get-ADObject -Identity "$member" -Filter {ObjectClass -eq 'contact'} -ErrorAction SilentlyContinue
					$memberName = $memberObj.DistinguishedName
				}
				Catch { }
			}
			# If the member was identified, output it
			if ( $memberName -ne [string]::Empty ) {
				if (
					(
						( 
							(
								$memberName -ne "EMAILange Organization Administrators" 
							) -AND (
								$memberName -ne "Backup Exec"
							)
						) -AND ( 
							(
								$memberName -ne "Enterprise Admins" 
							) -AND (
								$memberName -ne "Administrator" 
							)
						) 
					) -AND ( 
						( 
							(
								$memberName -ne "Organization Management" 
							) -AND (
								$memberName -ne "Admin, BES"
							)
						) -AND ( 
							(
								$memberName -ne "Domain Admins" 
							) -AND (
								$memberName -ne "Test, Account" 
							)
						) 
					)
				) {
					if ( $memberNames -eq "" ) {
						$memberNames = $memberName
					} 
					else {
						$memberNames += "; $memberName"
					}
				}
			}
		}		
		$MailboxAudit = [pscustomobject]@{ `
			'AccountName'=$username; `
			'Type'='Mailbox'; `
			'Enabled'=$isEnabled; `
			'Date Created'=$user.Created; `
			'Manager'=$managerName; `
			'Description'=$user.Description; `
			'OU'=$user.CanonicalName; `
			'MemberCount'='=LEN(H2)-LEN(SUBSTITUTE(H2,";",""))+IF(H2="",0,1)'; `
			'Members'=$memberNames; `
		}
		
		$MailboxAudit | export-csv -Path $csvOutFile -Append -NoTypeInformation
		#$fullAudit =+ $MailboxAudit
	}
}

#$fullAudit = $fullAudit | sort

#$fullAudit | export-csv -Path $csvOutFile -Append -NoTypeInformation

# End the EMAILange session
Remove-PSSession $ExOPSession
Exit-PSSession
		
