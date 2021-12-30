####
# 
# Name: Audit.ADGroupsAndLists
# Author: Joseph Gullo
# Last Modification: 2021.12.28
# Description: Export all AD Groups and Distribution Lists 
#   with their members; include Manager
# References: Various snippets of code adapted from many web 
#   searches, the sources of which are long lost
#
####

# Timestamp for the filename
$dateStrMin = Get-Date -UFormat "%Y.%m.%d-%H.%M.%S"
$Today = (Get-Date)
# Indicate a file to write the output to
$outFile = "Audit.ADGroupsAndLists.$dateStrMin.log"
# Populate an object with all enabled users in active directory
$allUsers = get-aduser -filter { 
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
	) } -Properties name,manager,department,canonicalname,title,office | sort name
# Populate an object with all groups in active directory
$allGroups = get-adgroup -filter '*' -Property * | Sort Name
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
	# Store the array of user objects representing the members of the group into a variable
	$groupMembers = $group.Members
	# Sort the object by name
	$groupMembers = $groupMembers | sort-object 
	$MemberCount = $groupMembers.Count
	# Start outputting the group's info
	Write-Output "Name: $groupName" | Out-File -Append -FilePath $outFile
	Write-Output "`tOU: $groupCanonicalName" | Out-File -Append -FilePath $outFile
	Write-Output "`tType: $groupCategory" | Out-File -Append -FilePath $outFile
	# If the manager is set, output it
	if ( $managerName -ne [string]::Empty ) {
		Write-Output "`tManaged By: $managerName" | Out-File -Append -FilePath $outFile
	}
	# Output the members of the group
	Write-Output "`tMembers: $MemberCount" | Out-File -Append -FilePath $outFile
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
		try {
			$memberObj = Get-ADComputer -identity "$member" -Property DisplayName -ErrorAction SilentlyContinue
			$memberName = $memberObj.Name
		}
		Catch { }
		# Test if the group member is a sub group
		try {
			$memberObj = Get-ADGroup -identity "$member" -Property DisplayName -ErrorAction SilentlyContinue
			$memberName = $memberObj.Name
		}
		Catch { }
		# If the member was identified, output it
		if ( $memberName -ne [string]::Empty ) {
			write-output "`t`t$memberName" | Out-File -Append -FilePath $outFile
		}
	}
	# Put a newline to separate entries
	Write-Output "" | Out-File -Append -FilePath $outFile
}
