<#
	Script Name: Get-OrgChart
	Script Author: Joseph Gullo
	Last Modification Date: 7/6/2018
	Script Description: This script is a combination of 3 functions which work to print
		a text-based output of an org chart from Active Directory info.
	Requirements: Powershell AD Commandlets from the Remote Server Administrative Tools
		specifically Get-ADUser
#>

<#
	Function: Write-UserInfo
	Description: This easily modified function is used to clean up and output the 
		user info for each user.  It checks each parameter for whether it's been 
		passed, then appends whitespace, a title, and the value to a single
		string which is output to the screen.  Additional parameters can be added
		trivially as needed.  Generally, Indent and Name are required for good output.
		Add or remove other parameters as needed based on what user info you want
		to display.
#>
function Write-UserInfo($Indent, $Name, $Title, $Department, $Office, $Manager, $OU) {
	$LengthIndent=$Indent.length
	$LengthName=$Name.length
	$IndentDeptLength=57 - $LengthIndent - $LengthName
	$IndentDept=""
	$i=0
	while ( $i++ -le $IndentDeptLength ) {
		$IndentDept+=" "
	}
	if ($null -ne $Department) { $Department="Department: $Department" }
	$LengthDept=$Department.length
	$IndentOfficeLength=40 - $LengthDept
	$IndentOffice=""
	$i=0
	while ( $i++ -le $IndentOfficeLength ) {
		$IndentOffice+=" "
	}
	if ($null -ne $Office) { $Office="Office: $Office" }
	$LengthOffice=$Office.length
	$IndentTitleLength=40 - $LengthOffice
	$IndentTitle=""
	$i=0
	while ( $i++ -le $IndentTitleLength ) {
		$IndentTitle+=" "
	}
	if ($null -ne $Title) {	$Title="Title: $Title" }
	if ($null -ne $Manager) { $Manager="`t| Manager: $Manager" }
	if ($null -ne $OU) { $OU="`t| OU: $OU" }
	write-output "$Indent$Name$IndentDept| $Department$IndentOffice| $Office$IndentTitle| $Title$Manager$OU"
}

<#
	Function: Get-DirectReports
	Parameters: 
		manager: The user object for the manager we want to find direct reports for
		level: A numerical representation of the hierarchical depth of the org chart 
			the desired manager is at
	Description: This function assumes that $managegroups has already been populated
		from the parent function, as well as $all.  Given a user that has been flagged 
		as a manager, the function crawls all users to find those that have the desired
		manager listed as their supervisor.  The user info is passed to the Write-UserInfo
		function to be printed, then the user is checked for reports under them (by 
		seeing if they are in the $managegroups object).  If a direct report is a manager
		for other users, recursively call this function while incrementing the level
		counter by 1.  The level counter is used to generate a string for proper indent
		display.
#>
function Get-DirectReports($manager, $level) {
	$indent = "    "
	for ($i=1; $i -lt $level; $i++) {
		$indent = "$indent¦   "
	}
	foreach ( $user in $all ) {
		if ($user.manager -eq $manager) {
			Write-UserInfo -Indent "$indent+-- " -Name $($user.name) -Title $($user.title) -Department $($user.department) -Office $($user.office) #-Manager $($user.manager) #-OU $($user.CanonicalName)
			if ($managegroups.name.contains($user.distinguishedname)) {
				Get-DirectReports $user $($level+1)
			}
		}
	}
}

<#
	Function: Get-OrgChart
	Description: This function first grabs ALL AD users with, most importantly, their
	    managers, and stashes it into an object.  Then, it parses this info to identify 
		all managers and puts them in an object.  These two objects are used by all 
		sub-functions.  It starts by finding the users with no manager listed, splitting 
		them into those in the manager groups and those not in the manager groups.  It 
		then invokes the "get-directreports" function for all users in the managers list,
		and lists everyone else as "having no manager."
		
#>
function Get-OrgChart {
	clear-host
	write-output ""
	<#  If different user info is required, or a different filter is needed to be applied, 
		make edits here.  If you add a field to be displayed, you need to edit 
		Write-UserInfo to accept new parameters, then edit every invocation of that
		function. #>
   # Uncomment this to get all accounts
	#$all = get-aduser -filter 'enabled -eq $true' -Properties name,manager,department,canonicalname,title,office | sort name
   # Uncomment this to get all real user accounts
	$all = get-aduser -filter { ( ( enabled -eq $true ) -AND ( title -notlike 'Service Account -*' ) -AND ( title -notlike 'Mailbox -*' ) -AND ( title -notlike 'Test Account -*' ) -AND ( title -notlike 'Admin Account -*' ) ) -OR ( ( enabled -eq $true ) -AND ( title -notlike '*' ) ) } -Properties name,manager,department,CanonicalName,title,office | sort name
   # Uncomment this to get all real user accounts EXCEPT MEMBERS
	#$all = get-aduser -filter { ( ( enabled -eq $true ) -AND ( title -notlike 'Service Account -*' ) -AND ( title -notlike 'Mailbox -*' ) -AND ( title -notlike 'Test Account -*' ) -AND ( title -notlike 'Admin Account -*' ) -AND ( title -ne 'Member' ) -AND ( title -notlike 'ORGPREFIX Member*' ) ) -OR ( ( enabled -eq $true ) -AND ( title -notlike '*' ) ) } -Properties name,manager,department,CanonicalName,title,office | sort name
   # Uncomment this to get all users and mailboxes
	#$all = get-aduser -filter { ( ( enabled -eq $true ) -AND ( title -notlike 'Service Account -*' ) -AND ( title -notlike 'Test Account -*' ) ) -OR ( ( enabled -eq $true ) -AND ( title -notlike '*' ) ) } -Properties name,manager,department,CanonicalName,title,office | sort name
   # Uncomment this to get all mailboxes
	#$all = get-aduser -filter { ( ( enabled -eq $true ) -AND ( title -like 'Mailbox -*' ) ) } -Properties name,manager,department,CanonicalName,title,office | sort name
   # Uncomment this to get all users and service accounts
	#$all = get-aduser -filter { ( ( enabled -eq $true ) -AND ( title -notlike 'Mailbox -*' ) -AND ( title -notlike 'Test Account -*' ) ) -OR ( ( enabled -eq $true ) -AND ( title -notlike '*' ) ) } -Properties name,manager,department,CanonicalName,title,office | sort name
   # Uncomment this to get all service accounts
	#$all = get-aduser -filter { ( ( enabled -eq $true ) -AND ( title -like 'Service Account -*' ) ) } -Properties name,manager,department,CanonicalName,title,office | sort name
	$allSep = get-aduser -filter { ( ( enabled -eq $false ) -AND ( title -notlike 'Service Account -*' ) -AND ( title -notlike 'Mailbox -*' ) -AND ( title -notlike 'Test Account -*' ) -AND ( title -notlike 'Admin Account -*' ) -AND ( title -ne 'Member' ) ) -OR ( ( enabled -eq $false ) -AND ( title -notlike '*' ) ) } -Properties name,manager,department,CanonicalName,title,office | sort name
	$managegroups = ($all | select-object -Property name,manager | Group-Object -Property manager)
	foreach ( $user in $all ) {
		if ( ( $user.manager -ne $user.distinguishedname ) -and ( ( $user.manager -eq $null ) -and ( $managegroups.name.contains( $user.distinguishedname ) ) ) ) {
			Write-UserInfo -Indent "" -Name $($user.name) -Title $($user.title) -Department $($user.department) -Office $($user.office) #-Manager $($user.manager) #-OU $($user.CanonicalName)
			Get-DirectReports $user 1
		}
	}
	write-output "No Manager Listed:"
	foreach ( $user in $all ) {
		if ( ( $user.manager -eq $user.distinguishedname ) -or ( ( $user.manager -eq $null ) -and -not ( $managegroups.name.contains( $user.distinguishedname ) ) ) ) {
			Write-UserInfo -Indent "    +-- " -Name $($user.name) -Title $($user.title) -Department $($user.department) -Office $($user.office) #-Manager $($user.manager) #-OU $($user.CanonicalName)
		}
	}
	write-output "Manager Is Separated:"
	foreach ( $user in $all ) {
		foreach ( $mgr in $allSep ) {
			if ( $mgr.DistinguishedName -eq $user.manager ) {
				Write-UserInfo -Indent "    +-- " -Name $($user.name) -Title $($user.title) -Department $($user.department) -Office $($user.office) #-Manager $($user.manager) #-OU $($user.CanonicalName)
				break
			}
		}
	}
	write-output ""
}

# Invoke the function to generate the org chart 
Get-OrgChart
