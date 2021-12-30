####
# 
# Name: UserAccessAnalysisScript
# Author: Joseph Gullo
# Last Modification: 2021.12.28
# Description: This script analyzes the file server to look
#   for what files and folders, mailboxes, and other permissions
#   a specific user has access to.
# References: 
#
####

param (
    [Parameter(Mandatory=$False)] [string]$userName
)

# Test if the Active Directory commandlets are installed.  If not, exit.
if ( -not ( Get-Command -CommandType Cmdlet Get-ADUser -errorAction SilentlyContinue ) ) {
	Write-Output "`nActive Directory Commandlets are NOT installed, exiting!"
} else {
	if ( $userName -eq [string]::Empty ) {
		$userName = Read-Host -Prompt 'Which user do you want to analyze? (Format: account name, ie jgullo)'
	}
	
	# Populate some variables for cleaner output
	$userObj = Get-ADUser -filter {SAMAccountName -eq $userName} -Property *
	$fullName = "$($userObj.GivenName) $($userObj.surname)"

	# Populate some variables about how the script actually ran
	$adminUser = ((whoami) -replace "DOMAIN\\", "")
	$adminUserObj = Get-ADUser -filter {SAMAccountName -eq $adminUser}
	$adminUserName = "$($adminUserObj.GivenName) $($adminUserObj.surname)"
	$dateStr = Get-Date -UFormat "%Y.%m.%d"
	$dateStrMin = Get-Date -UFormat "%Y.%m.%d-%H.%M.%S"
		
	# Identify OutputLog File
	$outLogFile = "\\ORGPREFIX-sharepointDSTORAGE.AD.DOMAIN.ORG\it\Documentation\UserSeparationScriptLogs\$userName.AnalysisOnly.$dateStr.log"

	# Engage a powershell session of the EMAILange management shell if one is not already active
	if ( -not ( Get-Command Get-Mailbox -ErrorAction SilentlyContinue ) ) { 
		$ExOPSession = New-PSSession -ConfigurationName Microsoft.EMAILange -ConnectionUri http://ORGPREFIX-EMAIL-01.ad.DOMAIN.org/PowerShell/ -Authentication Kerberos
		Import-PSSession $ExOPSession *>&1 | out-null
	}

	&{
		Write-Output "`nUser Access Analysis Process for $fullName initiated on $(Get-Date) by $adminUserName"

		Write-Output "`n-----`nList all AD Groups $fullName is a member of:`n"
		get-aduser -filter {SAMAccountName -eq $userName} -Properties * | select-object -expandProperty MemberOf | Sort
			
		# Output and remove all dependent employees where this user was the manager
		Write-Output "`n-----`nThe following users directly report to $fullName"
		$all = get-aduser -filter * -Properties name,manager,department,canonicalname,title,office | sort name
		$userObjName = $userObj.DistinguishedName
		foreach ( $user in $all ) {
			$userManager = $user.manager
			if ( $userManager ) {
				if ( "$userManager" -ne [string]::Empty ) {
					if ( "$userManager" -eq "$userObjName" ) {
						write-host $user
					}
				}
			}
		}
			
		# Output and remove the manager for this user
		Write-Output "`n-----`nIf listed, the following user manages $fullName"
		$userManager = $userObj.manager
		write-output "`n$userManager"
						
		# Analyze the user's home directory
		$userDir = "\\ORGPREFIX-sharepointDSTORAGE.AD.DOMAIN.ORG\users$\$userName"
		if ( Test-Path $userDir ) {
			$exportedProfileLength = (get-childitem $userDir | measure Length -s).Sum
			$exportedProfileSize = $(($exportedProfileLength)/1024/1024)
			Write-Output "`n-----`nProfile is $exportedProfileSize MB in size."
		}

		if ( -not ( Get-mailbox -Identity $userName  -ErrorAction silentlycontinue ) ) {
			Write-Output "`n-----`nUser does not have a mailbox so not doing any EMAILange work"
		} else {
			Write-Output "`n-----`nList all mailboxes, calendars, and lists to which $fullName has Full Access Permissions"
			Get-Mailbox | Get-MailboxPermission -User $userName | Format-Table -auto

			Write-Output "`n-----`nList all mailboxes to which $fullName has Send on behalf of permissions"
			Get-Mailbox | ? {$_.GrantSendOnBehalfTo -match $userName} | Format-Table -auto

			Write-Output "`n-----`nList all calendars to which $fullName has access to"
			$calendars = Get-Mailbox -RecipientTypeDetails UserMailbox | Get-MailboxFolderStatistics | ? {$_.FolderType -eq "Calendar"} | select @{n="Identity"; e={$_.Identity.Replace("\",":\")}}
			$calendars | % { if ( Get-MailboxFolderPermission -Identity $_.Identity -User $userName -ErrorAction SilentlyContinue ) { $_.Identity; (Get-MailboxFolderPermission -Identity $_.Identity -User $userName).AccessRights } }

			Write-Output "`n-----`nList all users who have Send-As permissions to $fullName's mailbox"
			Get-Mailbox -Identity $userName | Get-ADPermission | ? { $_.ExtendedRights -like "*send*" } | Format-Table -auto User,ExtendedRights
	
				
		}
	} | Out-File -FilePath $outLogFile
	# End the EMAILange session
	Remove-PSSession $ExOPSession
	Exit-PSSession
}
