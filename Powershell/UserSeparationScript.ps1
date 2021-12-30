####
# 
# Name: UserSeparationScript
# Author: Joseph Gullo
# Last Modification: 2021.12.28
# Description: This script performs all separation duties for a user leaving the company, 
#   as well as keeps a log of all actions taken.
# References: 
#
####

param (
    [Parameter(Mandatory=$False)] [string]$userName, 
    [Parameter(Mandatory=$False)] [string]$autoReplyMsg    
)

#clear-host

# Test if 7-Zip is installed.  If it isn't, offer to install it.  If they decline, exit.
if ( -not ( test-path "$env:ProgramFiles\7-Zip\7z.exe" ) ) {
	$install7Zip = Read-Host -Prompt "7-Zip isn't installed, do you want to install it? [Y/n]"
	if ( $install7Zip -eq "Y" ) {
		Write-Output "`nInstalling 7-Zip"
		cd "\\ORGPREFIX-sharepointDSTORAGE.AD.DOMAIN.ORG\IT\Applications\7-Zip\"
		Start-Process -Wait "./7-Zip.Current.exe" -ArgumentList "/S" -NoNewWindow
		C:
	} else {
		Write-Output "`nWithout 7-Zip, this won't work...exiting!"
	}
} else {

	# Set an alias for 7-Zip for later invocation
	set-alias sz "$env:ProgramFiles\7-Zip\7z.exe"
	
	# Test if the Active Directory commandlets are installed.  If not, exit.
	if ( -not ( Get-Command -CommandType Cmdlet Get-ADUser -errorAction SilentlyContinue ) ) {
		Write-Output "`nActive Directory Commandlets are NOT installed, exiting!"
	} else {
		if ( $userName -eq [string]::Empty ) {
			$userName = Read-Host -Prompt 'Which user do you want to delete? (Format: account name, ie jgullo)'
		}
		if ( $autoReplyMsg -eq [string]::Empty ) {
			$autoReplyMsg = Read-Host -Prompt 'What do you want the auto-reply e-mail message to say?'
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
		$outLogFile = "\\ORGPREFIX-sharepointDSTORAGE.AD.DOMAIN.ORG\it\Documentation\UserSeparationScriptLogs\$userName.$dateStr.log"

		# Engage a powershell session of the EMAILange management shell if one is not already active
		if ( -not ( Get-Command Get-Mailbox -ErrorAction SilentlyContinue ) ) { 
			$ExOPSession = New-PSSession -ConfigurationName Microsoft.EMAILange -ConnectionUri http://ORGPREFIX-EMAIL-01.ad.DOMAIN.org/PowerShell/ -Authentication Kerberos
			Import-PSSession $ExOPSession *>&1 | out-null
		}

		&{
			Write-Output "`nUser Separation Process for $fullName initiated on $(Get-Date) by $adminUserName"

			Write-Output "`n-----`nList all AD Groups $fullName is a member of:`n"
			get-aduser -filter {SAMAccountName -eq $userName} -Properties * | select-object -expandProperty MemberOf | Sort
			
			# Remove the user's account from all AD groups
			Get-ADUser -Identity $userName -Properties MemberOf | ForEach-Object {
				$_.MemberOf | Remove-ADGroupMember -Members $_.DistinguishedName -Confirm:$false
			}
			Write-Output "`n-----`nAll groups have been removed from $fullName's Active Directory Account"

			# Output and remove all dependent employees where this user was the manager
			Write-Output "`n-----`nThe following users directly reported $fullName but now have no manager"
			$all = get-aduser -filter * -Properties name,manager,department,canonicalname,title,office | sort name
			$userObjName = $userObj.DistinguishedName
			foreach ( $user in $all ) {
				$userManager = $user.manager
				if ( $userManager ) {
					if ( "$userManager" -ne [string]::Empty ) {
						if ( "$userManager" -eq "$userObjName" ) {
							write-host $user
							Set-ADUser -Identity $user -Clear manager
						}
					}
				}
			}
			
			# Output and remove the manager for this user
			Write-Output "`n-----`nIf listed, the following user managed $fullName but has now been cleared"
			$userManager = $userObj.manager
			write-output "`n$userManager"
			Set-ADUser -Identity $userObj -Clear manager
						
			# Compress the user's home directory and archive it
			$userDir = "\\ORGPREFIX-sharepointDSTORAGE.AD.DOMAIN.ORG\users$\$userName"
			if ( Test-Path $userDir ) {
				$profileArchiveFile = "\\ORGPREFIX-sharepointDSTORAGE.AD.DOMAIN.ORG\userArchive$\Archive_Users\$userName.$dateStr.zip"
				sz a -bd -mx=9 $profileArchiveFile $userDir
				$exportedProfile = get-itemproperty $profileArchiveFile
				$exportedProfileLength = $exportedProfile.Length
				$exportedProfileSize = $(($exportedProfileLength)/1024/1024)
				Write-Output "`n-----`nExport of Profile completed, located at $profileArchiveFile and is $exportedProfileSize MB in size.  File creation started at $exportedProfile.CreationTime and completed at $exportedProfile.LastWriteTime."

				# Delete the user's home directory
				Remove-Item -Recurse -Force $userDir
				Write-Output "`n-----`nRemoved profile directory for $fullName"
			}

#			# Check if the user has a VDI directory; if so, archive and delete it.
#			$userVdiDir = "\\ORGPREFIX-sharepointDSTORAGE.AD.DOMAIN.ORG\users_VDIProfiles$\$userName"
#			if ( Test-Path $userVdiDir ) {
#				$vdiProfileArchiveFile = "\\ORGPREFIX-sharepointDSTORAGE.AD.DOMAIN.ORG\userArchive$\Archive_Users_VDIProfiles\$userName.$dateStr.zip"
#				sz a -bd -mx=9 $vdiProfileArchiveFile $userVdiDir
#				$exportedVdiProfile = get-itemproperty $vdiProfileArchiveFile
#				$exportedVdiProfileSize = $(($exportedVdiProfile.Length)/1024/1024)
#				Write-Output "`n-----`nExport of Profile completed, located at $vdiProfileArchiveFile and is $exportedVdiProfileSize MB in size.  File creation started at $exportedVdiProfile.CreationTime and completed at $exportedVdiProfile.LastWriteTime."

#				Remove-Item -Recurse -Force $userVdiDir
#				Write-Output "`n-----`nRemoved VDI profile directory for $fullName"
#			}

			if ( -not ( Get-mailbox -Identity $userName  -ErrorAction silentlycontinue ) ) {
				Write-Output "`n-----`nUser does not have a mailbox so not doing any EMAILange work"
			} else {
				Write-Output "`n-----`nList all mailboxes, calendars, and lists to which $fullName has Full Access Permissions"
				Get-Mailbox | Get-MailboxPermission -User $userName | Format-Table -auto

				# NOTE this didn't work, but is in here for later attempts.
				# Write-Output "`n-----`nList all mailboxes to which $userName has Send As permissions"
				#Get-Mailbox | Get-RecipientPermission -Trustee $userName | Format-Table -auto

				Write-Output "`n-----`nList all mailboxes to which $fullName has Send on behalf of permissions"
				Get-Mailbox | ? {$_.GrantSendOnBehalfTo -match $userName} | Format-Table -auto

				Write-Output "`n-----`nList all calendars to which $fullName has access to"
				$calendars = Get-Mailbox -RecipientTypeDetails UserMailbox | Get-MailboxFolderStatistics | ? {$_.FolderType -eq "Calendar"} | select @{n="Identity"; e={$_.Identity.Replace("\",":\")}}
				$calendars | % { if ( Get-MailboxFolderPermission -Identity $_.Identity -User $userName -ErrorAction SilentlyContinue ) { $_.Identity; (Get-MailboxFolderPermission -Identity $_.Identity -User $userName).AccessRights } }

				Write-Output "`n-----`nList all users who have Send-As permissions to $fullName's mailbox"
				Get-Mailbox -Identity $userName | Get-ADPermission | ? { $_.ExtendedRights -like "*send*" } | Format-Table -auto User,ExtendedRights
				
				# Set the Auto-Reply message for the mailbox if one is passed
				if ( -not ( ( $autoReplyMsg -eq "" ) -OR ( $autoReplyMsg -eq [string]::Empty ) ) ) {
					Set-MailboxAutoReplyConfiguration $userName -AutoReplyState enabled -ExternalAudience all -InternalMessage $autoReplyMsg -ExternalMessage $autoReplyMsg
					Write-Output "`n-----`nThe following auto-reply message has been set for $fullname`n$autoReplyMsg`n"
				}

				# Remove the user from the GAL
				Write-Output "`n-----`nRemove $fullName from the GAL"
				get-mailbox -Identity $userName | set-mailbox -HiddenFromAddressListsEnabled $true
			}
			
			# Disable the AD Account
			Disable-ADAccount -Identity $userName
			Write-Output "`n-----`nActive Directory Account disabled for $fullName"

			if ( -not ( Get-mailbox -Identity $userName  -ErrorAction silentlycontinue ) ) {
				Write-Output "`n-----`nUser does not have a mailbox so not doing any EMAILange work"
			} else {
				# Export the user's mailbox to a PST File
				Write-Output "`n-----`nEverything has completed except exporting the PST.  Starting export of PST"
				$pstExportPath = "\\ORGPREFIX-sharepointDSTORAGE.AD.DOMAIN.ORG\userArchive$\Archive_PST\$userName.$dateStr.pst"
				$pstJobName = "$userName.$dateStrMin"
				New-MailboxExportRequest -Mailbox $userName -FilePath $pstExportPath -Name $pstJobName -ErrorAction SilentlyContinue
				While ( "$(((Get-MailboxExportRequest -Name $pstJobName | Get-MailboxExportRequestStatistics -IncludeReport).Report.Entries[(Get-MailboxExportRequest | Get-MailboxExportRequestStatistics -IncludeReport).Report.Entries.Count -1]).Message.StringId)" -ne "ExDABAF1" ) {
					Sleep 30 
				}
				Get-MailboxExportRequest -Name $pstJobName | Remove-MailboxExportRequest -Confirm:$false
				$exportedPST = get-itemproperty $pstExportPath
				$exportedPSTSize = $(($exportedPST.Length)/1024/1024)
				Write-Output "`n-----`nExport of PST completed, located at $pstExportPath and is $exportedPSTSize MB in size.  File creation started at $exportedPST.CreationTime and completed at $exportedPST.LastWriteTime."
			}

			# Move the user's account to the Separated Users OU
			Move-ADObject -Identity $userObj -TargetPath "OU=Separated,OU=Inactive Users,DC=AD,DC=DOMAIN,DC=org"
			Write-Output "`n-----`nActive Directory Object for $fullName moved to the separated users organizational unit."
			
		} | Out-File -FilePath $outLogFile

		# End the EMAILange session
		Remove-PSSession $ExOPSession
		Exit-PSSession
	}
}

# cd \\ORGPREFIX-sharepointDSTORAGE.AD.DOMAIN.ORG\IT\CodeRepo
