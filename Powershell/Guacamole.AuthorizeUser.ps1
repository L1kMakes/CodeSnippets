####
# 
# Name: Guacamole.AuthorizeUser
# Author: Joseph Gullo
# Last Modification: 2021.12.28
# Description: This script provisions users for Apache Guacamole
#   by adding them to the local Remote Desktop users group on the
#   desired computer.
# References: 
#
####

param (
    [Parameter(Mandatory=$False)] [string]$userName, 
    [Parameter(Mandatory=$False)] [string]$computerName    
)
Clear-Host
if ( -Not ( Get-Command get-aduser -errorAction SilentlyContinue ) ) { 
	Write-Host "The Active Directory modules aren't loaded, attempting to load them."
	Import-WinModule -Name ActiveDirectory
	if ( -Not ( Get-Command get-aduser -errorAction SilentlyContinue ) ) { 
		Write-Host "We can't get the Active Directory modules loaded so this won't work!"
		Exit
	} else {
		Write-Host "Successfully loaded the Active Directory modules!"
	}
} 
if ( $userName -eq [string]::Empty ) {
	$userName = Read-Host -Prompt 'Which user do you want to authorize? (Format: account name, ie jgullo)'
}
if ( $computerName -eq [string]::Empty ) {
	$computerName = Read-Host -Prompt 'What computer would you like to grant Guacamole access to? (Format: ORGPREFIX-DT0057)'
}

if ( -Not ( get-aduser $userName -ErrorAction SilentlyContinue ) ) {
	Write-Host "There is no user for the username specified, we cannot proceed!"
	Exit
}

if ( Test-Connection -Quiet -Computername "$computerName" -ErrorAction SilentlyContinue ) { 
	Write-Host "Attempting to authorize $userName to connect to $computerName through Guacamole!"
	Invoke-Command -ComputerName $computerName -ArgumentList $userName -Scriptblock { Add-LocalGroupMember -Group "Remote Desktop Users" -Member $args[0] }
	Write-Host "The following users are authorized for Remote Connection to this computer:"
	Invoke-Command -ComputerName $computerName -Scriptblock { 
		$groupMembers = Get-LocalGroupMember -Group "Remote Desktop Users" 
		foreach ( $member in $groupMembers ) {
			Write-Host $member.Name
		}
	}
} else {
	Write-Host "We cannot reach the computer so we cannot authorize the user.  Is the computer powered on?"
}
