####
# 
# Name: ExportMailboxToPST
# Author: Joseph Gullo
# Last Modification: 2021.12.28
# Description: This opens a powershell session on the EMAILange server
#   to export a user's mailbox to a PST.
# References: 
#
####

$userName = Read-Host -Prompt 'Which mailbox do you want to export to a pst? (Format: account name, ie jgullo)'
$dateStr = Get-Date -UFormat "%Y.%m.%d"
$dateStrMin = Get-Date -UFormat "%Y.%m.%d-%H.%M.%S"

# Engage a powershell session of the EMAILange management shell if one is not already active
if ( -not ( Get-Command Get-Mailbox -ErrorAction SilentlyContinue ) ) { 
	$ExOPSession = New-PSSession -ConfigurationName Microsoft.EMAILange -ConnectionUri http://ORGPREFIX-EMAIL-01.ad.DOMAIN.org/PowerShell/ -Authentication Kerberos
	Import-PSSession $ExOPSession *>&1 | out-null
}
# Export the user's mailbox to a PST File
$pstExportPath = "\\ORGPREFIX-sharepointDSTORAGE.AD.DOMAIN.ORG\userArchive$\Archive_PST\$userName.$dateStr.pst"
$pstJobName = "$userName.$dateStrMin"
#write-host $userName
#write-host $pstExportPath
#write-host $pstJobName
New-MailboxExportRequest -Mailbox $userName -FilePath $pstExportPath -Name $pstJobName -BadItemLimit unlimited -ErrorAction SilentlyContinue
#While ( "$($(Get-MailboxExportRequest -Name $pstJobName).Status)" -ne "Completed" ) {
While ( "$(((Get-MailboxExportRequest -Name $pstJobName | Get-MailboxExportRequestStatistics -IncludeReport).Report.Entries[(Get-MailboxExportRequest | Get-MailboxExportRequestStatistics -IncludeReport).Report.Entries.Count -1]).Message.StringId)" -ne "ExDABAF1" ) {
	Sleep 30 
}

Get-MailboxExportRequest -Name $pstJobName | Remove-MailboxExportRequest -Confirm:$false

# End the EMAILange session
Remove-PSSession $ExOPSession
Exit-PSSession
