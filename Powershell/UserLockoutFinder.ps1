####
# 
# Name: UserLockoutFinder
# Author: Joseph Gullo
# Last Modification: 2021.12.28
# Description: This scans all domain controllers for lockout events
#   in order to identify the source of repeated user lockouts.
# References: 
#
####

# Run this script WHILE THE USER IS STILL LOCKED OUT
clear-host
$userName = Read-Host -Prompt 'Which user do you want to investigate for lockouts? (Format: account name, ie jgullo)'
# Figure out which DC user is authenticating against on their real computer login…doesn’t mean it’s where they're locking out from, but if it’s something on their computer it’s the highest chance of hit:
select-string -Path  '\\ORGPREFIX-sharepointDSTORAGE.AD.DOMAIN.ORG\ORGPREFIXComputerLoginTracking$\info.txt' -Pattern '$userName'
$UserInfo = Get-ADUser -Identity $userName

if ( -not ( ( get-aduser -filter { SAMAccountName -eq $userName } -Properties LockedOut ).LockedOut ) ) {
    Write-host "The account $userName was NOT locked."
    $endRaw = ( get-date ).addseconds(30)
    $beginRaw = ( get-date ).addhours(-12)
    $end = (get-date -Date $endRaw -UFormat "%m/%d/%y %H:%M:%S") 
    $begin = get-date -Date $beginRaw -UFormat "%m/%d/%y %H:%M:%S"
} else {
    #get-aduser $userName -properties LockoutTime,LockedOut,WhenChanged | % {$_.LockedOut; $_.LockoutTime}
    # Confirm they are locked out, and the lockout time
    $LockTime = get-aduser $userName -properties LockoutTime,LockedOut,LastLogon | % {$_.LockoutTime}
	while ( ( get-aduser -filter { SAMAccountName -eq $userName } -Properties LockedOut ).LockedOut ) {
		unlock-adaccount -identity $userName
		sleep 5
	}
    Write-host "The account $userName is now unlocked."
    $LockTime = (get-date -Date $LockTime).addhours(-7)
    $endRaw = (get-date -Date $LockTime).addseconds(30)
    $beginRaw = (get-date -Date $LockTime).addminutes(-5)
    $end = get-date -Date $endRaw -UFormat "%m/%d/%y %H:%M:%S"
    $begin = get-date -Date $beginRaw -UFormat "%m/%d/%y %H:%M:%S"
}

Write-host "Beginning time to search: $begin"
Write-host "End time to search: $end"

# Engage a powershell session of the EMAILange management shell if one is not already active
if ( -not ( Get-Command Get-Mailbox -ErrorAction SilentlyContinue ) ) { 
    $ExOPSession = New-PSSession -ConfigurationName Microsoft.EMAILange -ConnectionUri http://ORGPREFIX-EMAIL-01.ad.DOMAIN.org/PowerShell/ -Authentication Kerberos
    Import-PSSession $ExOPSession *>&1 | out-null
}

$lockoutReport = @()

$EMAILangeGuid = (get-mailbox -Identity $userName).EMAILangeGuid
write-host "Checking the PDC for lockout events."
#Get main DC
$PDC = (Get-ADDomainController -Filter * | Where-Object {$_.OperationMasterRoles -contains "PDCEmulator"})
#Get user info
$UserInfo = Get-ADUser -Identity $userName
#Search PDC for lockout events with ID 4740
$LockedOutEvents = Get-WinEvent -ComputerName $PDC.HostName -FilterHashtable @{
    LogName='Security';
    Id=4740;
    StartTime=$begin;
    EndTime=$end
} -ErrorAction SilentlyContinue | Sort-Object -Property TimeCreated -Descending
#Parse and filter out lockout events
Foreach($Event in $LockedOutEvents) {
    If($Event | Where {$_.Properties[2].value -match $UserInfo.SID.Value}) {
        $lockoutEntry = [PSCustomObject]@{
            'User'=$Event.Properties[0].Value
            'DomainController'=$Event.MachineName
            'EventId'=$Event.Id
            'LockoutTimeStamp'=$Event.TimeCreated
            'Message'=$Event.Message -split "`r" | Select -First 1
            'LockoutSource'=$Event.Properties[1].Value
        }
        #$LockoutEntry
        $lockoutReport += $LockoutEntry
    }    
}        

# GetLogs
$S = 'ORGPREFIX-DOMCTR-01', 'ORGPREFIX-DOMCTR-02', 'ORGPREFIX-DOMCTR-03', 'ORGPREFIX-DOMCTR-DR', 'ORGPREFIX-S5-DC', 'ORGPREFIX-S3-DC', 'ORGPREFIX-S4-DC', 'ORGPREFIX-S6-DC', 'ORGPREFIX-S2-DC'
$Events = $null
ForEach ($Server in $S) {
    #write-host $Server
    write-host "Checking $Server for failed authentication events."
    $LockedOutEvents = Get-WinEvent -ComputerName $Server -FilterHashtable @{
        LogName="Security";
        ID=4771;
        StartTime=$begin;
        EndTime=$end
    } -ErrorAction SilentlyContinue
    Foreach($Event in $LockedOutEvents) {
        If($Event | Where {$_.Properties[1].value -match $UserInfo.SID.Value}) {
            $lockoutEntry = [pscustomobject]@{
                'User'=$Event.Properties[0].Value
                'DomainController'=$Event.MachineName
                'EventId'=$Event.Id
                'LockoutTimeStamp'=$Event.TimeCreated
                'Message'=$Event.Message -split "`r" | Select -First 1
                'LockoutSource'=$event.Properties[6].Value
            }
            #$LockoutEntry
            $lockoutReport += $LockoutEntry
        }    
    }    
    #$LockedOutEvents | Sort TimeCreated | Format-Table –Wrap
}
#Write-Host "FINAL TALLY"
$lockoutReport | Sort LockoutTimeStamp | Format-Table –Wrap

Write-Host "EMAILange mailboxID is $EMAILangeGuid for $userName; get ready for a lot file to open so you can correlate some DATES"

$LogFolder1 = "\\ORGPREFIX-EMAIL-01\L$\EMAILange IIS Logs\W3SVC1"
$LogFiles1 = [System.IO.Directory]::GetFiles($LogFolder1, "*.log")
$LogFolder2 = "\\ORGPREFIX-EMAIL-01\L$\EMAILange IIS Logs\W3SVC2"
$LogFiles2 += [System.IO.Directory]::GetFiles($LogFolder2, "*.log")
$LogFolder3 = "\\ORGPREFIX-EMAIL-01\L$\EMAILange IIS Logs\W3SVC3"
$LogFiles3 += [System.IO.Directory]::GetFiles($LogFolder3, "*.log")
$LogTemp = "C:\Windows\Temp\AllLogs.txt"
$Logs = @()
$LogColumns = ( $LogFiles1 | select -first 1 | % { Get-Content $_ | where {$_ -Like "#[F]*" } } ) -replace "#Fields: ", "" -replace "-","" -replace "\(","" -replace "\)",""
$LogFiles1 | select -last 30 | % { Get-Content $_ | where {$_ -notLike "#[D,F,S,V]*" } | where { $_ -like "*$EMAILangeGuid*" } | % { $Logs += $_ } }
$LogFiles2 | select -last 30 | % { Get-Content $_ | where {$_ -notLike "#[D,F,S,V]*" } | where { $_ -like "*$EMAILangeGuid*" } | % { $Logs += $_ } }
$LogFiles3 | select -last 30 | % { Get-Content $_ | where {$_ -notLike "#[D,F,S,V]*" } | where { $_ -like "*$EMAILangeGuid*" } | % { $Logs += $_ } }
$Logs = $Logs | Sort
Set-Content -LiteralPath $LogTemp -Value ( [System.String]::Format( "{0}{1}{2}", $LogColumns, [Environment]::NewLine, ( [System.String]::Join( [Environment]::NewLine, $Logs ) ) ) )
notepad $LogTemp
sleep 5
rm $LogTemp
