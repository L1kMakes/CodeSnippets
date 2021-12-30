####
# 
# Name: ExportADUsersToCSV
# Author: Jospeh Gullo
# Last Modification: 2021.12.28
# Description: Dumps a subset of AD info to a CSV file.
# References: 
#
####

$path = Split-Path -parent "C:\Working\ExportADUsers\*.*"
$LogDate = get-date -f yyyyMMddhhmm
$csvfile = $path + "\ALLADUsers_$logDate.csv"

Import-Module ActiveDirectory
$SearchBase = "DC=ad,DC=DOMAIN,DC=org"

$ADServer = 'ORGPREFIX-DOMCTR-01'

$AllADUsers = Get-ADUser -server $ADServer -Filter { ( ( enabled -eq $true ) -AND ( title -notlike 'Service Account -*' ) -AND ( title -notlike 'Mailbox -*' ) -AND ( title -notlike 'Test Account -*' ) ) -OR ( ( enabled -eq $true ) -AND ( title -notlike '*' ) ) } -Properties * | Sort Surname

$AllADUsers |
Select-Object @{Label = "First Name";Expression = {$_.GivenName}},
@{Label = "Logon Name";Expression = {$_.sAMAccountName}},
@{Label = "Last Name";Expression = {$_.Surname}},
@{Label = "Display Name";Expression = {$_.DisplayName}},
@{Label = "Office";Expression = {$_.Office}},
@{Label = "Full address";Expression = {$_.StreetAddress}},
@{Label = "City";Expression = {$_.City}},
@{Label = "State";Expression = {$_.st}},
@{Label = "Post Code";Expression = {$_.PostalCode}},
@{Label = "Country/Region";Expression = {if (($_.Country -eq 'GB')  ) {'United Kingdom'} Else {''}}},
@{Label = "Company";Expression = {$_.Company}},
@{Label = "Department";Expression = {$_.Department}},
@{Label = "Job Title";Expression = {$_.Title}},
@{Label = "Description";Expression = {$_.Description}},
@{Label = "Phone";Expression = {$_.telephoneNumber}},
@{Label = "Mobile";Expression = {$_.mobile}},
@{Label = "MobilePhone";Expression = {$_.mobilePhone}},
@{Label = "Email";Expression = {$_.Mail}},
@{Label = "Manager";Expression = {%{(Get-AdUser $_.Manager -server $ADServer -Properties DisplayName).DisplayName}}},
@{Label = "Account Status";Expression = {if (($_.Enabled -eq 'TRUE')  ) {'Enabled'} Else {'Disabled'}}}, # the 'if statement# replaces $_.Enabled
@{Label = "Last LogOn Date";Expression = {$_.lastlogondate}},
@{Label = "OU";Expression = {$_.CanonicalName}} | Export-Csv -Path $csvfile -NoTypeInformation
