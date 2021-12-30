####
# 
# Name: Audit.InsecureLDAPBinds
# Author: Joseph Gullo
# Last Modification: 2021.12.28
# Description: This script searched AD records for binds using ldap
#   instead of ldaps as the protocol will be deprecated.
# References: Various snippets of code adapted from many web 
#   searches, the sources of which are long lost
#
####

#set-itemproperty -path HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics -name "16 LDAP Interface Events" -value 2

$dateStrMin = Get-Date -UFormat "%Y.%m.%d-%H.%M.%S"
$Today = (Get-Date)
$outFile = "Audit.InsecureLDAPBinds.$dateStrMin.csv"
$S = 'ORGPREFIX-DOMCTR-01', 'ORGPREFIX-DOMCTR-02', 'ORGPREFIX-DOMCTR-03', 'ORGPREFIX-DOMCTR-DR', 'ORGPREFIX-S5-DC', 'ORGPREFIX-S3-DC', 'ORGPREFIX-S4-DC', 'ORGPREFIX-S6-DC', 'ORGPREFIX-S2-DC'
$Events = $null
$InsecureLDAPBinds = @()
$Hours = 48
ForEach ($Server in $S) {
	write-host $Server
	$EventSite = Get-WinEvent -ComputerName $Server -FilterHashtable @{
		Logname='Directory Service';
		Id=2889; 
		StartTime=(get-date).AddHours("-$Hours")
	} -ErrorAction SilentlyContinue
	
	# Loop through each event and output the 
	ForEach ($Event in $EventSite) { 
		$eventXML = [xml]$Event.ToXml()
		
		# Build Our Values
		$Client = ($eventXML.event.EventData.Data[0])
		$IPAddress = $Client.SubString(0,$Client.LastIndexOf(":")) #Accomodates for IPV6 Addresses
		$Port = $Client.SubString($Client.LastIndexOf(":")+1) #Accomodates for IPV6 Addresses
		$User = $eventXML.event.EventData.Data[1]
		Switch ($eventXML.event.EventData.Data[2])
			{
			0 {$BindType = "Unsigned"}
			1 {$BindType = "Simple"}
			}
		$TimeStamp = $Event.TimeCreated
		# Add Them To a Row in our Array
		$Row = "" | select IPAddress,Port,User,BindType,Timestamp
		$Row.IPAddress = $IPAddress
		$Row.Port = $Port
		$Row.User = $User
		$Row.BindType = $BindType
		$Row.Timestamp = $TimeStamp
		
		# Add the row to our Array
		$InsecureLDAPBinds += $Row
	}
}

# Dump it all out to a CSV.
Write-Host $InsecureLDAPBinds.Count "records saved to $outFile for Domain Controllers"
$InsecureLDAPBinds | Export-CSV -NoTypeInformation $outFile

$InsecureLDAPBinds = @()


