####
# 
# Name: Audit.AccountAuthUsage
# Author: Joseph Gullo
# Last Modification: 2021.12.28
# Description: This script crawls domain controllers and looks for 
#   certain login and logout events to understand if a service account 
#    is used.
# References: Various snippets of code adapted from many web 
#   searches, the sources of which are long lost
#
####

Clear-Host
$dateStr = Get-Date -UFormat "%Y.%m.%d-%H.%M"
$StartTime = (Get-Date).AddDays(-1)
$outFileRemotePath = "\\ORGPREFIX-sharepointDSTORAGE.AD.DOMAIN.ORG\IT\Documentation"
$outFileLocalPath = "C:\temp"
$outFilePrefix = "Audit.AuthEvents"
$outFilePrefixDate = "$outFilePrefix.$dateStr"
$DomainControllers=Get-ADComputer -Filter * -SearchBase "OU=Domain Controllers, DC=AD, DC=DOMAIN, DC=org"
sleep 2
foreach ( $DC in $DomainControllers ) {
	$DCName = $DC.Name
	$outLogFileRemote = "$outFileRemotePath\$outFilePrefixDate.$DCName.csv"
	$outLogFileLocal = "$outFileLocalPath\$outFilePrefixDate.$DCName.csv"
#Write-Output $DCName $outLogFileRemote $outLogFileLocal
	Start-Job -ScriptBlock {
#Write-Output "Debug 01: "$args[0]
		$DCName2 = $args[0]
		$properties4624 = @(
			'TimeCreated',
			'TaskDisplayName',
			@{n='Keyword';e={$_.KeywordsDisplayNames[0]}},
			@{n='Account';e={$_.Properties[5].Value}},
			@{n='Target';e=' '},
			@{n='IPAddress';e={$_.Properties[18].Value}},
			'ID',
			@{n='DC';e={$($DCName2)}},
			@{n='EventName';e={$('An Account was Successfully Logged On.')}}
		)
		$results4624 = Get-Winevent -ComputerName $args[0] -FilterHashtable @{logname="Security"; id="4624"; StartTime=$args[1]} -ErrorAction SilentlyContinue | Select $properties4624 | Where-Object {$_.Account -notlike "ORGPREFIX-*"} 
#Write-Output "Debug 02: "$args[0]
		$properties4648 = @(
			'TimeCreated',
			'TaskDisplayName',
			@{n='Keyword';e={$_.KeywordsDisplayNames[0]}},
			@{n='Account';e={$_.Properties[5].Value}},
			@{n='Target';e={$_.Properties[1].Value}},
			@{n='IPAddress';e={$_.Properties[12].Value}},
			'ID',
			@{n='DC';e={$($DCName2)}},
			@{n='EventName';e={$('Logon Attempted With Explicit Credentials')}}
		)
		$results4648 = Get-Winevent -ComputerName $args[0] -FilterHashtable @{logname="Security"; id="4648"; StartTime=$args[1]} -ErrorAction SilentlyContinue | Select $properties4648 
#Write-Output "Debug 03: "$args[0]
		$properties4771 = @(
			'TimeCreated',
			'TaskDisplayName',
			@{n='Keyword';e={$_.KeywordsDisplayNames[0]}},
			@{n='Account';e={$_.Properties[0].Value}},
			@{n='Target';e=' '},
			@{n='IPAddress';e={$_.Properties[6].Value}},
			'ID',
			@{n='DC';e={$($DCName2)}},
			@{n='EventName';e={$('Kerberos pre-authentication failed')}}
		)
		$results4771 = Get-Winevent -ComputerName $args[0] -FilterHashtable @{logname="Security"; id="4771"; StartTime=$args[1]} -ErrorAction SilentlyContinue | Select $properties4771 | Where-Object {$_.Account -notlike "ORGPREFIX-*"} 
#Write-Output "Debug 04: "$args[0]
		$properties4768 = @(
			'TimeCreated',
			'TaskDisplayName',
			@{n='Keyword';e={$_.KeywordsDisplayNames[0]}},
			@{n='Account';e={$_.Properties[0].Value}},
			@{n='Target';e=' '},
			@{n='IPAddress';e={$_.Properties[9].Value}},
			'ID',
			@{n='DC';e={$($DCName2)}},
			@{n='EventName';e={$('A Kerberos Ticket Was Requested')}}
		)
		$results4768 = Get-Winevent -ComputerName $args[0] -FilterHashtable @{logname="Security"; id="4768"; StartTime=$args[1]} -ErrorAction SilentlyContinue | Select $properties4768 | Where-Object {$_.Account -notlike "ORGPREFIX-*"} 
#Write-Output "Debug 05: "$args[0]
		$results = $results4624 + $results4648 + $results4768 + $results4771
#Write-Output "Debug 06: "$args[0]
		$results | sort-object -Property 'TimeCreated' | export-csv -Path $args[2] -NoTypeInformation
#Write-Output "Debug 07: "$args[0]
		$results | sort-object -Property 'TimeCreated' | export-csv -Path $args[3] -NoTypeInformation
#Write-Output "Debug 08: "$args[0]
		[io.file]::readalltext($args[2]).replace("::ffff:","") | Out-File $args[2] -Encoding ascii –Force
#Write-Output "Debug 09: "$args[0]
		[io.file]::readalltext($args[3]).replace("::ffff:","") | Out-File $args[3] -Encoding ascii –Force
#Write-Output "Debug 10: "$args[0]
		Write-Host "END: "$args[0]" $(Get-Date)"

	} -ArgumentList $DCName, $StartTime, $outLogFileRemote, $outLogFileLocal
}
Do {
	Clear-Host
	$AllJobs = Get-Job -State Running
	Get-Job
	Sleep 10
} While ( $AllJobs )
$jobs = Get-Job
foreach ($job in $jobs) {
	Receive-Job $job
	remove-job $job
}
Get-ChildItem -recurse -Path "$outFileRemotePath\$outFilePrefixDate.*.csv" | % { Get-Content $_ -ReadCount 0 | Add-Content "$outFileRemotePath\$outFilePrefix.Complete.$dateStr.csv" }
Get-ChildItem -recurse -Path "$outFileLocalPath\$outFilePrefixDate.*.csv" | % { Get-Content $_ -ReadCount 0 | Add-Content "$outFileLocalPath\$outFilePrefix.Complete.$dateStr.csv" }
Remove-Item "$outFileRemotePath\$outFilePrefixDate.*.csv"
Remove-Item "$outFileLocalPath\$outFilePrefixDate.*.csv"


Get-Winevent -MaxEvents 5 -FilterHashtable @{logname="Security"; id="4624"} | %{([xml]$_.ToXml()).Event.EventData.Data}
Get-Winevent -MaxEvents 5 -FilterHashtable @{logname="Security"; id="4648"} | %{([xml]$_.ToXml()).Event.EventData.Data}
Get-Winevent -MaxEvents 5 -FilterHashtable @{logname="Security"; id="4768"} | %{([xml]$_.ToXml()).Event.EventData.Data}
Get-Winevent -MaxEvents 5 -FilterHashtable @{logname="Security"; id="4771"} | %{([xml]$_.ToXml()).Event.EventData.Data}
Get-Winevent -MaxEvents 5 -FilterHashtable @{logname="Security"; id="4777"} | %{([xml]$_.ToXml()).Event.EventData.Data}



Clear-Host
$dateStr = Get-Date -UFormat "%Y.%m.%d"
$StartTime = (Get-Date).AddMinutess(-1)
$outFile = "C:\temp\LogonEventAudit.$dateStr.csv"
$properties4624 = @(
	'TimeCreated',
	'TaskDisplayName',
	@{n='Keyword';e={$_.KeywordsDisplayNames[0]}},
	@{n='Account';e={$_.Properties[5].Value}},
	@{n='Target';e=' '},
	@{n='IPAddress';e={$_.Properties[18].Value}},
	'ID',
	@{n='EventName';e={$('An Account was Successfully Logged On.')}}
)
Get-Winevent -MaxEvents 10 -FilterHashtable @{logname="Security"; id="4624"; StartTime=$StartTime} | Select $properties4624 | Where-Object {$_.Account -notlike "ORGPREFIX-*"} | ft
$results4624 = Get-Winevent -FilterHashtable @{logname="Security"; id="4624"; StartTime=$StartTime} | Select $properties4624 | Where-Object {$_.Account -notlike "ORGPREFIX-*"} 
$properties4648 = @(
	'TimeCreated',
	'TaskDisplayName',
	@{n='Keyword';e={$_.KeywordsDisplayNames[0]}},
	@{n='Account';e={$_.Properties[5].Value}},
	@{n='Target';e={$_.Properties[1].Value}},
	@{n='IPAddress';e={$_.Properties[12].Value}},
	'ID',
	@{n='EventName';e={$('Logon Attempted With Explicit Credentials')}}
)
$results4648 = Get-Winevent -FilterHashtable @{logname="Security"; id="4648"; StartTime=$StartTime} | Select $properties4648 
$properties4771 = @(
	'TimeCreated',
	'TaskDisplayName',
	@{n='Keyword';e={$_.KeywordsDisplayNames[0]}},
	@{n='Account';e={$_.Properties[0].Value}},
	@{n='Target';e=' '},
	@{n='IPAddress';e={$_.Properties[6].Value}},
	'ID',
	@{n='EventName';e={$('Kerberos pre-authentication failed')}}
)
$results4771 = Get-Winevent -FilterHashtable @{logname="Security"; id="4771"; StartTime=$StartTime} | Select $properties4771 | Where-Object {$_.Account -notlike "ORGPREFIX-*"} 
$properties4768 = @(
	'TimeCreated',
	'TaskDisplayName',
	@{n='Keyword';e={$_.KeywordsDisplayNames[0]}},
	@{n='Account';e={$_.Properties[0].Value}},
	@{n='Target';e=' '},
	@{n='IPAddress';e={$_.Properties[9].Value}},
	'ID',
	@{n='EventName';e={$('A Kerberos Ticket Was Requested')}}
)
$results4768 = Get-Winevent -FilterHashtable @{logname="Security"; id="4768"; StartTime=$StartTime} | Select $properties4768 | Where-Object {$_.Account -notlike "ORGPREFIX-*"} 
$results = $results4624 + $results4648 + $results4768 + $results4771
$results | sort-object -Property 'TimeCreated' | export-csv -Path "$outFile" -NoTypeInformation
[io.file]::readalltext("$outFile").replace("::ffff:","") | Out-File "$outFile" -Encoding ascii –Force


