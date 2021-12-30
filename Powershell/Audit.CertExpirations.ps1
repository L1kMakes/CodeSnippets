####
# 
# Name: Audit.CertExpirations
# Author: Joseph Gullo
# Last Modification: 2021.12.28
# Description: Crawl through all servers in Active Directory and
#   check through the certs used on them to look for upcoming expirations
# References: Various snippets of code adapted from many web 
#   searches, the sources of which are long lost
#
####

# Get all certificates from all servers
$dateStrMin = Get-Date -UFormat "%Y.%m.%d-%H.%M.%S"
$outFile = "Audit.CertExpirations.$dateStrMin.log"
$serverCert = $null
ipconfig /flushdns
$offlineServers = "The following servers are offline and could not be checked:"
$servers=get-adcomputer -filter { ( OperatingSystem -like '*server*') -AND ( Name -notlike '*-DT0094' ) } | sort Name
foreach ( $server in $servers ) { 
	$ServerName=$server.Name
	$ServerName="$ServerName.AD.DOMAIN.ORG"
	if ( Test-Connection -Count 1 -Computername "$ServerName" -ErrorAction SilentlyContinue ) { 
		$serverCert += Invoke-Command -ComputerName $ServerName -Scriptblock { 
			return $(Get-ChildItem Cert:\LocalMachine\My | Select-Object *, @{N="Description";E={$_.FriendlyName}}, @{N="TemplateName";E={($_.Extensions | ?{$_.oid.Friendlyname -match "Certificate Template Information"}).Format(0) -replace "(.+)?=(.+)\((.+)?", '$2' -replace 'Template=', '' -replace '1.3.6.1.4.1.311.21.8.16245382.12313948.10571683.3565079.1665071.100.15924968.15384388.*', 'SCCM Client Certificate' -replace '1.3.6.1.4.1.311.21.8.16245382.12313948.10571683.3565079.1665071.100.9941395.14900143.*','ORGPREFIX IIS Web Servers' -replace '1.3.6.1.4.1.311.21.8.16245382.12313948.10571683.3565079.1665071.100.1979823.4984146.*','WSUS Web Server Certificate'}})
		}
	} else {
		$offlineServers="$offlineServers $ServerName"
	}
}
$serverCert | Select-Object PSComputerName, Description, NotAfter, TemplateName, @{N="IssuedBy";E={($_.IssuerName.Name -split ',*..=')[1]}}, @{N="Subject";E={($_.Subject -split ',*..=')[1]}} | Sort NotAfter, PSComputerName | Format-Table -Wrap | Out-File -Append -FilePath $outFile
Write-Output $offlineServers | Out-File -Append -FilePath $outFile
