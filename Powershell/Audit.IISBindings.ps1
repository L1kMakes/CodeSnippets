####
# 
# Name: Audit.IISBindings
# Author: Joseph Gullo
# Last Modification: 2021.12.28
# Description: Due to some TLS Security flaws, we needed to
#   scan all IIS instances and output a record of which servers
#   needed patching and configuration
# References: Various snippets of code adapted from many web 
#   searches, the sources of which are long lost
#
####

# Show all updates on all servers
function checkIISBindings () {
    ipconfig /flushdns
    $dateStrMin = Get-Date -UFormat "%Y.%m.%d-%H.%M.%S"
    $csvOutFile = "Audit.IISBindings.$dateStrMin.csv"
    $IISBindingReport = @()
    $servers=get-adcomputer -filter { ( OperatingSystem -like '*server*') -AND ( Name -notlike '*-EMAILange10' ) } | sort Name
    foreach ( $server in $servers ) { 
        $ServerName=$server.Name
        $ServerName="$ServerName.AD.DOMAIN.ORG"
        Get-adcomputer -filter { cn -like $ServerName} -Properties Description | ForEach-Object {$_.Description}
        if ( Test-Connection -Count 1 -Computername "$ServerName" -ErrorAction SilentlyContinue ) { 
            $Result = Invoke-Command -Computer $ServerName -ScriptBlock { 
                $IISBindingEntries = @()
                if ( ( ( Get-WindowsFeature Web-Server ).InstallState -eq "Installed" ) -or ( (Get-WindowsFeature Web-Server).Installed -eq "True" ) ) {
                    If (!(Get-module -Name WebAdministration)) {
                        Import-Module -Name WebAdministration -ErrorAction SilentlyContinue
                    }
                    If (!(Get-module -Name PowerShellGet)) {
                        Import-Module -Name PowerShellGet -ErrorAction SilentlyContinue
                    }
                    If (!(Get-PackageProvider "NuGet")) {
                        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction SilentlyContinue
                    }
                    If (!(Get-module -Name IISAdministration)) {
                        Install-Module –Name IISAdministration -Confirm:$False -Force -ErrorAction SilentlyContinue
                        Import-Module -Name IISAdministration -ErrorAction SilentlyContinue
                    }
                    $sites = Get-ChildItem -Path IIS:Sites
                    foreach ( $site in $sites ) { 
                        $siteName = $site.Name
                        $siteID = $site.ID
                        $siteBindings = $site.bindings
                        $sslBindings = Get-ChildItem -Path IIS:SSLBindings | Where-Object { $_.Sites.Value -eq $siteName }
                        foreach ( $binding in $siteBindings.Collection ) {
                            $bindingProtocol = $binding.Protocol
                            $bindingInfo = $binding.bindingInformation
                            $bindingFlag = $binding.sslFlags
                            $sslBindings | Where-Object { $bindingInfo -like $_.Port }
                            $bindingThumbprint = $binding.certificateHash
                            $certName = ""
                            $certSubject = ""
                            $certExp = ""
                            $certDNS = ""
                            if ( $bindingThumbprint ) {
                                $certificate = Get-ChildItem -Path CERT:LocalMachine/My | Where-Object -Property Thumbprint -EQ -Value $bindingThumbprint
                                if ( $certificate.FriendlyName ) {
                                    $certName = $certificate.FriendlyName
                                } else {
                                    $certName = "No Certificate Selected"
                                }
                                $certSubject = $certificate.Subject
                                $certExp = $certificate.NotAfter
                                $certDNS = $certificate.DnsNameList
                            }
                            $iisBindingEntry = [pscustomobject]@{
                                'Host'=$env:Computername
                                'SiteName'=$siteName
                                'SiteID'=$siteID
                                'BindingProtocol'=$bindingProtocol
                                'BindingInformation'=$bindingInfo
                                'CertificateName'=$certName
                                'CertificateSubject'=$certSubject
                                'CertificateExpiration'=$certExp
                                'CertificateDNSAliases'=$certDNS
                            }
                            $IISBindingEntries += $iisBindingEntry
                        }
                    }
                } 
                Return $IISBindingEntries
            }
            $IISBindingReport += $Result
        }
    }
    $IISBindingReport | export-csv -Path $csvOutFile -Append -NoTypeInformation
}
checkIISBindings
