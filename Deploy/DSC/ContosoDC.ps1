Configuration ContosoDC {
    Param (
        [string]$DomainName="Contoso",
        [String]$targetDrive = "C",
        [String]$targetADPath = "$targetDrive" + ":\ADDS",
        [Securestring]$secPassword = (ConvertTo-SecureString "Password01" -AsPlainText -Force),
        [PSCredential]$domaincreds
    )

    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'xPSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'ComputerManagementDsc'
    Import-DscResource -ModuleName 'StorageDSC'
    Import-DscResource -ModuleName 'NetworkingDSC'
    Import-DscResource -ModuleName 'DnsServerDsc'
    Import-DscResource -ModuleName 'cChoco'
    Import-DscResource -ModuleName 'DSCR_Shortcut'
    Import-DscResource -ModuleName 'xCredSSP'
    Import-DscResource -ModuleName 'ActiveDirectoryDsc'

    Node "ContosoDC" {
        #$netAdapters = Get-NetAdapter -Name ($ipConfig.InterfaceAlias) | Select-Object -First 1
        #$InterfaceAlias = $($netAdapters.Name) 
        
        if ( $domaincreds -eq $null) {
           $domaincreds= New-Object System.Management.Automation.PSCredential ("Contoso\Administrator", $secPassword)
            }

            #Windows Features
            WindowsFeature DNS { 
                Ensure = "Present" 
                Name   = "DNS"		
            }

            Script EnableDNSDiags {
                SetScript  = { 
                    Set-DnsServerDiagnostics -All $true
                    Write-Verbose -Verbose "Enabling DNS client diagnostics" 
                }
                GetScript  = { @{} }
                TestScript = { $false }
                DependsOn  = "[WindowsFeature]DNS"
            }

            WindowsFeature DnsTools {
                Ensure    = "Present"
                Name      = "RSAT-DNS-Server"
                DependsOn = "[WindowsFeature]DNS"
            }

            DnsServerAddress "DnsServerAddress for ContosoDC"
            { 
                Address        = '127.0.0.1'
                InterfaceAlias = "Ethernet"
                AddressFamily  = 'IPv4'
                DependsOn      = "[WindowsFeature]DNS"
            }

       
            WindowsFeature ADDSInstall { 
                Ensure    = "Present" 
                Name      = "AD-Domain-Services"
                DependsOn = "[WindowsFeature]DNS" 
            }

            WindowsFeature ADDSTools {
                Ensure    = "Present"
                Name      = "RSAT-ADDS-Tools"
                DependsOn = "[WindowsFeature]ADDSInstall"
            }

            WindowsFeature ADAdminCenter {
                Ensure    = "Present"
                Name      = "RSAT-AD-AdminCenter"
                DependsOn = "[WindowsFeature]ADDSInstall"
            }
         
            ADDomain FirstDS {
                DomainName                    = $DomainName
                Credential                    = $DomainCreds
                SafemodeAdministratorPassword = $DomainCreds
                DatabasePath                  = "$targetADPath" + "\NTDS"
                LogPath                       = "$targetADPath" + "\NTDS"
                SysvolPath                    = "$targetADPath" + "\SYSVOL"
                DependsOn                     = @("[WindowsFeature]ADDSInstall")
            }

        

        }
}

$Configdata=@{
allnodes=@(
    @{
        nodename="ContosoDC"
        PSDSCAllowPlainTextPassword=$true
    }
)
}

ContosoDC -ConfigurationData $configdata 