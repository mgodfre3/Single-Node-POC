Configuration ContosoDC {
    Param (
        [string]$DomainName="Contoso",
        [String]$targetDrive = "C",
        [String]$targetADPath = "$targetDrive" + ":\ADDS",
        [Securestring]$secPassword = (ConvertTo-SecureString "Password01" -AsPlainText -Force),
        [PSCredential]$domaincreds
    )

    #Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'xPSDesiredStateConfiguration' -ModuleVersion 9.1.0
    Import-DscResource -ModuleName 'ComputerManagementDsc' -ModuleVersion 8.5.0
    Import-DscResource -ModuleName 'StorageDSC' -ModuleVersion 5.0.1
    Import-DscResource -ModuleName 'NetworkingDSC' -ModuleVersion 8.2.0
    Import-DscResource -ModuleName 'DnsServerDsc' -ModuleVersion 3.0.0
    Import-DscResource -ModuleName 'cChoco' -ModuleVersion 2.5.0.0 
    Import-DscResource -ModuleName 'DSCR_Shortcut' -ModuleVersion 2.2.0 
    Import-DscResource -ModuleName 'xCredSSP' -ModuleVersion 1.3.0.0
    Import-DscResource -ModuleName 'ActiveDirectoryDsc' -ModuleVersion 6.0.1 

    Node "ContosoDC" {
        #$netAdapters = Get-NetAdapter -Name ($ipConfig.InterfaceAlias) | Select-Object -First 1
        #$InterfaceAlias = $($netAdapters.Name) 
        
        if ( $domaincreds -eq $null) {
           $domaincreds= New-Object System.Management.Automation.PSCredential ("Contoso\Administrator", $secPassword)
            }
            #Set Net Adapter
            NetIPInterface DisableDhcp{
                InterfaceAlias = $InterfaceAlias
                AddressFamily  = 'IPv4'
                Dhcp           = 'Disabled'
            }

            IPAddress NewIPv4Address{
                IPAddress      = '192.168.1.254'
                InterfaceAlias = 'Ethernet'
                AddressFamily  = 'IPV4'
                DependsOn = '[NetIPInterface]DisableDHCP'
            }

            DefaultGatewayAddress SetDefaultGateway{
            Address        = '192.168.1.1'
            InterfaceAlias = 'Ethernet'
            AddressFamily  = 'IPv4'
            DependsOn = '[IPAddress]NewIPV4Address'
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
        PSDSCAllowDomainUser=$true
        
    }
)
}

ContosoDC -ConfigurationData $configdata 