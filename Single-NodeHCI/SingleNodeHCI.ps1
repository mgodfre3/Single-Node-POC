    
    
Configuration SingleNodeHCI {
    param(
[String]$targetDrive = "C",
[String]$targetVMPath = "$targetDrive" + ":\VMs",
[String]$server2019_uri="https://aka.ms/AAgscek",
[String]$wacUri = "https://aka.ms/wacdownload",
[String]$SwitchName="InternalSwitch",
[String]$ExtSwitchName="HCI-Uplink",
[String]$vhdPath = 'C:\temp\disk.vhdx',
[String]$relativeDestinationPath = '$env:SystemDrive\Windows\System32\Configuration\Pending.mof',
[String]$dcmofuri="https://github.com/mgodfre3/Single-Node-POC/blob/main/ContosoDC/ContosoDC.zip?raw=true",
[String]$netAdapters = (get-netadapter | Where-Object {$_.name -NotLike "vEthernet*" -and $_.status -eq "Up"}), 
[PSCredential]$domaincreds
)
   
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration' 
    Import-DscResource -ModuleName 'xPSDesiredStateConfiguration' -ModuleVersion 9.1.0 
    Import-DscResource -ModuleName 'xCredSSP' -ModuleVersion 1.3.0.0 
    Import-DscResource -ModuleName 'DSCR_Shortcut' -ModuleVersion 2.2.0
    Import-DscResource -ModuleName 'xHyper-V'
    Import-DscResource -ModuleName 'NetworkingDSC' -ModuleVersion 8.2.0 
    Import-DscResource -ModuleName ComputerManagementDsc -ModuleVersion 8.5.0
    Import-DscResource -ModuleName xFailOverCluster
    Import-DscResource -Module ActiveDirectoryDsc -ModuleVersion 6.0.1


    
    Node localhost{

            LocalConfigurationManager {
            RebootNodeIfNeeded = $true
            ActionAfterReboot  = 'ContinueConfiguration'
            ConfigurationMode = 'ApplyAndAutoCorrect'
            RefreshMode = 'Push'

             }

           

            #Windows Features Installations
            WindowsFeature Hyper-V {
            Ensure = 'Present'
            Name = "Hyper-V"
            IncludeAllSubFeature = $true 
            
            }
            
            WindowsFeature Hyper-V-PowerShell{
            Ensure = 'Present'
            Name='Hyper-V-PowerShell'
            IncludeAllSubFeature = $true
            }

            PendingReboot RebootAfterFeatureInstall{
            Name = 'FeatureInstall'
            DependsOn = '[WindowsFeature]Hyper-V', '[WindowsFeature]Hyper-V-PowerShell'
        }
            
            # Directory Requirments
            File "VMfolder" {
                Type            = 'Directory'
                DestinationPath = "$targetVMPath"
                
            }
        
            File "HCIVHDs" {
                Type            = 'Directory'
                DestinationPath = "$env:SystemDrive\HCIVHDs"
                
            }

            File "temp" {
                Type            = 'Directory'
                DestinationPath = "$env:SystemDrive\Temp"
                
            }

            xRemoteFile "ContosoDC-MOF"{
                uri=$dcmofuri
                DestinationPath="$env:SystemDrive\Temp\ContosoDC.zip"
                DependsOn="[File]Temp"
            }

        <#
            xRemoteFile "Server2019VHD"{
                uri=$server2019_uri
                DestinationPath="$env:SystemDrive\HCIVHDs\GUI.vhdx"
                DependsOn="[File]HCIVHDs"
            }
        #>
        
            Archive "ContosoDC-MOF" {
                Path="$env:SystemDrive\temp\ContosoDC.zip"
                Destination="$env:SystemDrive\Temp\ContosoDC\"
                DependsOn="[xRemoteFile]ContosoDC-MOF"
        
            }
        
            #Virtual Switch Configurations
           
            xVMSwitch ExternalSwitch
            {
                Ensure                = 'Present'
                Name                  = $ExtSwitchName
                Type                  = 'External'
                NetAdapterName        =  "Ethernet"
                EnableEmbeddedTeaming =  $true
                AllowManagementOS =  $true
                BandwidthReservationMode = "weight"
                LoadBalancingAlgorithm = 'Dynamic' 
                DependsOn      = '[WindowsFeature]Hyper-V'
            }

            # Internal Switch for DC 
            xVMSwitch InternalSwitch
            {
                Ensure         = 'Present'
                Name           = $SwitchName
                Type           = 'Internal'
                DependsOn      = '[WindowsFeature]Hyper-V'
            }

            IPAddress "New IP for vEthernet $SwitchName"
            {
                InterfaceAlias = "vEthernet (InternalSwitch)"
                AddressFamily  = 'IPv4'
                IPAddress      = '192.168.1.1/24'
                DependsOn      = "[xVMSwitch]InternalSwitch"
            }

            HostsFile HostsFileAddEntry{
            HostName  = 'Contoso.com'
            IPAddress = '192.168.1.254'
            Ensure    = 'Present'
        }
    <#
            NetIPInterface "Enable IP forwarding on vEthernet $SwitchName"
            {   
                AddressFamily  = 'IPv4'
                InterfaceAlias = "vEthernet `($vSwitchNameHost`)"
                Forwarding     = 'Enabled'
                DependsOn      = "[IPAddress]New IP for vEthernet $SwitchName"
            }
        #>
            <#
            script NAT {
                GetScript  = {
                    $nat = "AzSHCINAT"
                    $result = if (Get-NetNat -Name $nat -ErrorAction SilentlyContinue) { $true } else { $false }
                    return @{ 'Result' = $result }
                }
            
                SetScript  = {
                    $nat = "AzSHCINAT"
                    New-NetNat -Name $nat -InternalIPInterfaceAddressPrefix "192.168.0.0/24"          
                }
            
                TestScript = {
                    # Create and invoke a scriptblock using the $GetScript automatic variable, which contains a string representation of the GetScript.
                    $state = [scriptblock]::Create($GetScript).Invoke()
                    return $state.Result
                }
                DependsOn  = "[IPAddress]New IP for vEthernet $SwitchName"
            }
            #>

            #Domain Controller Virtual Machine
            #OS VHD

            File "ContosoDC_Directory" {
                Type            = 'Directory'
                DestinationPath = "$targetVMPath\ContosoDC"
                }

                File "ContosoDCVHD_Directory" {
                    Type            = 'Directory'
                    DestinationPath = "$targetVMPath\ContosoDC\VHD"
                    }
<#
            xVHD ContosoDC {
        
                Ensure     = 'Present'
                Name       = "ContosoDC-OS.vhdx"
                Path       = "$targetVMPath\ContosoDC\VHD\"
                Generation = 'vhdx'
                ParentPath = "$env:SystemDrive\HCIVHDs\GUI.vhdx"
                Type = 'Differencing'
                MaximumSizeBytes = "40096"
            }

            xVhdFile "Copy_ContosoDC-MOF_to_ContosoDC"{
                VhdPath =  "$env:SystemDrive\VMs\ContosoDC\VHD\ContosoDC-OS.vhdx"
                FileDirectory =  @(
            
                    # Pending.mof
                    MSFT_xFileDirectory {
                        SourcePath = "$env:SystemDrive\Temp\ContosoDC\ContosoDC.mof"
                        DestinationPath = "\Windows\Sytem32\Configuration\Pending.mof" 
                    }
                )
            }
  #>                 

            # create the ContosoDC VM out of the vhd.
            xVMHyperV ContosoDC_VM{
                Name            = "ContosoDC"
                SwitchName      = $SwitchName
                VhdPath         = "$targetVMPath\ContosoDC\VHD\ContosoDC-OS.vhdx"
                ProcessorCount  = 2
                StartupMemory = 2GB
                MaximumMemory   = 4GB
                MinimumMemory   = 2GB
                Generation = 2
                Path = "$targetVMPath\ContosoDC"
                RestartIfNeeded = $true
                DependsOn       = '[xVMSwitch]Internalswitch'
                State           = 'Running'
            }

            xVMNetworkAdapter ContosoDC-VNic{
                Ensure = 'Present'
                Id = 'ContosoDC-VNic'
                Name = 'Ethernet'
                SwitchName = 'HCI-Uplink'
                MacAddress = '001523be0c00'
                VMName = 'ContosoDC'
                DependsOn = '[xVMHyperV]ContosoDC_VM'
                NetworkSetting = xNetworkSettings
                {
                    IpAddress = '192.168.1.154'
                    Subnet = '255.255.255.-'
                    DefaultGateway = '192.168.1.1'
                    DnsServer = '127.0.0.1'
                }
            }
            
            DnsServerAddress DnsServerAddress{
            Address        = '192.168.1.254'
            InterfaceAlias = "vEthernet (HCI-Uplink)" 
            AddressFamily  = 'IPv4'
            Validate       = $true
        }

            WaitForADDomain 'contoso.com'{
            DomainName = 'contoso.com'
            }
           
            #Configure SAHCI Node (Continued after domain controller deployment)
            Computer JoinDomain
                    {
                        Name       = 'SAHCI'
                        DomainName = 'Contoso'
                        Credential = $domaincreds
                        DependsOn = '[WaitForADDomain]Contoso.com'
                    }
               
            xCluster CreateCluster{
                Name                          = 'SAHCICL'
            #    StaticIPAddress               = '192.168.100.20/24'
                DomainAdministratorCredential = $domaincreds
                DependsOn                     = '[Computer]JoinDomain'
                }
                
            xWaitForCluster WaitForCluster
                {
                    Name             = 'SAHCICL'
                    RetryIntervalSec = 10
                    RetryCount       = 60
                    DependsOn        = '[xCluster]CreateCluster'
                }

                


        }

}

$Configdata=@{
    allnodes=@(
        @{
            nodename="SingleNodeHCI"
            PSDSCAllowPlainTextPassword=$true
            PSDSCAllowDomainUser=$true
            
        }
    )
    }
    SingleNodeHCI -ConfigurationData $configdata 