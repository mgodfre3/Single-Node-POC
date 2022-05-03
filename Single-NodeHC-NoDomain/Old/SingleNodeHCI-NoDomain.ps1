    
    
Configuration SingleNodeHCI-NoDomain {
    param(
[String]$targetDrive = "C",
[String]$targetVMPath = "$targetDrive" + ":\VMs",
[String]$ExtSwitchName="HCI-Uplink",
[String]$relativeDestinationPath = '$env:SystemDrive\Windows\System32\Configuration\Pending.mof',
[String]$netAdapters = (get-netadapter | Where-Object {$_.name -NotLike "vEthernet*" -and $_.status -eq "Up"}), 
[String]$ClusterIPAddress="10.50.10.202",
[String]$DNSIPAddress="10.50.10.1"
#[PSCredential]$domaincreds
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
            
            WindowsFeature Failover-Cluster {
                Ensure = 'Present'
                Name = "Failover-Clustering"
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
        

            File "temp" {
                Type            = 'Directory'
                DestinationPath = "$env:SystemDrive\Temp"
                
            }

           
            #Virtual Switch Configurations
           
            xVMSwitch ExternalSwitch
            {
                Ensure                = 'Present'
                Name                  = $ExtSwitchName
                Type                  = 'External'
                NetAdapterName        =  $netAdapters.name
                EnableEmbeddedTeaming =  $true
                AllowManagementOS =  $true
                BandwidthReservationMode = "weight"
                LoadBalancingAlgorithm = 'Dynamic' 
                DependsOn      = '[WindowsFeature]Hyper-V'
            }

                   
            DnsServerAddress DnsServerAddress{
            Address        = '$DNSIP'
            InterfaceAlias = "vEthernet (HCI-Uplink)" 
            AddressFamily  = 'IPv4'
            Validate       = $true
        }
        
            
           
               
            xCluster CreateCluster{
                Name                          = 'SAHCICL'
                StaticIPAddress               = $ClusterIPAddress
                #DomainAdministratorCredential = $domaincreds
                DependsOn                     = '[WindowsFeature]Failover-Cluster'
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
    SingleNodeHCI-NoDomain -ConfigurationData $configdata 