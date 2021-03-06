    
    
Configuration SingleNodeHCI {
        param(
    [String]$targetDrive = "C",
    [String]$targetVMPath = "$targetDrive" + ":\VMs",
    [String]$server2019_uri="https://aka.ms/AAbclsv",
    [String]$wacUri = "https://aka.ms/wacdownload",
    [String]$SwitchName="InternalSwitch",
    [String]$ExtSwitchName="HCI-Uplink",
    [String]$vhdPath = 'C:\temp\disk.vhdx',
    [String]$relativeDestinationPath = '$env:SystemDrive\Windows\System32\Configuration\Pending.mof',
    [String]$dcmofuri="",
    [String]$netAdapters = (Get-Netadapter | Where-Object status -eq "Up"), 
    [PSCredential]$domaincreds
    )
       
        Import-DscResource -ModuleName 'PSDesiredStateConfiguration' 
        Import-DscResource -ModuleName 'xPSDesiredStateConfiguration'
        Import-DscResource -ModuleName 'xCredSSP'
        Import-DscResource -ModuleName 'DSCR_Shortcut'
        Import-DscResource -ModuleName 'xHyper-V'
        Import-DscResource -ModuleName 'NetworkingDSC'
        Import-DscResource -Module ComputerManagementDsc

        
        Node localhost{

                LocalConfigurationManager {
                RebootNodeIfNeeded = $true
                ActionAfterReboot  = 'ContinueConfiguration'
                ConfigurationMode = 'ApplyAndMonitor'
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
            
                xRemoteFile "Server2019VHD"{
                    uri=$server2019_uri
                    DestinationPath="$env:SystemDrive\HCIVHDs\GUI.vhdx"
                    DependsOn="[File]HCIVHDs"
                }

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
                    NetAdapterName        = "$Netadapters"
                    EnableEmbeddedTeaming = $true
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

                NetIPInterface "Enable IP forwarding on vEthernet $SwitchName"
                {   
                    AddressFamily  = 'IPv4'
                    InterfaceAlias = "vEthernet `($vSwitchNameHost`)"
                    Forwarding     = 'Enabled'
                    DependsOn      = "[IPAddress]New IP for vEthernet $SwitchName"
                }

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
                    VhdPath =  "$targetVMPath\ContosoDC\VHD\ContosoDC-OS.vhdx"
                    FileDirectory =  @(
                
                        # Pending.mof
                        MSFT_xFileDirectory {
                            SourcePath = "$env:SystemDrive\Temp\ContosoDC\ContosoDC.mof"
                            DestinationPath = "\Windows\Sytem32\Configuration\Pending.mof" 
                        }
                    )
                }
                       
    
                # create the testVM out of the vhd.
                
                xVMHyperV ContosoDC_VM
                {
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
                    DependsOn       = '[xVHD]ContosoDC', '[xVMSwitch]Internalswitch', '[xVhdFile]Copy_ContosoDC-MOF_to_ContosoDC'
                    State           = 'Off'
                }

                #Configure SAHCI Node (Continued after domain controller deployment)
                Computer RenameServer{
                    Name="SAHCI"
                    DomainName="Contoso"
                    Credential=$domaincreds
                    DependsOn='[xVMHyperV]ContosoDC_VM'
                 }



            }

}
