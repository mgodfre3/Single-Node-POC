




<#
.SYNOPSIS
This PS1 will deploy a standalone Domain Controller and Forest on a Single-Hyper-V Host, along side an Internal VSwitch. You will need to supply a config file, which is located in this repo. 

.DESCRIPTION
Use this to deploy a single Domain Controller for a quick Single Node HCI cluster deployment. 

.PARAMETER Definations 
ConfigurationFile is the psd1 file that contains the Variables needed
Delete will remove this installaiton.


.EXAMPLE
sadc_deploy.ps1 -ConfigurationFile "".\sadc_config.psd1"

.NOTES
Use at own Risk, Please file an Issue in GitHub for any problems. 
#>

[CmdletBinding(DefaultParameterSetName = "NoParameters")]

param(
    [Parameter(Mandatory = $true, ParameterSetName = "ConfigurationFile")]
    [String] $ConfigurationDataFile = '.\sadc_config.psd1',
    [Parameter(Mandatory = $false, ParameterSetName = "Delete")]
    [Bool] $Delete = $false
) 


#########################################################################################Parameters#########################################################################################

$SDNConfig = Import-PowerShellDataFile -Path $ConfigurationDataFile

$localCred = new-object -typename System.Management.Automation.PSCredential -argumentlist "Administrator" `
                , (ConvertTo-SecureString $SDNConfig.SDNAdminPassword   -AsPlainText -Force)  

$domainCred = new-object -typename System.Management.Automation.PSCredential `
                -argumentlist (($SDNConfig.SDNDomainFQDN.Split(".")[0]) + "\Administrator"), `
            (ConvertTo-SecureString $SDNConfig.SDNAdminPassword  -AsPlainText -Force)               


############################################################################################### Functions ###########################################################################################
function Get-HyperVHosts {

    param (

        [String[]]$MultipleHyperVHosts,
        [string]$HostVMPath
    )
    
    foreach ($HypervHost in $MultipleHyperVHosts) {

        # Check Network Connectivity
        Write-Verbose "Checking Network Connectivity for Host $HypervHost"
        $testconnection = Test-Connection -ComputerName $HypervHost -Quiet -Count 1
        if (!$testconnection) { Write-Error "Failed to ping $HypervHost"; break }
    
        # Check Hyper-V Host 
        $HypHost = Get-VMHost -ComputerName $HypervHost -ErrorAction Ignore
        if ($HypHost) { Write-Verbose "$HypervHost Hyper-V Connectivity verified" }
        if (!$HypHost) { Write-Error "Cannot connect to hypervisor on system $HypervHost"; break }
    
        # Check HostVMPath
        $DriveLetter = $HostVMPath.Split(':')
        $testpath = Test-Path (("\\$HypervHost\") + ($DriveLetter[0] + "$") + ($DriveLetter[1])) -ErrorAction Ignore
        if ($testpath) { Write-Verbose "$HypervHost's $HostVMPath path verified" }
        if (!$testpath) { Write-Error "Cannot connect to $HostVMPath on system $HypervHost"; break }

    }
    
} 
    
function Set-HyperVSettings {
    
    param (

        $MultipleHyperVHosts,
        $HostVMPath
    )
    
    foreach ($HypervHost in $MultipleHyperVHosts) {

        Write-Verbose "Configuring Hyper-V Settings on $HypervHost"

        $params = @{
        
            ComputerName              = $HypervHost
            VirtualHardDiskPath       = $HostVMPath
            VirtualMachinePath        = $HostVMPath
            EnableEnhancedSessionMode = $true

        }

        Set-VMhost @params
    
    }
    
}
function get-sysprepedvhd {
    $GUIURI="https://aka.ms/AAbclsv"
       $tp=Test-Path $guiVHDXPath
       if ($tp -eq "false"){
       New-Item -Path C:\ -Name VMS -ItemType Directory
       New-Item -Path C:\vms -Name Base -ItemType Directory 
       Invoke-WebRequest $GUIURI -outfile $guiVHDXPath
       }
       else {
       Write-Host "VHD is downloaded to Staging loction"
       }
   } 
       
function Set-LocalHyperVSettings {

    Param (

        [string]$HostVMPath
    )
    
    Write-Verbose "Configuring Hyper-V Settings on localhost"

    $params = @{

        VirtualHardDiskPath       = $HostVMPath
        VirtualMachinePath        = $HostVMPath
        EnableEnhancedSessionMode = $true

    }

    Set-VMhost @params  
}
    
function New-ExternalSwitch {
    
    Param (

        $pswitchname, 
        $SDNConfig
    )
    
    $querySwitch = Get-VMSwitch -Name $pswitchname -ErrorAction Ignore
    
    if (!$querySwitch) {
            $activenetadapter=Get-Netadapter | where-object status -eq "up"
            #Add-NetIntent -Name "External" -Management -Compute -AdapterName $activenetadapter

            New-VMSwitch -Name $pswitchname -AllowManagementOS $true -EnableEmbeddedTeaming $true -NetAdapterName $activenetadapter.Name | Out-Null
           
            
            #Assign IP to External Switch
            $ExternalAdapter = Get-Netadapter -Name "vEthernet ($pswitchname)"
            $IP = $SDNConfig.PhysicalHostInternalIP
            $Prefix = ($SDNConfig.AzSMGMTIP.Split("/"))[1]
            $Gateway = $SDNConfig.SDNLABRoute
            $DNS = $SDNConfig.SDNLABDNS
            
            $params = @{
    
                AddressFamily  = "IPv4"
                IPAddress      = $IP
                PrefixLength   = $Prefix
                DefaultGateway = $Gateway
                
            }
        
            $ExternalAdapter | New-NetIPAddress @params | Out-Null
            $ExternalAdapter | Set-DnsClientServerAddress -ServerAddresses $DNS | Out-Null
        
        
       
    }
    
    Else { Write-Verbose "External Switch $pswitchname already exists. Not creating a new external switch." }
    
}


function New-HostvNIC {
    
    param (

        $SDNConfig,
        $localCred
    )

    $ErrorActionPreference = "Stop"

    $SBXIP = 250

    foreach ($SDNSwitchHost in $SDNConfig.MultipleHyperVHostNames) {

        Write-Verbose "Creating vNIC on $SDNSwitchHost"

        Invoke-Command -ComputerName $SDNSwitchHost -ArgumentList $SDNConfig, $SBXIP -ScriptBlock {

            $SDNConfig = $args[0]
            $SBXIP = $args[1]

            $vnicName = $SDNConfig.MultipleHyperVHostExternalSwitchName + "-SBXAccess"
    

            $params = @{

                SwitchName = $SDNConfig.MultipleHyperVHostExternalSwitchName
                Name       = $vnicName

            }
    
            Add-VMNetworkAdapter -ManagementOS @params | Out-Null
            

            Set-VMNetworkAdapterVlan -ManagementOS -Trunk -NativeVlanId 0 -AllowedVlanIdList 1-200
  
            $IP = ($SDNConfig.MGMTSubnet.TrimEnd("0/24")) + $SBXIP
            $prefix = $SDNConfig.MGMTSubnet.Split("/")[1]
            $gateway = $SDNConfig.BGPRouterIP_MGMT.TrimEnd("/24")
            $DNS = $SDNConfig.SDNLABDNS

            $NetAdapter = Get-NetAdapter | Where-Object { $_.Name -match $vnicName }[0]

            $params = @{

                AddressFamily  = "IPv4"
                IPAddress      = $IP
                PrefixLength   = $Prefix
                DefaultGateway = $Gateway
            
            }

            $NetAdapter | New-NetIPAddress @params | Out-Null
            $NetAdapter | Set-DnsClientServerAddress -ServerAddresses $DNS | Out-Null

        }

        $SBXIP--
    
    }
    
}
    
function Test-VHDPath {

    Param (

        $guiVHDXPath,
        $azSHCIVHDXPath
    )
    $GUIURI="https://aka.ms/AAbclsv"
    $Result = Get-ChildItem -Path $guiVHDXPath -ErrorAction Ignore  
    if (!$result) { Write-Host "Path $guiVHDXPath was not found!" -ForegroundColor Red ; 
    Invoke-WebRequest $GUIURI -outfile $guiVHDXPath
}
    $Result = Get-ChildItem -Path $azSHCIVHDXPath -ErrorAction Ignore  
    if (!$result) { Write-Host "Path $azSHCIVHDXPath was not found!" -ForegroundColor Red ; break }

} 
function Select-VMHostPlacement {
    
    Param($MultipleHyperVHosts, $AzSHOSTs)    
    
    $results = @()
    
    Write-Host "Note: if using a NAT switch for internet access, please choose the host that has the external NAT Switch for VM: AzSMGMT." `
        -ForegroundColor Yellow
    
    foreach ($AzSHOST in $AzSHOSTs) {
    
        Write-Host "`nOn which server should I put $AzSHOST ?" -ForegroundColor Green
    
        $i = 0
        foreach ($HypervHost in $MultipleHyperVHosts) {
    
            Write-Host "`n $i. Hyper-V Host: $HypervHost" -ForegroundColor Yellow
            $i++
        }
    
        $MenuOption = Read-Host "`nSelect the Hyper-V Host and then press Enter" 
    
        $results = $results + [pscustomobject]@{AzSHOST = $AzSHOST; VMHost = $MultipleHyperVHosts[$MenuOption] }
    
    }
    
    return $results
     
}
    
function Select-SingleHost {

    Param (

        $AzSHOSTs

    )

    $results = @()
    foreach ($AzSHOST in $AzSHOSTs) {

        $results = $results + [pscustomobject]@{AzSHOST = $AzSHOST; VMHost = $env:COMPUTERNAME }
    }

    Return $results

}

function New-DCVM {

    Param (

        $SDNConfig,
        $localCred,
        $domainCred

    )

    

        $SDNConfig = $SDNConfig
        $localcred = $localcred
        $domainCred = $domainCred
        $ParentDiskPath = "C:\VMs\Base\"
        $vmpath = "C:\VMs\"
        $OSVHDX = "GUI.vhdx"
        $coreOSVHDX = "AzSHCI.vhdx"
        $VMStoragePathforOtherHosts = $SDNConfig.HostVMPath
        $SourcePath = 'C:\VMConfigs'
        $VMName = $SDNConfig.DCName

        $ProgressPreference = "SilentlyContinue"
        $ErrorActionPreference = "Stop"
        $VerbosePreference = "Continue"
        $WarningPreference = "SilentlyContinue"

        # Create Virtual Machine

        Write-Verbose "Creating $VMName differencing disks"
        
        $params = @{

            ParentPath = ($ParentDiskPath + $OSVHDX)
            Path       = ($vmpath + $VMName + '\' + $VMName + '.vhdx')

        }

        New-VHD  @params -Differencing | Out-Null

        Write-Verbose "Creating $VMName virtual machine"
        
        $params = @{

            Name       = $VMName
            VHDPath    = ($vmpath + $VMName + '\' + $VMName + '.vhdx')
            Path       = ($vmpath + $VMName)
            Generation = 2

        }

        New-VM @params | Out-Null

        Write-Verbose "Setting $VMName Memory"

        $params = @{

            VMName               = $VMName
            DynamicMemoryEnabled = $true
            StartupBytes         = $SDNConfig.MEM_DC
            MaximumBytes         = $SDNConfig.MEM_DC
            MinimumBytes         = 500MB

        }


        Set-VMMemory @params | Out-Null

        Write-Verbose "Configuring $VMName's networking"

        Remove-VMNetworkAdapter -VMName $VMName -Name "Network Adapter" | Out-Null

        $params = @{

            VMName       = $VMName
            Name         = $SDNConfig.DCName
            SwitchName   = $ExternalSwitch
            DeviceNaming = 'On'

        }

        Add-VMNetworkAdapter @params | Out-Null
        Write-Verbose "Configuring $VMName's settings"
        Set-VMProcessor -VMName $VMName -Count 2 | Out-Null
        Set-VM -Name $VMName -AutomaticStartAction Start -AutomaticStopAction ShutDown | Out-Null

        # Inject Answer File

        Write-Verbose "Mounting and injecting answer file into the $VMName VM."        
        $VerbosePreference = "SilentlyContinue"

        New-Item -Path "C:\TempMount" -ItemType Directory | Out-Null
        Mount-WindowsImage -Path "C:\TempMount" -Index 1 -ImagePath ($vmpath + $VMName + '\' + $VMName + '.vhdx') | Out-Null

        $VerbosePreference = "Continue"
        Write-Verbose "Applying Unattend file to Disk Image..."

        $password = $SDNConfig.SDNAdminPassword
        $Unattend = @"
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
    <servicing>
        <package action="configure">
            <assemblyIdentity name="Microsoft-Windows-Foundation-Package" version="10.0.14393.0" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="" />
            <selection name="ADCertificateServicesRole" state="true" />
            <selection name="CertificateServices" state="true" />
        </package>
    </servicing>
    <settings pass="specialize">
        <component name="Networking-MPSSVC-Svc" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <DomainProfile_EnableFirewall>false</DomainProfile_EnableFirewall>
            <PrivateProfile_EnableFirewall>false</PrivateProfile_EnableFirewall>
            <PublicProfile_EnableFirewall>false</PublicProfile_EnableFirewall>
        </component>
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <ComputerName>$VMName</ComputerName>
        </component>
        <component name="Microsoft-Windows-TerminalServices-LocalSessionManager" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <fDenyTSConnections>false</fDenyTSConnections>
        </component>
        <component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <UserLocale>en-us</UserLocale>
            <UILanguage>en-us</UILanguage>
            <SystemLocale>en-us</SystemLocale>
            <InputLocale>en-us</InputLocale>
        </component>
    </settings>
    <settings pass="oobeSystem">
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <OOBE>
                <HideEULAPage>true</HideEULAPage>
                <SkipMachineOOBE>true</SkipMachineOOBE>
                <SkipUserOOBE>true</SkipUserOOBE>
                <HideOEMRegistrationScreen>true</HideOEMRegistrationScreen>
            </OOBE>
            <UserAccounts>
                <AdministratorPassword>
                    <Value>$password</Value>
                    <PlainText>true</PlainText>
                </AdministratorPassword>
            </UserAccounts>
        </component>
    </settings>
    <cpi:offlineImage cpi:source="" xmlns:cpi="urn:schemas-microsoft-com:cpi" />
</unattend>
"@

        New-Item -Path C:\TempMount\windows -ItemType Directory -Name Panther -Force | Out-Null
        Set-Content -Value $Unattend -Path "C:\TempMount\Windows\Panther\Unattend.xml"  -Force

        Write-Verbose "Dismounting Windows Image"
        Dismount-WindowsImage -Path "C:\TempMount" -Save | Out-Null
        Remove-Item "C:\TempMount" | Out-Null

        # Start Virtual Machine

        Write-Verbose "Starting Virtual Machine" 
        Start-VM -Name $VMName | Out-Null

        # Wait until the VM is restarted

        while ((Invoke-Command -VMName $VMName -Credential $domainCred { "Test" } `
                    -ea SilentlyContinue) -ne "Test") { Start-Sleep -Seconds 1 }

        Write-Verbose "Configuring Domain Controller VM and Installing Active Directory."

        Invoke-Command -VMName $VMName -Credential $localCred -ArgumentList $SDNConfig -ScriptBlock {

            $SDNConfig = $args[0]

            $VerbosePreference = "Continue"
            $WarningPreference = "SilentlyContinue"
            $ErrorActionPreference = "Stop"
            $DCName = $SDNConfig.DCName
            $IP = $SDNConfig.SDNLABDNS
            $PrefixLength = ($SDNConfig.AzSMGMTIP.split("/"))[1]
            $SDNLabRoute = $SDNConfig.SDNLABRoute
            $DomainFQDN = $SDNConfig.SDNDomainFQDN
            $DomainNetBiosName = $DomainFQDN.Split(".")[0]

            Write-Verbose "Configuring NIC Settings for Domain Controller"
            $VerbosePreference = "SilentlyContinue"
            $NIC = Get-NetAdapterAdvancedProperty -RegistryKeyWord "HyperVNetworkAdapterName" | Where-Object { $_.RegistryValue -eq $DCName }
            Rename-NetAdapter -name $NIC.name -newname $DCName | Out-Null 
            New-NetIPAddress -InterfaceAlias $DCName -IPAddress $ip -PrefixLength $PrefixLength -DefaultGateway $SDNLabRoute | Out-Null
            Set-DnsClientServerAddress -InterfaceAlias $DCName -ServerAddresses $IP | Out-Null
            Install-WindowsFeature -name AD-Domain-Services –IncludeManagementTools | Out-Null
            $VerbosePreference = "Continue"

            Write-Verbose "Configuring Trusted Hosts"
            Set-Item WSMan:\localhost\Client\TrustedHosts * -Confirm:$false -Force

            Write-Verbose "Installing Active Directory Forest. This will take some time..."
        
            $SecureString = ConvertTo-SecureString $SDNConfig.SDNAdminPassword -AsPlainText -Force
            Write-Verbose "Installing Active Directory..." 

            $params = @{

                DomainName                    = $DomainFQDN
                DomainMode                    = 'WinThreshold'
                DatabasePath                  = "C:\Domain"
                DomainNetBiosName             = $DomainNetBiosName
                SafeModeAdministratorPassword = $SecureString

            }


            Write-Output $params

            
            $VerbosePreference = "SilentlyContinue"

            Install-ADDSForest  @params -InstallDns -Confirm -Force -NoRebootOnCompletion | Out-Null

        }

        Write-Verbose "Stopping $VMName"
        Get-VM $VMName | Stop-VM
        Write-Verbose "Starting $VMName"
        Get-VM $VMName | Start-VM 

        # Wait until DC is created and rebooted

        while ((Invoke-Command -VMName $VMName -Credential $domainCred `
                    -ArgumentList $SDNConfig.DCName { (Get-ADDomainController $args[0]).enabled } -ea SilentlyContinue) -ne $true) { Start-Sleep -Seconds 1 }

        $VerbosePreference = "Continue"
        Write-Verbose "Configuring User Accounts and Groups in Active Directory"

        Invoke-Command -VMName $VMName -Credential $domainCred -ArgumentList $SDNConfig -ScriptBlock {

            $SDNConfig = $args[0]
            $SDNDomainFQDN = $SDNConfig.SDNDomainFQDN

            $VerbosePreference = "Continue"
            $ErrorActionPreference = "Stop"
    
           


            $params = @{

                ComplexityEnabled = $false
                Identity          = $SDNConfig.SDNDomainFQDN
                MinPasswordLength = 0

            }


            Set-ADDefaultDomainPasswordPolicy @params

            

            # Set Administrator Account Not to Expire

            Get-ADUser Administrator | Set-ADUser -PasswordNeverExpires $true  -CannotChangePassword $true

            # Set DNS Forwarder

            Write-Verbose "Adding DNS Forwarders"
            $VerbosePreference = "SilentlyContinue"

            if ($SDNConfig.natDNS) { Add-DnsServerForwarder $SDNConfig.natDNS }
            else { Add-DnsServerForwarder 8.8.8.8 }

            # Create Enterprise CA 

            $VerbosePreference = "Continue"
            Write-Verbose "Installing and Configuring Active Directory Certificate Services and Certificate Templates"
            $VerbosePreference = "SilentlyContinue"

            

            Install-WindowsFeature -Name AD-Certificate -IncludeAllSubFeature -IncludeManagementTools | Out-Null

            $params = @{

                CAtype              = 'EnterpriseRootCa'
                CryptoProviderName  = 'ECDSA_P256#Microsoft Software Key Storage Provider'
                KeyLength           = 256
                HashAlgorithmName   = 'SHA256'
                ValidityPeriod      = 'Years'
                ValidityPeriodUnits = 10
            }

            Install-AdcsCertificationAuthority @params -Confirm:$false | Out-Null

            # Give WebServer Template Enroll rights for Domain Computers

            $filter = "(CN=WebServer)"
            $ConfigContext = ([ADSI]"LDAP://RootDSE").configurationNamingContext
            $ConfigContext = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigContext"
            $ds = New-object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$ConfigContext", $filter)  
            $Template = $ds.Findone().GetDirectoryEntry() 

            if ($Template -ne $null) {
                $objUser = New-Object System.Security.Principal.NTAccount("Domain Computers") 
                $objectGuid = New-Object Guid 0e10c968-78fb-11d2-90d4-00c04f79dc55                     
                $ADRight = [System.DirectoryServices.ActiveDirectoryRights]"ExtendedRight"                     
                $ACEType = [System.Security.AccessControl.AccessControlType]"Allow"                     
                $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $objUser, $ADRight, $ACEType, $objectGuid                     
                $Template.ObjectSecurity.AddAccessRule($ACE)                     
                $Template.commitchanges()
            } 
 
            CMD.exe /c "certutil -setreg ca\ValidityPeriodUnits 8" | Out-Null
            Restart-Service CertSvc
            Start-Sleep -Seconds 60
 
            #Issue Certificate Template

            CMD.exe /c "certutil -SetCATemplates +WebServer"
 
        }
 
    }

function set-hostnat {

        param (
    
            $SDNConfig
        )
    
        $VerbosePreference = "Continue" 
    
        $switchExist = Get-NetAdapter | Where-Object { $_.Name -match $SDNConfig.natHostVMSwitchName }
    
        if (!$switchExist) {
    
            Write-Verbose "Creating Internal NAT Switch: $($SDNConfig.natHostVMSwitchName)"
            # Create Internal VM Switch for NAT
            New-VMSwitch -Name $SDNConfig.natHostVMSwitchName -SwitchType Internal | Out-Null
    
            Write-Verbose "Applying IP Address to NAT Switch: $($SDNConfig.natHostVMSwitchName)"
            # Apply IP Address to new Internal VM Switch
            $intIdx = (Get-NetAdapter | Where-Object { $_.Name -match $SDNConfig.natHostVMSwitchName }).ifIndex
            $natIP = $SDNConfig.natHostSubnet.Replace("0/24", "1")
    
            New-NetIPAddress -IPAddress $natIP -PrefixLength 24 -InterfaceIndex $intIdx | Out-Null
    
            # Create NetNAT
    
            Write-Verbose "Creating new NETNAT"
            New-NetNat -Name $SDNConfig.natHostVMSwitchName  -InternalIPInterfaceAddressPrefix $SDNConfig.natHostSubnet | Out-Null
    
        }
    
    }
    function configure-hcivm {
        $biosversion=(get-computerinfo).biosmanufacturer 
        
        if ($biosversion -eq "Microsoft Corporation"){
            Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All -NoRestart -Verbose
            Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-Management-PowerShell -All -NoRestart -Verbose
            }
        
        elseif ($osversion -ne "Microsoft Corporation"){
            Install-WindowsFeature -Name "BitLocker", "Data-Center-Bridging", "Failover-Clustering", "FS-FileServer", "FS-Data-Deduplication", "Hyper-V", "Hyper-V-PowerShell", "RSAT-AD-Powershell", "RSAT-Clustering-Powershell","FS-Data-Deduplication", "Storage-Replica", "NetworkATC", "System-Insights" -IncludeAllSubFeature -IncludeManagementTools
            }
        
        else {
            Write-Host "Please confirm you have enabled Processor Virtualization Settings in BIOS."
            }
        }

    function Delete-AzSHCISandbox {

        param (
    
            $VMPlacement,
            $SDNConfig,
            $SingleHostDelete
    
        )
    
        $VerbosePreference = "Continue"
    
        Write-Verbose "Deleting Azure Stack HCI Sandbox"
    
        foreach ($vm in $VMPlacement) {
    
            $AzSHOSTName = $vm.vmHost
            $VMName = $vm.AzSHOST
    
            Invoke-Command -ComputerName $AzSHOSTName -ArgumentList $VMName -ScriptBlock {
    
                $VerbosePreference = "SilentlyContinue"
    
                Import-Module Hyper-V
    
                $VerbosePreference = "Continue"
                $vmname = $args[0]
    
                # Delete SBXAccess vNIC (if present)
                $vNIC = Get-VMNetworkAdapter -ManagementOS | Where-Object { $_.Name -match "SBXAccess" }
                if ($vNIC) { $vNIC | Remove-VMNetworkAdapter -Confirm:$false }
    
                $sdnvm = Get-VM | Where-Object { $_.Name -eq $vmname }
    
                If (!$sdnvm) { Write-Verbose "Could not find $vmname to delete" }
    
                if ($sdnvm) {
    
                    Write-Verbose "Shutting down VM: $sdnvm)"
    
                    Stop-VM -VM $sdnvm -TurnOff -Force -Confirm:$false 
                    $VHDs = $sdnvm | Select-Object VMId | Get-VHD
                    Remove-VM -VM $sdnvm -Force -Confirm:$false 
    
                    foreach ($VHD in $VHDs) {
    
                        Write-Verbose "Removing $($VHD.Path)"
                        Remove-Item -Path $VHD.Path -Force -Confirm:$false
    
                    }
    
                }
    
    
            }
    
        }
    
        If ($SingleHostDelete -eq $true) {
            
            $RemoveSwitch = Get-VMSwitch | Where-Object { $_.Name -match $SDNConfig.ExternalSwitch }
    
            If ($RemoveSwitch) {
    
                Write-Verbose "Removing Internal Switch: $($SDNConfig.ExternalSwitch)"
                $RemoveSwitch | Remove-VMSwitch -Force -Confirm:$false
    
            }
    
        }
    
        Write-Verbose "Deleting RDP links"
    
        Remove-Item C:\Users\Public\Desktop\AdminCenter.lnk -Force -ErrorAction SilentlyContinue
    
    
        Write-Verbose "Deleting NetNAT"
        Get-NetNAT | Remove-NetNat -Confirm:$false
    
        Write-Verbose "Deleting Internal Switches"
        Get-VMSwitch | Where-Object { $_.SwitchType -eq "Internal" } | Remove-VMSwitch -Force -Confirm:$false
    
    
    }    
##########################################################################################Create Resources ###########################################################################

#region Main
    
$WarningPreference = "SilentlyContinue"
$ErrorActionPreference = "Stop" 

#Get Start Time
$starttime = Get-Date
   

# Set VM Host Memory
$totalPhysicalMemory = (Get-CimInstance -ClassName 'Cim_PhysicalMemory' | Measure-Object -Property Capacity -Sum).Sum / 1GB
$availablePhysicalMemory = (([math]::Round(((((Get-Counter -Counter '\Hyper-V Dynamic Memory Balancer(System Balancer)\Available Memory For Balancing' -ComputerName $env:COMPUTERNAME).CounterSamples.CookedValue) / 1024) - 18) / 2))) * 1073741824
$SDNConfig.NestedVMMemoryinGB = $availablePhysicalMemory


# Delete configuration if specified

if ($Delete) {

    if ($SDNConfig.MultipleHyperVHosts) {

        $params = @{

            MultipleHyperVHosts = $SDNConfig.MultipleHyperVHostNames
            AzSHOSTs            = $AzSHOSTs    

        }       

        $VMPlacement = Select-VMHostPlacement @params
        $SingleHostDelete = $false
    }     
    elseif (!$SDNConfig.MultipleHyperVHosts) { 
    
        Write-Verbose "This is a single host installation"
        $VMPlacement = Select-SingleHost -AzSHOSTs $AzSHOSTs
        $SingleHostDelete = $true

    }

    Delete-AzSHCISandbox -SDNConfig $SDNConfig -VMPlacement $VMPlacement -SingleHostDelete $SingleHostDelete

    Write-Verbose "Successfully Removed the Azure Stack HCI Sandbox"
    exit

}

#Copy and Download Files for DC Image
get-sysprepedvhd



# Set Variables from config file

$NestedVMMemoryinGB = $SDNConfig.NestedVMMemoryinGB
$guiVHDXPath = $SDNConfig.guiVHDXPath
$azSHCIVHDXPath = $SDNConfig.azSHCIVHDXPath
$HostVMPath = $SDNConfig.HostVMPath
$ExternalSwitch = $SDNConfig.ExternalSwitch
$natDNS = $SDNConfig.natDNS
$natSubnet = $SDNConfig.natSubnet
$natConfigure = $SDNConfig.natConfigure   

configure-hcivm
$VerbosePreference = "SilentlyContinue" 
Import-Module Hyper-V 
$VerbosePreference = "Continue"
$ErrorActionPreference = "Stop"
    
#Configure Hyper-V Host
Write-Verbose "Creating External Switch"

    $params = @{

        pswitchname = $SDNConfig.ExternalSwitch
        SDNConfig   = $SDNConfig
    
    }

    New-ExternalSwitch @params

    Write-Verbose "Creating NAT Switch"

    set-hostnat -SDNConfig $SDNConfig

    $VMSwitch = $sdnconfig.ExternalSwitch



# Provision Domain Controller 
 Write-Verbose "Provisioning Domain Controller VM"
 New-DCVM -SDNConfig $SDNConfig -localCred $localCred -domainCred $domainCred | Out-Null


