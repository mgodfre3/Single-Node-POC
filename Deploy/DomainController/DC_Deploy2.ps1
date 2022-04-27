#Parameters

[CmdletBinding(DefaultParameterSetName = "NoParameters")]

param(
    [Parameter(Mandatory = $true, ParameterSetName = "ConfigurationFile")]
    [String] $ConfigurationDataFile = '.\AzSHCISandbox-Config.psd1',
    [Parameter(Mandatory = $false, ParameterSetName = "Delete")]
    [Bool] $Delete = $false
)




#Functions

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
    
function New-InternalSwitch {
    
    Param (

        $pswitchname, 
        $SDNConfig
    )
    
    $querySwitch = Get-VMSwitch -Name $pswitchname -ErrorAction Ignore
    
    if (!$querySwitch) {
    
        New-VMSwitch -SwitchType Internal -MinimumBandwidthMode None -Name $pswitchname | Out-Null
    
        #Assign IP to Internal Switch
        $InternalAdapter = Get-Netadapter -Name "vEthernet ($pswitchname)"
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
    
        $InternalAdapter | New-NetIPAddress @params | Out-Null
        $InternalAdapter | Set-DnsClientServerAddress -ServerAddresses $DNS | Out-Null
    
    }
    
    Else { Write-Verbose "Internal Switch $pswitchname already exists. Not creating a new internal switch." }
    
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

    $Result = Get-ChildItem -Path $guiVHDXPath -ErrorAction Ignore  
    if (!$result) { Write-Host "Path $guiVHDXPath was not found!" -ForegroundColor Red ; break }
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

function New-NATSwitch {
    
    Param (

        $VMPlacement,
        $SwitchName,
        $SDNConfig

    )
    
    $natSwitchTarget = $VMPlacement | Where-Object { $_.AzSHOST -eq "AzSMGMT" }
    
    Add-VMNetworkAdapter -VMName $natSwitchTarget.AzSHOST -ComputerName $natSwitchTarget.VMHost -DeviceNaming On 

    $params = @{

        VMName       = $natSwitchTarget.AzSHOST
        ComputerName = $natSwitchTarget.VMHost
    }

    Get-VMNetworkAdapter @params | Where-Object { $_.Name -match "Network" } | Connect-VMNetworkAdapter -SwitchName $SDNConfig.natHostVMSwitchName
    Get-VMNetworkAdapter @params | Where-Object { $_.Name -match "Network" } | Rename-VMNetworkAdapter -NewName "NAT"
    
    Get-VM @params | Get-VMNetworkAdapter -Name NAT | Set-VMNetworkAdapter -MacAddressSpoofing On
    
    <# Should not need this anymore

    if ($SDNConfig.natVLANID) {
    
        Get-VM @params | Get-VMNetworkAdapter -Name NAT | Set-VMNetworkAdapterVlan -Access -VlanId $natVLANID | Out-Null
    
    }

    #>
    
    #Create PROVIDER NIC in order for NAT to work from SLB/MUX and RAS Gateways

    Add-VMNetworkAdapter @params -Name PROVIDER -DeviceNaming On -SwitchName $SwitchName
    Get-VM @params | Get-VMNetworkAdapter -Name PROVIDER | Set-VMNetworkAdapter -MacAddressSpoofing On
    Get-VM @params | Get-VMNetworkAdapter -Name PROVIDER | Set-VMNetworkAdapterVlan -Access -VlanId $SDNConfig.providerVLAN | Out-Null    
    
    #Create VLAN 200 NIC in order for NAT to work from L3 Connections

    Add-VMNetworkAdapter @params -Name VLAN200 -DeviceNaming On -SwitchName $SwitchName
    Get-VM @params | Get-VMNetworkAdapter -Name VLAN200 | Set-VMNetworkAdapter -MacAddressSpoofing On
    Get-VM @params | Get-VMNetworkAdapter -Name VLAN200 | Set-VMNetworkAdapterVlan -Access -VlanId $SDNConfig.vlan200VLAN | Out-Null    

    
    #Create Simulated Internet NIC in order for NAT to work from L3 Connections

    Add-VMNetworkAdapter @params -Name simInternet -DeviceNaming On -SwitchName $SwitchName
    Get-VM @params | Get-VMNetworkAdapter -Name simInternet | Set-VMNetworkAdapter -MacAddressSpoofing On
    Get-VM @params | Get-VMNetworkAdapter -Name simInternet | Set-VMNetworkAdapterVlan -Access -VlanId $SDNConfig.simInternetVLAN | Out-Null

    
} 

function New-DCVM {

    Param (

        $SDNConfig,
        $localCred,
        $domainCred

    )

    Invoke-Command -VMName AzSMGMT -Credential $domainCred -ScriptBlock {

        $SDNConfig = $using:SDNConfig
        $localcred = $using:localcred
        $domainCred = $using:domainCred
        $ParentDiskPath = "C:\VMs\Base\"
        $vmpath = "D:\VMs\"
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
            SwitchName   = 'vSwitch-Fabric'
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

        while ((Invoke-Command -VMName $VMName -Credential $using:domainCred { "Test" } `
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
            New-NetIPAddress -InterfaceAlias $DCName –IPAddress $ip -PrefixLength $PrefixLength -DefaultGateway $SDNLabRoute | Out-Null
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

        while ((Invoke-Command -VMName $VMName -Credential $using:domainCred `
                    -ArgumentList $SDNConfig.DCName { (Get-ADDomainController $args[0]).enabled } -ea SilentlyContinue) -ne $true) { Start-Sleep -Seconds 1 }

        $VerbosePreference = "Continue"
        Write-Verbose "Configuring User Accounts and Groups in Active Directory"

        Invoke-Command -VMName $VMName -Credential $using:domainCred -ArgumentList $SDNConfig -ScriptBlock {

            $SDNConfig = $args[0]
            $SDNDomainFQDN = $SDNConfig.SDNDomainFQDN

            $VerbosePreference = "Continue"
            $ErrorActionPreference = "Stop"
    
            $SecureString = ConvertTo-SecureString $SDNConfig.SDNAdminPassword -AsPlainText -Force


            $params = @{

                ComplexityEnabled = $false
                Identity          = $SDNConfig.SDNDomainFQDN
                MinPasswordLength = 0

            }


            Set-ADDefaultDomainPasswordPolicy @params

            $params = @{

                Name                  = 'NC Admin'
                GivenName             = 'NC'
                Surname               = 'Admin'
                SamAccountName        = 'NCAdmin'
                UserPrincipalName     = "NCAdmin@$SDNDomainFQDN"
                AccountPassword       = $SecureString
                Enabled               = $true
                ChangePasswordAtLogon = $false
                CannotChangePassword  = $true
                PasswordNeverExpires  = $true
            }

            New-ADUser @params

            $params.Name = 'NC Client'
            $params.Surname = 'Client'
            $params.SamAccountName = 'NCClient'
            $params.UserPrincipalName = "NCClient@$SDNDomainFQDN" 

            New-ADUser @params

            NEW-ADGroup –name “NCAdmins” –groupscope Global
            NEW-ADGroup –name “NCClients” –groupscope Global

            add-ADGroupMember "Domain Admins" "NCAdmin"
            add-ADGroupMember "NCAdmins" "NCAdmin"
            add-ADGroupMember "NCClients" "NCClient"
            add-ADGroupMember "NCClients" "Administrator"
            add-ADGroupMember "NCAdmins" "Administrator"

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

}

function New-RouterVM {

    Param (

        $SDNConfig,
        $localCred,
        $domainCred

    )

    Invoke-Command -VMName AzSMGMT -Credential $localCred -ScriptBlock {

        $SDNConfig = $using:SDNConfig
        $localcred = $using:localcred
        $domainCred = $using:domainCred
        $ParentDiskPath = "C:\VMs\Base\"
        $vmpath = "D:\VMs\"
        $OSVHDX = "AzSHCI.vhdx"
        $VMStoragePathforOtherHosts = $SDNConfig.HostVMPath
        $SourcePath = 'C:\VMConfigs'
    
        $ProgressPreference = "SilentlyContinue"
        $ErrorActionPreference = "Stop"
        $VerbosePreference = "Continue"
        $WarningPreference = "SilentlyContinue"    
    
        $VMName = "bgp-tor-router"
    
        # Create Host OS Disk

        Write-Verbose "Creating $VMName differencing disks"

        $params = @{

            ParentPath = ($ParentDiskPath + $OSVHDX)
            Path       = ($vmpath + $VMName + '\' + $VMName + '.vhdx') 

        }

        New-VHD @params -Differencing | Out-Null
    
        # Create VM

        $params = @{

            Name       = $VMName
            VHDPath    = ($vmpath + $VMName + '\' + $VMName + '.vhdx')
            Path       = ($vmpath + $VMName)
            Generation = 2

        }

        Write-Verbose "Creating the $VMName VM."
        New-VM @params | Out-Null
    
        # Set VM Configuration

        Write-Verbose "Setting $VMName's VM Configuration"

        $params = @{

            VMName               = $VMName
            DynamicMemoryEnabled = $true
            StartupBytes         = $SDNConfig.MEM_BGP
            MaximumBytes         = $SDNConfig.MEM_BGP
            MinimumBytes         = 500MB
        }
   
        Set-VMMemory @params | Out-Null
        Remove-VMNetworkAdapter -VMName $VMName -Name "Network Adapter" | Out-Null 
        Set-VMProcessor -VMName $VMName -Count 2 | Out-Null
        set-vm -Name $VMName -AutomaticStopAction TurnOff | Out-Null
    
        # Configure VM Networking

        Write-Verbose "Configuring $VMName's Networking"
        Add-VMNetworkAdapter -VMName $VMName -Name Mgmt -SwitchName vSwitch-Fabric -DeviceNaming On
        Add-VMNetworkAdapter -VMName $VMName -Name Provider -SwitchName vSwitch-Fabric -DeviceNaming On
        Add-VMNetworkAdapter -VMName $VMName -Name VLAN200 -SwitchName vSwitch-Fabric -DeviceNaming On
        Add-VMNetworkAdapter -VMName $VMName -Name SIMInternet -SwitchName vSwitch-Fabric -DeviceNaming On
        Set-VMNetworkAdapterVlan -VMName $VMName -VMNetworkAdapterName Provider -Access -VlanId $SDNConfig.providerVLAN
        Set-VMNetworkAdapterVlan -VMName $VMName -VMNetworkAdapterName VLAN200 -Access -VlanId $SDNConfig.vlan200VLAN
        Set-VMNetworkAdapterVlan -VMName $VMName -VMNetworkAdapterName SIMInternet -Access -VlanId $SDNConfig.simInternetVLAN
           
    
        # Add NAT Adapter

        if ($SDNConfig.natConfigure) {

            Add-VMNetworkAdapter -VMName $VMName -Name NAT -SwitchName NAT -DeviceNaming On
        }    
    
        # Configure VM
        Set-VMProcessor -VMName $VMName  -Count 2
        Set-VM -Name $VMName -AutomaticStartAction Start -AutomaticStopAction ShutDown | Out-Null      
    
        # Inject Answer File

        Write-Verbose "Mounting Disk Image and Injecting Answer File into the $VMName VM." 
        New-Item -Path "C:\TempBGPMount" -ItemType Directory | Out-Null
        Mount-WindowsImage -Path "C:\TempBGPMount" -Index 1 -ImagePath ($vmpath + $VMName + '\' + $VMName + '.vhdx') | Out-Null
    
        New-Item -Path C:\TempBGPMount\windows -ItemType Directory -Name Panther -Force | Out-Null
    
        $Password = $SDNConfig.SDNAdminPassword
        $ProductKey = $SDNConfig.GUIProductKey
    
        $Unattend = @"
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
        <servicing>
            <package action="configure">
                <assemblyIdentity name="Microsoft-Windows-Foundation-Package" version="10.0.14393.0" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="" />
                <selection name="RemoteAccessServer" state="true" />
                <selection name="RasRoutingProtocols" state="true" />
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
                        <Value>$Password</Value>
                        <PlainText>true</PlainText>
                    </AdministratorPassword>
                </UserAccounts>
            </component>
        </settings>
        <cpi:offlineImage cpi:source="" xmlns:cpi="urn:schemas-microsoft-com:cpi" />
    </unattend>    
"@
        Set-Content -Value $Unattend -Path "C:\TempBGPMount\Windows\Panther\Unattend.xml" -Force
    
        Write-Verbose "Enabling Remote Access"
        Enable-WindowsOptionalFeature -Path C:\TempBGPMount -FeatureName RasRoutingProtocols -All -LimitAccess | Out-Null
        Enable-WindowsOptionalFeature -Path C:\TempBGPMount -FeatureName RemoteAccessPowerShell -All -LimitAccess | Out-Null
        Write-Verbose "Dismounting Disk Image for $VMName VM." 
        Dismount-WindowsImage -Path "C:\TempBGPMount" -Save | Out-Null
        Remove-Item "C:\TempBGPMount"
    
        # Start the VM

        Write-Verbose "Starting $VMName VM."
        Start-VM -Name $VMName      
    
        # Wait for VM to be started

        while ((Invoke-Command -VMName $VMName -Credential $localcred { "Test" } -ea SilentlyContinue) -ne "Test") { Start-Sleep -Seconds 1 }    
    
        Write-Verbose "Configuring $VMName" 
    
        Invoke-Command -VMName $VMName -Credential $localCred -ArgumentList $SDNConfig -ScriptBlock {
    
            $ErrorActionPreference = "Stop"
            $VerbosePreference = "Continue"
            $WarningPreference = "SilentlyContinue"
    
            $SDNConfig = $args[0]
            $Gateway = $SDNConfig.SDNLABRoute
            $DNS = $SDNConfig.SDNLABDNS
            $Domain = $SDNConfig.SDNDomainFQDN
            $natSubnet = $SDNConfig.natSubnet
            $natDNS = $SDNConfig.natSubnet
            $MGMTIP = $SDNConfig.BGPRouterIP_MGMT.Split("/")[0]
            $MGMTPFX = $SDNConfig.BGPRouterIP_MGMT.Split("/")[1]
            $PNVIP = $SDNConfig.BGPRouterIP_ProviderNetwork.Split("/")[0]
            $PNVPFX = $SDNConfig.BGPRouterIP_ProviderNetwork.Split("/")[1]
            $VLANIP = $SDNConfig.BGPRouterIP_VLAN200.Split("/")[0]
            $VLANPFX = $SDNConfig.BGPRouterIP_VLAN200.Split("/")[1]
            $simInternetIP = $SDNConfig.BGPRouterIP_SimulatedInternet.Split("/")[0]
            $simInternetPFX = $SDNConfig.BGPRouterIP_SimulatedInternet.Split("/")[1]
    
            # Renaming NetAdapters and setting up the IPs inside the VM using CDN parameters

            Write-Verbose "Configuring $env:COMPUTERNAME's Networking"
            $VerbosePreference = "SilentlyContinue"  
            $NIC = Get-NetAdapterAdvancedProperty -RegistryKeyWord "HyperVNetworkAdapterName" | Where-Object { $_.RegistryValue -eq "Mgmt" }
            Rename-NetAdapter -name $NIC.name -newname "Mgmt" | Out-Null
            New-NetIPAddress -InterfaceAlias "Mgmt" –IPAddress $MGMTIP -PrefixLength $MGMTPFX | Out-Null
            Set-DnsClientServerAddress -InterfaceAlias “Mgmt” -ServerAddresses $DNS] | Out-Null
            $NIC = Get-NetAdapterAdvancedProperty -RegistryKeyWord "HyperVNetworkAdapterName" | Where-Object { $_.RegistryValue -eq "PROVIDER" }
            Rename-NetAdapter -name $NIC.name -newname "PROVIDER" | Out-Null
            New-NetIPAddress -InterfaceAlias "PROVIDER" –IPAddress $PNVIP -PrefixLength $PNVPFX | Out-Null
            $NIC = Get-NetAdapterAdvancedProperty -RegistryKeyWord "HyperVNetworkAdapterName" | Where-Object { $_.RegistryValue -eq "VLAN200" }
            Rename-NetAdapter -name $NIC.name -newname "VLAN200" | Out-Null
            New-NetIPAddress -InterfaceAlias "VLAN200" –IPAddress $VLANIP -PrefixLength $VLANPFX | Out-Null
            $NIC = Get-NetAdapterAdvancedProperty -RegistryKeyWord "HyperVNetworkAdapterName" | Where-Object { $_.RegistryValue -eq "SIMInternet" }
            Rename-NetAdapter -name $NIC.name -newname "SIMInternet" | Out-Null
            New-NetIPAddress -InterfaceAlias "SIMInternet" –IPAddress $simInternetIP -PrefixLength $simInternetPFX | Out-Null      
    
            # if NAT is selected, configure the adapter
       
            if ($SDNConfig.natConfigure) {
    
                $NIC = Get-NetAdapterAdvancedProperty -RegistryKeyWord "HyperVNetworkAdapterName" `
                | Where-Object { $_.RegistryValue -eq "NAT" }
                Rename-NetAdapter -name $NIC.name -newname "NAT" | Out-Null
                $Subnet = ($natSubnet.Split("/"))[0]
                $Prefix = ($natSubnet.Split("/"))[1]
                $natEnd = $Subnet.Split(".")
                $natIP = ($natSubnet.TrimEnd("0./$Prefix")) + (".10")
                $natGW = ($natSubnet.TrimEnd("0./$Prefix")) + (".1")
                New-NetIPAddress -InterfaceAlias "NAT" –IPAddress $natIP -PrefixLength $Prefix -DefaultGateway $natGW | Out-Null
                if ($natDNS) {
                    Set-DnsClientServerAddress -InterfaceAlias "NAT" -ServerAddresses $natDNS | Out-Null
                }
            }
    
            # Configure Trusted Hosts

            Write-Verbose "Configuring Trusted Hosts"
            Set-Item WSMan:\localhost\Client\TrustedHosts * -Confirm:$false -Force
            
            
            # Installing Remote Access

            Write-Verbose "Installing Remote Access on $env:COMPUTERNAME" 
            $VerbosePreference = "SilentlyContinue"
            Install-RemoteAccess -VPNType RoutingOnly | Out-Null
    
            # Adding a BGP Router to the VM

            $VerbosePreference = "Continue"
            Write-Verbose "Installing BGP Router on $env:COMPUTERNAME"
            $VerbosePreference = "SilentlyContinue"

            $params = @{

                BGPIdentifier  = $PNVIP
                LocalASN       = $SDNConfig.BGPRouterASN
                TransitRouting = 'Enabled'
                ClusterId      = 1
                RouteReflector = 'Enabled'

            }

            Add-BgpRouter @params

            #Add-BgpRouter -BGPIdentifier $PNVIP -LocalASN $SDNConfig.BGPRouterASN `
            # -TransitRouting Enabled -ClusterId 1 -RouteReflector Enabled

            # Configure BGP Peers

            if ($SDNConfig.ConfigureBGPpeering -and $SDNConfig.ProvisionNC) {

                Write-Verbose "Peering future MUX/GWs"

                $Mux01IP = ($SDNConfig.BGPRouterIP_ProviderNetwork.TrimEnd("1/24")) + "4"
                $GW01IP = ($SDNConfig.BGPRouterIP_ProviderNetwork.TrimEnd("1/24")) + "5"
                $GW02IP = ($SDNConfig.BGPRouterIP_ProviderNetwork.TrimEnd("1/24")) + "6"

                $params = @{

                    Name           = 'MUX01'
                    LocalIPAddress = $PNVIP
                    PeerIPAddress  = $Mux01IP
                    PeerASN        = $SDNConfig.SDNASN
                    OperationMode  = 'Mixed'
                    PeeringMode    = 'Automatic'
                }

                Add-BgpPeer @params -PassThru

                $params.Name = 'GW01'
                $params.PeerIPAddress = $GW01IP

                Add-BgpPeer @params -PassThru

                $params.Name = 'GW02'
                $params.PeerIPAddress = $GW02IP

                Add-BgpPeer @params -PassThru    

            }
    
            # Enable Large MTU

            Write-Verbose "Configuring MTU on all Adapters"
            Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Set-NetAdapterAdvancedProperty -RegistryValue $SDNConfig.SDNLABMTU -RegistryKeyword "*JumboPacket"   
    
        }     
    
        $ErrorActionPreference = "Continue"
        $VerbosePreference = "SilentlyContinue"
        $WarningPreference = "Continue"

    } -AsJob

}

function New-SDNS2DCluster {

    param (

        $SDNConfig,
        $domainCred,
        $AzStackClusterNode

    )

    $VerbosePreference = "Continue" 
                
    Invoke-Command -ComputerName $AzStackClusterNode -ArgumentList $SDNConfig, $domainCred -Credential $domainCred -ScriptBlock {
         
        $SDNConfig = $args[0]
        $domainCred = $args[1]
        $VerbosePreference = "SilentlyContinue"
        $ErrorActionPreference = "Stop"


        Register-PSSessionConfiguration -Name microsoft.SDNNestedS2D -RunAsCredential $domainCred -MaximumReceivedDataSizePerCommandMB 1000 -MaximumReceivedObjectSizeMB 1000 | Out-Null

        Invoke-Command -ComputerName $Using:AzStackClusterNode -ArgumentList $SDNConfig, $domainCred -Credential $domainCred -ConfigurationName microsoft.SDNNestedS2D -ScriptBlock {

            $SDNConfig = $args[0]
            $domainCred = $args[1]


            # Create S2D Cluster

            $SDNConfig = $args[0]
            $AzSHOSTs = @("AzSHOST1", "AzSHOST2")

            Write-Verbose "Creating Cluster: AzStackCluster"

            $VerbosePreference = "SilentlyContinue"

            Import-Module FailoverClusters 
            Import-Module Storage

            $VerbosePreference = "Continue"

            $ClusterIP = ($SDNConfig.MGMTSubnet.TrimEnd("0/24")) + "252"
            $ClusterName = "AzStackCluster"

            # Create Cluster

            $VerbosePreference = "SilentlyContinue"

            New-Cluster -Name $ClusterName -Node $AzSHOSTs -StaticAddress $ClusterIP `
                -NoStorage -WarningAction SilentlyContinue | Out-Null

            $VerbosePreference = "Continue"

            # Invoke Command to enable S2D on AzStackCluster        
            
              Enable-ClusterS2D -Confirm:$false -Verbose

            # Wait for Cluster Performance History Volume to be Created
            while (!$PerfHistory) {

            Write-Verbose "Waiting for Cluster Performance History volume to come online."
            Start-Sleep -Seconds 10            
            $PerfHistory = Get-ClusterResource | Where-Object {$_.Name -match 'ClusterPerformanceHistory'}
            if ($PerfHistory) {Write-Verbose "Cluster Perfomance History volume online." }            

            }


            Write-Verbose "Setting Physical Disk Media Type"

            Get-PhysicalDisk | Where-Object { $_.Size -lt 127GB } | Set-PhysicalDisk -MediaType HDD | Out-Null

            $params = @{
            
                FriendlyName            = "S2D_vDISK1" 
                FileSystem              = 'CSVFS_ReFS'
                StoragePoolFriendlyName = 'S2D on AzStackCluster'
                ResiliencySettingName   = 'Mirror'
                PhysicalDiskRedundancy  = 1
                AllocationUnitSize = 64KB
                
            }


            Write-Verbose "Creating Physical Disk"

            Start-Sleep -Seconds 60
            New-Volume @params -UseMaximumSize  | Out-Null

            # Set Virtual Environment Optimizations

            Write-Verbose "Setting Virtual Environment Optimizations"


             

            $VerbosePreference = "SilentlyContinue"
            Get-storagesubsystem clus* | set-storagehealthsetting -name “System.Storage.PhysicalDisk.AutoReplace.Enabled” -value “False”
            Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\spaceport\Parameters -Name HwTimeout -Value 0x00007530
            $VerbosePreference = "Continue"
           
                    # Rename Storage Network Adapters

        Write-Verbose "Renaming Storage Network Adapters"

        (Get-Cluster -Name azstackcluster | Get-ClusterNetwork | Where-Object { $_.Address -eq ($sdnconfig.storageAsubnet.Replace('/24', '')) }).Name = 'StorageA'
        (Get-Cluster -Name azstackcluster | Get-ClusterNetwork | Where-Object { $_.Address -eq ($sdnconfig.storageBsubnet.Replace('/24', '')) }).Name = 'StorageB'
        (Get-Cluster -Name azstackcluster | Get-ClusterNetwork | Where-Object { $_.Address -eq ($sdnconfig.MGMTSubnet.Replace('/24', '')) }).Name = 'Public'


        # Set Allowed Networks for Live Migration

        Write-Verbose "Setting allowed networks for Live Migration"

        Get-ClusterResourceType -Name "Virtual Machine" -Cluster AzStackCluster | Set-ClusterParameter -Cluster AzStackCluster -Name MigrationExcludeNetworks `
            -Value ([String]::Join(";", (Get-ClusterNetwork -Cluster AzStackCluster | Where-Object { $_.Name -notmatch "Storage" }).ID))

        } | Out-Null

    } 


}

function test-internetConnect {

    $testIP = '1.1.1.1'
    $ErrorActionPreference = "Stop"  
    $intConnect = Test-Connection -ComputerName $testip -Quiet -Count 2

    if (!$intConnect) {

        Write-Error "Unable to connect to Internet. An Internet connection is required."

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

#region Main
    
$WarningPreference = "SilentlyContinue"
$ErrorActionPreference = "Stop" 

#Get Start Time
$starttime = Get-Date
   
    
# Import Configuration Module

$SDNConfig = Import-PowerShellDataFile -Path $ConfigurationDataFile
Copy-Item $ConfigurationDataFile -Destination .\Applications\SCRIPTS -Force

# Set-Credentials
$localCred = new-object -typename System.Management.Automation.PSCredential `
    -argumentlist "Administrator", (ConvertTo-SecureString $SDNConfig.SDNAdminPassword -AsPlainText -Force)

$domainCred = new-object -typename System.Management.Automation.PSCredential `
    -argumentlist (($SDNConfig.SDNDomainFQDN.Split(".")[0]) + "\Administrator"), `
(ConvertTo-SecureString $SDNConfig.SDNAdminPassword  -AsPlainText -Force)

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
  

# Set Variables from config file

$NestedVMMemoryinGB = $SDNConfig.NestedVMMemoryinGB
$guiVHDXPath = $SDNConfig.guiVHDXPath
$azSHCIVHDXPath = $SDNConfig.azSHCIVHDXPath
$HostVMPath = $SDNConfig.HostVMPath
$InternalSwitch = $SDNConfig.InternalSwitch
$natDNS = $SDNConfig.natDNS
$natSubnet = $SDNConfig.natSubnet
$natConfigure = $SDNConfig.natConfigure   


$VerbosePreference = "SilentlyContinue" 
Import-Module Hyper-V 
$VerbosePreference = "Continue"
$ErrorActionPreference = "Stop"
    

# Enable PSRemoting

Write-Verbose "Enabling PS Remoting on client..."
$VerbosePreference = "SilentlyContinue"
Enable-PSRemoting
Set-Item WSMan:\localhost\Client\TrustedHosts * -Confirm:$false -Force
$VerbosePreference = "Continue"

# if single host installation, set up installation parameters

if (!$SDNConfig.MultipleHyperVHosts) {

    Write-Verbose "No Multiple Hyper-V Hosts defined. Using Single Hyper-V Host Installation"
    Write-Verbose "Testing VHDX Path"

    $params = @{

        guiVHDXPath    = $guiVHDXPath
        azSHCIVHDXPath = $azSHCIVHDXPath
    
    }

    Test-VHDPath @params

    Write-Verbose "Generating Single Host Placement"

    $VMPlacement = Select-SingleHost -AzSHOSTs $AzSHOSTs

    Write-Verbose "Creating Internal Switch"

    $params = @{

        pswitchname = $InternalSwitch
        SDNConfig   = $SDNConfig
    
    }

    New-InternalSwitch @params

    Write-Verbose "Creating NAT Switch"

    set-hostnat -SDNConfig $SDNConfig

    $VMSwitch = $InternalSwitch

    Write-Verbose "Getting local Parent VHDX Path"

    $params = @{

        guiVHDXPath = $guiVHDXPath
        HostVMPath  = $HostVMPath
    
    }


    $ParentVHDXPath = Get-guiVHDXPath @params

    Set-LocalHyperVSettings -HostVMPath $HostVMPath

    $params = @{

        azSHCIVHDXPath = $azSHCIVHDXPath
        HostVMPath     = $HostVMPath
    
    }

    $coreParentVHDXPath = Get-azSHCIVHDXPath @params


}

# if single host installation, copy the parent VHDX file to the specified Parent VHDX Path

if (!$SDNConfig.MultipleHyperVHosts) {

    Write-Verbose "Copying VHDX Files to Host"

    $params = @{

        azSHCIVHDXPath = $azSHCIVHDXPath
        HostVMPath     = $HostVMPath
        guiVHDXPath    = $guiVHDXPath 
    }

    Copy-VHDXtoHost @params
}

# Provision Domain Controller 
Write-Verbose "Provisioning Domain Controller VM"
New-DCVM -SDNConfig $SDNConfig -localCred $localCred -domainCred $domainCred | Out-Null







    

    