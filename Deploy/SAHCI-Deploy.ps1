<#
.SYNOPSIS 
    Deploys and configure a Single Node Azure Stack HCI Cluster for a Proof of Concept.
.EXAMPLE
    .\SAHCI-Deploy.ps1 -ConfigurationFile .\sahci_config.psd1

.NOTES
    Prerequisites:
    *This script should be run from a Jump Workstation, with network communication to the ASHCI Physical Nodes that will be configured"
     
    * You will be asked to login to your Azure Subscription, as this will allow credentials from Azure Key Vault to be utilized.
    
    *The AD Group "Fabric Admins" needs to be made local admin on the Hosts.  
    
    *You must provide the Configuraiton variables in the attached Config file and supply it as a paramter.

    *You will need to configure AD and Service Principal Secrets in an Azure Key Vault in the same subscription. 
#>

param(
    [Parameter(Mandatory)]
    [String] $ConfigurationDataFile
) 

#Set Variables from Config File
Get-Content $ConfigurationDataFile
$config=Import-PowerShellDataFile -Path $ConfigurationDataFile 

Write-Host -ForegroundColor Green -Object $WelcomeMessage




###################################################################################

#Set AD Domain Cred
$adcred=Get-Credential -UserName "contoso\administrator" -Message "Provide AD Account Password"

<#
#Set Azure Context 
        $azcred=Get-AzContext

        if (-not (Get-AzContext)){
            $azcred=Login-AzAccount -UseDeviceAuthentication
        }

    #select context
        $context=Get-AzContext -ListAvailable
        if (($context).count -gt 1){
            $context=$context | Out-GridView -OutputMode Single
            $context | Set-AzContext
        }

    #location (all locations where HostPool can be created)
        $region=(Get-AzLocation | Where-Object Providers -Contains "Microsoft.DesktopVirtualization" | Out-GridView -OutputMode Single -Title "Please select Location for AVD Host Pool metadata").Location
#>

#######################################################################################

$ServerList = $config.Node01

###############################################################################################################################

Write-Host -ForegroundColor Green -Object "Configuring Managment Workstation"

#Set WinRM for remote management of nodes
winrm quickconfig
Enable-WSManCredSSP -Role Client -DelegateComputer * -Force
#New-Item hklm:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentialsWhenNTLMOnly
#New-ItemProperty hklm:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentialsWhenNTLMOnly -Name 1 -Value "wsman/*" -Force

###############################################################################################################################
Write-Host -ForegroundColor Green -Object "Installing Required Features on Management Workstation"


#Install some PS modules if not already installed

$wsinfo=Get-computerinfo -Property osproducttype

#Windows Workstation Command 
if ($wsinfo -eq "workstation") {
    $featurename="RSAT-AzureStack.HCI.Management.Tools", "RSAT-FailoverClusterManagement.Tools"
ForEach ($f in $featurename){
Add-WindowsCapability -Online -Name $f 
    }
$optionalFeatures="Microsoft-Hyper-V-Management-PowerShell"
ForEach ($of in $optionalFeatures)
{
    Enable-WindowsOptionalFeature -Online -FeatureName $of
} 

elseif ($wsinfo -eq "server") {
    Install-WindowsFeature -Name RSAT-Clustering,RSAT-Clustering-Mgmt,RSAT-Clustering-PowerShell,RSAT-Hyper-V-Tools;
}

Install-Module AZ.ConnectedMachine -force

##########################################Configure Nodes####################################################################

Write-Host -ForegroundColor Green "Configuring Nodes"

#Add features, add PS modules, rename, join domain, reboot
Invoke-Command -ComputerName $ServerList -Credential $ADCred -ScriptBlock {
    Install-WindowsFeature -Name "BitLocker", "Data-Center-Bridging", "Failover-Clustering", "FS-FileServer", "FS-Data-Deduplication", "Hyper-V", "Hyper-V-PowerShell", "RSAT-AD-Powershell", "RSAT-Clustering-Powershell","FS-Data-Deduplication", "Storage-Replica", "NetworkATC", "System-Insights" -IncludeAllSubFeature -IncludeManagementTools
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    Install-Module -Name Az.StackHCI -Force -All
    Enable-WSManCredSSP -Role Server -Force
    New-NetFirewallRule -DisplayName “ICMPv4” -Direction Inbound -Action Allow -Protocol icmpv4 -Enabled True
    Enable-NetFirewallRule -DisplayGroup “Remote Desktop”
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" –Value 0
    Set-TimeZone -Name $config.$timezone 
}
     
Restart-Computer -ComputerName $ServerList -Protocol WSMan -Wait -For PowerShell -Force

#Pause for a bit - let changes apply before moving on...
Start-Sleep 180

###############################################################################################################################

##################################################Configure Node01#############################################################
Write-Host -ForegroundColor Green -Object "Configure Node 01"

Invoke-Command -ComputerName $config.Node01 -Credential $ADCred -ScriptBlock {

# Configure IP and subnet mask, no default gateway for Storage interfaces
    #MGMT
    $netadapter=Get-NetAdapter | where status -eq "up"
    New-NetIPAddress -InterfaceAlias $netadapter.ifalias -IPAddress $using:config.node01_MgmtIP -PrefixLength 24 -DefaultGateway $using:config.GWIP | Set-DnsClientServerAddress -ServerAddresses $using:config.DNSIP

    #New-NetIPAddress -InterfaceAlias "LOM2 Port3" -IPAddress $using:config.node01_MgmtIP -PrefixLength 24 -DefaultGateway $using:config.GWIP  | Set-DnsClientServerAddress -ServerAddresses $using:config.DNSIP
    Get-NetAdapter | where status -NE "up"|  Disable-NetAdapter -Confirm:$false
}



#########################################################Configure HCI Cluster##########################################################

Write-Host -ForegroundColor Green -Object "Prepare Storage"

#Clear Storage
Invoke-Command ($ServerList) {
    Update-StorageProviderCache
    Get-StoragePool | ? IsPrimordial -eq $false | Set-StoragePool -IsReadOnly:$false -ErrorAction SilentlyContinue
    Get-StoragePool | ? IsPrimordial -eq $false | Get-VirtualDisk | Remove-VirtualDisk -Confirm:$false -ErrorAction SilentlyContinue
    Get-StoragePool | ? IsPrimordial -eq $false | Remove-StoragePool -Confirm:$false -ErrorAction SilentlyContinue
    Get-PhysicalDisk | Reset-PhysicalDisk -ErrorAction SilentlyContinue
    Get-Disk | ? Number -ne $null | ? IsBoot -ne $true | ? IsSystem -ne $true | ? PartitionStyle -ne RAW | % {
        $_ | Set-Disk -isoffline:$false
        $_ | Set-Disk -isreadonly:$false
        $_ | Clear-Disk -RemoveData -RemoveOEM -Confirm:$false
        $_ | Set-Disk -isreadonly:$true
        $_ | Set-Disk -isoffline:$true
    }
    Get-Disk | Where Number -Ne $Null | Where IsBoot -Ne $True | Where IsSystem -Ne $True | Where PartitionStyle -Eq RAW | Group -NoElement -Property FriendlyName
} | Sort -Property PsComputerName, Count

#########################################################################################################################################
Write-Host -ForegroundColor Green -Object "Creating the Cluster"

#Create the Cluster
#Test-Cluster –Node $config.Node01 –Include "Storage Spaces Direct", "Inventory", "Network", "System Configuration"
New-Cluster -Name $config.ClusterName -Node $config.Node01 -StaticAddress $config.ClusterIP -NoStorage -AdministrativeAccessPoint Dns


#Pause for a bit then clear DNS cache.
Start-Sleep 30
Clear-DnsClientCache

# Update the cluster network names that were created by default.  First, look at what's there
Get-ClusterNetwork -Cluster $config.ClusterName  | ft Name, Role, Address

# Change the cluster network names so they are consistent with the individual nodes
(Get-ClusterNetwork -Cluster $config.ClusterName  | where-object address -like $config.MGMTSubnet).Name = "MGMT"

# Check to make sure the cluster network names were changed correctly
Get-ClusterNetwork -Cluster $config.ClusterName | ft Name, Role, Address

#########################################################################################################################################
Write-Host -ForegroundColor Green -Object "Set Cluster Live Migration Settings"

#Set Cluster Live Migration Settings 
Enable-VMMigration -ComputerName $ServerList
Set-VMHost -ComputerName $ServerList -MaximumStorageMigrations 2 -MaximumVirtualMachineMigrations 2 -VirtualMachineMigrationPerformanceOption SMB -UseAnyNetworkForMigration $false 

#########################################################################################################################################
Write-Host -ForegroundColor Green -Object "Enable Storage Spaces Direct"

#Enable S2D
Enable-ClusterStorageSpacesDirect  -CimSession $config.ClusterName -PoolFriendlyName $config.StoragePoolName -Confirm:0 

#########################################################################################################################################

#############Configure for 21H2 Preview Channel###############
Invoke-Command ($ServerList) {
    Set-WSManQuickConfig -Force
    Enable-PSRemoting
    Set-NetFirewallRule -Group "@firewallapi.dll,-36751" -Profile Domain -Enabled true
    Set-PreviewChannel
}

Restart-Computer -ComputerName $ServerList -Protocol WSMan -Wait -For PowerShell -Force
#Pause for a bit - let changes apply before moving on...
Start-Sleep 180

##########################################################################################################

#Update Cluster Function Level

$cfl=Get-Cluster -Name $config.ClusterName 
if ($cfl.ClusterFunctionalLevel -lt "12") {
write-host -ForegroundColor yellow -Object "Cluster Functional Level needs to be upgraded"  

Update-ClusterFunctionalLevel -Cluster $config.ClusterName -Verbose -Force
}

else {
write-host -ForegroundColor Green -Object "Cluster Functional Level is good"

}

#storage Pool Level check and upgrade

$spl=Get-StoragePool -CimSession $config.ClusterName -FriendlyName $config.StoragePoolName
 
if ($spl.version -ne "Windows Server 2022") {
write-host -ForegroundColor yellow -Object "Storage Pool Level needs to be upgraded"

Update-StoragePool -FriendlyName $config.StoragePoolName -Confirm:0 -CimSession $config.Node01
}
else {
write-host -ForegroundColor Green -Object "Storage Pool level is set to Windows Server 2022"
}

#########################################################################################################################################
write-host -ForegroundColor Green -Object "Creating Cluster Shared Volume"

#Create S2D Volume 
New-Volume -FriendlyName "Volume1" -FileSystem CSVFS_ReFS -StoragePoolFriendlyName $config.StoragePoolName -Size 10GB -ProvisioningType Thin -CimSession $config.ClusterName -ResiliencySettingName "Simple"


############################################################Set Net-Intent########################################################
write-host -ForegroundColor Green -Object "Setting NetworkATC Configuration"

Invoke-Command -ComputerName $config.Node01 -Credential $ADcred -Authentication Credssp {

#North-South Net-Intents
Add-NetIntent -ClusterName $using:config.ClusterName -AdapterName "Ethernet" -Name HCI -Compute -Management  
}

start-sleep 30 

Start-ClusterResource -Cluster $config.ClusterName -Name "Cluster IP Address"

write-host -ForegroundColor Green -Object "Testing to ensure Cluster IP is online" 

$tnc_clip=Test-NetConnection $config.ClusterIP
if ($tnc_clip.pingsucceded -eq "true") {
    write-host -ForegroundColor Green -Object "Cluster in online, NetworkATC was successful"
}

elseif ($tnc_clip.pingsucceded -eq "false") {
    Start-ClusterResource -Cluster $config.ClusterName -Name "Cluster IP Address"
   Start-Sleep 15
}
 
 $tnc_clip2=Test-NetConnection $config.ClusterIP

if ( $tnc_clip2.pingsucceded -eq "true") {

write-host -ForegroundColor Green -Object "Cluster in online, NetworkATC was successful"
}

else {

Write-Host -ForegroundColor Red -Object "Please ensure Cluster Resources are online and Network configration is correct on nodes";

    Start-Sleep 180
}

#########################################################################################################################################

write-host -ForegroundColor Green -Object "Register the Cluster to Azure Subscription"

#Register Cluster with Azure

    #download Azure module
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    if (!(Get-InstalledModule -Name Az.StackHCI -ErrorAction Ignore)){
        Install-Module -Name Az.StackHCI -Force
    }

    #login to azure
    #download Azure module
    if (!(Get-InstalledModule -Name az.accounts -ErrorAction Ignore)){
        Install-Module -Name Az.Accounts -Force
    }
    $azcred=Login-AzAccount -UseDeviceAuthentication

    #select context if more available
    $context=Get-AzContext -ListAvailable
    if (($context).count -gt 1){
        $context | Out-GridView -OutputMode Single | Set-AzContext
    }

    #select subscription if more available
    $subscriptions=Get-AzSubscription
    if (($subscriptions).count -gt 1){
        $SubscriptionID=($subscriptions | Out-GridView -OutputMode Single | Select-AzSubscription).Subscription.Id
    }else{
        $SubscriptionID=$subscriptions.id
    }

    #register Azure Stack HCI
        $ResourceGroupName="" #if blank, default will be used
        if (!(Get-InstalledModule -Name Az.Resources -ErrorAction Ignore)){
            Install-Module -Name Az.Resources -Force
        }
        #choose location for cluster (and RG)
        $region=(Get-AzLocation | Where-Object Providers -Contains "Microsoft.AzureStackHCI" | Out-GridView -OutputMode Single -Title "Please select Location for AzureStackHCI metadata").Location
        if ($ResourceGroupName){
            If (-not (Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Ignore)){
                New-AzResourceGroup -Name $ResourceGroupName -Location $region
            }
        }
        #Register AZSHCi without prompting for creds
        $armTokenItemResource = "https://management.core.windows.net/"
        $graphTokenItemResource = "https://graph.windows.net/"
        $azContext = Get-AzContext
        $authFactory = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory
        $graphToken = $authFactory.Authenticate($azContext.Account, $azContext.Environment, $azContext.Tenant.Id, $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, $graphTokenItemResource).AccessToken
        $armToken = $authFactory.Authenticate($azContext.Account, $azContext.Environment, $azContext.Tenant.Id, $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, $armTokenItemResource).AccessToken
        $id = $azContext.Account.Id
        #Register-AzStackHCI -SubscriptionID $subscriptionID -ComputerName $ClusterName -GraphAccessToken $graphToken -ArmAccessToken $armToken -AccountId $id
        if ($ResourceGroupName){
            Register-AzStackHCI -Region $Region -SubscriptionID $azContext.subscription.Id -ComputerName  $config.ClusterName -GraphAccessToken $graphToken -ArmAccessToken $armToken -AccountId $id -ResourceName $config.ClusterName ClusterName -ResourceGroupName $ResourceGroupName
        }else{
            Register-AzStackHCI -Region $Region -SubscriptionID $azcontext.subscription.ID -ComputerName  $config.ClusterName -GraphAccessToken $graphToken -ArmAccessToken $armToken -AccountId $id -ResourceName $config.ClusterName 
        }
    #validate registration status
        #grab available commands for registration
        Invoke-Command -ComputerName $config.ClusterName -ScriptBlock {Get-Command -Module AzureStackHCI}
        #validate cluster registration
        Invoke-Command -ComputerName $config.ClusterName -ScriptBlock {Get-AzureStackHCI}
        #validate certificates
        Invoke-Command -ComputerName $config.ClusterName -ScriptBlock {Get-AzureStackHCIRegistrationCertificate}
        #validate Arc integration
        Invoke-Command -ComputerName $config.ClusterName -ScriptBlock {Get-AzureStackHCIArcIntegration}






##########################################################################################################################

write-host -ForegroundColor Green -Object "Cluster is Deployed; Enjoy!"

