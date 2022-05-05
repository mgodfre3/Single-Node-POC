# Read in required Globals from config.txt file

$config = ConvertFrom-StringData (Get-Content -Raw ./config.txt)
foreach($i in $config.Keys) {New-Variable -Name $i -Value ($config.$i) -Force}

# Generate some derived values. You can edit these if you'd like to use other names.

$ClusterName = "cl-$HCINodeName"
$AzResourceGroup = "rg-$HCINodeName"


function Step1-PrepareNode {

    Rename-Computer -NewName $HCINodeName

    # Build a list of required features that need to be installed and install them
    $WinFeatures = "BitLocker", "Data-Center-Bridging", "Failover-Clustering", "FS-FileServer", "FS-Data-Deduplication", "Hyper-V", `
            "Hyper-V-PowerShell", "RSAT-AD-Powershell", "RSAT-Clustering-PowerShell", "NetworkATC", "Storage-Replica"

    Install-WindowsFeature -Name $WinFeatures -IncludeAllSubFeature -IncludeManagementTools

    # Clean up any previous attempts
    Get-Cluster | Remove-Cluster -Confirm:$false -Force -ErrorAction SilentlyContinue
    Get-VMSwitch | Remove-VMSwitch -Confirm:$false -Force -ErrorAction SilentlyContinue

    # Clear out storage devices
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

    # Fetch the modified Az.StackHCI module needed for workgroup cluster registration
    Remove-Item 'C:\Program Files\WindowsPowerShell\Modules\Az.StackHCI' -Recurse -Force -ErrorAction SilentlyContinue
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    $hcicustommoduleuri="https://github.com/mgodfre3/Single-Node-POC/blob/main/Single-NodeHC-NoDomain/CustomModules.zip?raw=true"
    New-Item -Path C:\ -Name Temp -ItemType Directory
    Invoke-WebRequest -Uri $hcicustommoduleuri -OutFile 'C:\Temp\Az.StackHCI-Custom.zip'
    Expand-Archive 'C:\Temp\AZ.StackHCI-Custom.zip' -DestinationPath 'C:\Temp' -Force
    Copy-Item -Path 'C:\Temp\CustomModules\Az.StackHCI' -Destination 'C:\Program Files\WindowsPowerShell\Modules' -Recurse

    # We'll need to reboot here no matter what
    Restart-Computer -Force
}

function Step2-ConfigureCluster {

    # Fetch the NICs that are up
    $adapter = (Get-NetAdapter -Physical | Where-Object {$_.Status -eq "Up"})

    # Create a VM Switch on the first NIC only (simplicty)
    New-VMSwitch -Name "HCI-Uplink" -EnableEmbeddedTeaming $true -AllowManagementOS $true -MinimumBandwidthMode Weight -NetAdapterName $adapter[0].Name

    # Grab the IP address from the new vNIC
    $MgmtIP = Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias "vEthernet (HCI-Uplink)"

    # Write out the hosts entries for the node and cluster
    $hostRecord = ($MgmtIP.IPAddress + " $HCINodeName")
    Out-File "C:\Windows\System32\drivers\etc\hosts" -Encoding utf8 -Append -InputObject $hostRecord
    Out-File "C:\Windows\System32\drivers\etc\hosts" -Encoding utf8 -Append -InputObject "$ClusterIP $ClusterName"

    # Create the cluster
    New-Cluster -Name $ClusterName -Node $HCINodeName -StaticAddress $ClusterIP -AdministrativeAccessPoint DNS -NoStorage
    
    # Enable S2D on the new cluster and create a volume
    Enable-ClusterS2D -PoolFriendlyName "S2Dpool" -Confirm:$false
    Set-StoragePool -FriendlyName S2Dpool -FaultDomainAwarenessDefault 'PhysicalDisk'
    New-Volume -StoragePoolFriendlyName "S2Dpool" -FriendlyName "Volume01" -FileSystem CSVFS_ReFS -ResiliencySettingName Simple -UseMaximumSize
}

function Step3-RegisterCluster {

    # Clean upDownload the modified Az.StackHCI module
    Import-Module Az.StackHCI
    Register-AzStackHCI -SubscriptionId $AzSubscription -Region $AzRegion -ResourceName $ClusterName -ResourceGroupName $AzResourceGroup -UseDeviceAuthentication
}

function Step4-PrepareAKSHCI {

    # Install modules and prepare subscription
    Install-Module -Name Az.Accounts -Repository PSGallery -RequiredVersion 2.2.4 -Confirm:$false
    Install-Module -Name Az.Resources -Repository PSGallery -RequiredVersion 3.2.0 -Confirm:$false
    Install-Module -Name AzureAD -Repository PSGallery -RequiredVersion 2.0.2.128 -Confirm:$false
    Install-Module -Name AksHci -Repository PSGallery -Confirm:$false

    Connect-AzAccount -Subscription $AzSubscription -UseDeviceAuthentication

    Register-AzResourceProvider -ProviderNamespace Microsoft.Kubernetes
    Register-AzResourceProvider -ProviderNamespace Microsoft.KubernetesConfiguration

    Out-File "C:\Windows\System32\drivers\etc\hosts" -Encoding utf8 -Append -InputObject "$ClusterIP $ClusterName"

    Write-Host "Please close this entire command window so that modules load correctly"

}

function Step5-InstallAKSHCI {

    Initialize-AksHciNode
    Import-Module Moc

    $DnsServer = (Get-DnsClientServerAddress -InterfaceAlias "vEthernet (HCI-Uplink)" -AddressFamily IPv4).ServerAddresses[0]
    $DefaultGw = (Get-NetRoute "0.0.0.0/0").NextHop

    $vnet = New-AksHciNetworkSetting -name myvnet -vSwitchName "HCI-Uplink" -k8sNodeIpPoolStart $AksNodeIpPoolStart -k8sNodeIpPoolEnd $AksNodeIpPoolEnd `
        -vipPoolStart $AksVipPoolStart -vipPoolEnd $AksVipPoolEnd -ipAddressPrefix $CidrSubnet -gateway $DefaultGw -dnsServers $dnsServer

    Set-AksHciConfig -imageDir C:\ClusterStorage\Volume01\Images -workingDir C:\ClusterStorage\Volume01\ImageStore -clusterRoleName "ca-$HCINodeName" `
        -cloudConfigLocation C:\ClusterStorage\Volume01\Config -vnet $vnet -cloudservicecidr $AksCloudIpCidr

    Set-MocConfigValue -Name "cloudFqdn" -Value $AksCloudIpCidr.Substring(0,($AksCloudIpCidr.IndexOf('/')))

    
    Set-AksHciRegistration -subscriptionId $AzSubscription -resourceGroupName $AzResourceGroup -UseDeviceAuthentication

    Install-AksHci
}