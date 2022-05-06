##Parmaeters
$LocalCreds=Get-Credential -UserName "SAHCI\Administrator" -Message "Provide Local Credentials"
$HCInode="" #Provide HCI Node Name or if no DNS entry is populated, the IP address will work. 
$HCINNodeName="" # Provide the desired name of the Node
$Clustername="" #Provide the Desired Cluster Name
$SPFName="" #Provide Friendly name for Storage Pool
$DNSIp=""   #Provide the Desired DNS Server(s) IP Addresses
$clusterIP=""   #Provide the Desired Cluster IP Address, please update your DNS with A Records




##Step 1A
Invoke-Command -ComputerName $HCINode -Credential $localcreds -ScriptBlock {
    $netAdapters = (get-netadapter | Where-Object {$_.name -NotLike "vEthernet*" -and $_.status -eq "Up"})
    New-VMSwitch -Name "HCI-Uplink" -EnableEmbeddedTeaming $true -AllowManagementOS $true -MinimumBandwidthMode Weight -NetAdapterName $netAdapters.name
    $vnetadapter=Get-Netadapter |  Where-Object {$_.name -Like "vEthernet*" -and $_.status -eq "Up"}
    Set-DnsClientServerAddress -InterfaceAlias $vnetadapter.InterfaceAlias -ServerAddresses $using:dnsip 
    New-Cluster -Name SAHCICL -StaticAddress $using:clusterIP -AdministrativeAccessPoint dns -NoStorage
    Enable-ClusterS2D -PoolFriendlyName $Using:SPFName -Confirm:$false
    Set-StoragePool -FriendlyName $Using:SPFName -FaultDomainAwarenessDefault 'PhysicalDisk'
    New-Volume -StoragePoolFriendlyName $Using:SPFName -FriendlyName "Volume01" -FileSystem CSVFS_ReFS `
     -ResiliencySettingName Simple -UseMaximumSize
    
    }

#Step 2 Azure Registration


write-host -ForegroundColor Green -Object "Register the Cluster to Azure Subscription"
#Variables


#Azure Account Info
  #install modules
  Invoke-Command -ComputerName $HCINode -Credential $localcreds -ScriptBlock {

       Write-Host "Installing Required Modules" -ForegroundColor Green -BackgroundColor Black
        Remove-Item 'C:\Program Files\WindowsPowerShell\Modules\Az.StackHCI' -Recurse -force
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
        $hcicustommoduleuri="https://github.com/mgodfre3/Single-Node-POC/blob/main/Single-NodeHC-NoDomain/CustomModules.zip?raw=true"
        New-Item -Path C:\ -Name Temp -ItemType Directory
        Invoke-WebRequest -Uri $hcicustommoduleuri -OutFile C:\temp\Az.StackHCI-Custom.zip
        Expand-Archive C:\temp\AZ.StackHCI-Custom.zip -DestinationPath 'C:\Temp\Custom' -Force
        Get-Item C:\temp\Custom\CustomModules\Az.StackHCI |Copy-Item -Destination 'C:\Program Files\WindowsPowerShell\Modules' -Recurse -force
        Install-module Az.StackHCI -RequiredVersion 1.1.1 -Force 


        $ModuleNames="Az.Resources","Az.Accounts"
        foreach ($ModuleName in $ModuleNames){
            if (!(Get-InstalledModule -Name $ModuleName -ErrorAction Ignore)){
                Install-Module -Name $ModuleName -Force
            }
        }
    }
        #Register the Cluster
        Login-AZAccount -UseDeviceAuthentication 
        $context=Get-AZContext
        Register-AzStackHCI -SubscriptionId $context.Subscription.Id -EnableAzureArcServer -Region "EastUS" -ResourceName $Clustername -UseDeviceAuthentication


    
    
