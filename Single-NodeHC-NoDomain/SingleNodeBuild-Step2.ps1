$LocalCreds=Get-Credential -UserName "SAHCI\Administrator" -Message "Provide Local Credentials"
$HCInode=""
$HCINNodeName="SAHCI"
$Clustername="SAHCICL"
$DNSIp=""
$clusterIP="1"

$AZSubscriptionIS=""



##Step 1A
Invoke-Command -ComputerName $HCINode -Credential $localcreds -ScriptBlock {
    $netAdapters = (get-netadapter | Where-Object {$_.name -NotLike "vEthernet*" -and $_.status -eq "Up"})
    New-VMSwitch -Name "HCI-Uplink" -EnableEmbeddedTeaming $true -AllowManagementOS $true -MinimumBandwidthMode Weight -NetAdapterName $netAdapters.name
    $vnetadapter=Get-Netadapter |  Where-Object {$_.name -Like "vEthernet*" -and $_.status -eq "Up"}
    Set-DnsClientServerAddress -InterfaceAlias $vnetadapter.InterfaceAlias -ServerAddresses $using:dnsip 
    New-Cluster -Name SAHCICL -StaticAddress $using:clusterIP -AdministrativeAccessPoint dns -NoStorage
    Enable-ClusterS2D -PoolFriendlyName "SAHCICL Storage Pool"
    $sp=Get-StoragePool | Where-Object friendlyname -ne "Primordial" 
    New-Volume -FriendlyName "Volume 1" -StoragePoolFriendlyName $sp.FriendlyName -FileSystem CSVFS_ReFS -ResiliencySettingName Simple -Size 100GB
    
    
    
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
        New-Item -Path C:\ -Name Test -ItemType Directory
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
        Register-AzStackHCI -SubscriptionId $context.Subscription.Id -EnableAzureArcServer -Region "EastUS" -ResourceName $using:clustername -UseDeviceAuthentication


    
    
