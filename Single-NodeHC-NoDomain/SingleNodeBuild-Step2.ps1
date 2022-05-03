$LocalCreds=Get-Credential -UserName "SAHCI\Administrator" -Message "Provide Local Credentials"
$HCInode="10.50.10.202"
$HCINNodeName="SAHCI"
$Clustername="SAHCICL"
$DNSIp="10.50.10.1"
$clusterIP="10.50.10.203"

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
    New-Volume -FriendlyName "Volume 1" -StoragePoolFriendlyName $sp.FriendlyName -FileSystem CSVFS_ReFS -ResiliencySettingName Simple -Size 10GB
    
    
    
    }
    

