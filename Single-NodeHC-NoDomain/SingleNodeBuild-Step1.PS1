##Phase 1A #

$lcred=Get-Credential -UserName "Administrator" -Message "Local Credential"
$HCInode="10.50.10.202"
$HCINNodeName="SAHCI"
$Clustername="SAHCICL"
$DNSIp="10.50.10.1"
$clusterIP="10.50.10.203"
$Volume1Size="10GB" #Please put in GB
$AZSubscriptionIS="a2899dc7-f46b-4ba8-a492-1b957352eefd"



Invoke-Command -ComputerName $HCINode -Credential $lcred -ScriptBlock {
        Rename-Computer -NewName "$HCINodename"
        $WinFeatures = "Hyper-V-Powershell", "Hyper-V", "Failover-Clustering"
        ForEach ($f in $WinFeatures) {
        Install-WindowsFeature -Name $f -IncludeAllSubFeature -IncludeManagementTools
        Restart-Computer -Force  
}

}