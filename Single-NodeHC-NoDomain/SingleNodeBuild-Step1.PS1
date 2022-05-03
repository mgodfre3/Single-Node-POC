##Phase 1A #

$lcred=Get-Credential -UserName "Administrator" -Message "Local Credential"
$HCInode="10.50.10.202"
$HCINNodeName="SAHCI"




Invoke-Command -ComputerName $HCINode -Credential $lcred -ScriptBlock {
        Rename-Computer -NewName "$HCINodename"
        $WinFeatures = "Hyper-V-Powershell", "Hyper-V", "Failover-Clustering"
        ForEach ($f in $WinFeatures) {
        Install-WindowsFeature -Name $f -IncludeAllSubFeature -IncludeManagementTools
        Restart-Computer -Force  
}

}