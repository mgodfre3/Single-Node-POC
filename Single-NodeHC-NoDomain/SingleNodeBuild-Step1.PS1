##Phase 1A #

$lcred=Get-Credential -UserName "Administrator" -Message "Local Credential"
$HCInode = "$env:computername"
$HCINodeName="SAHCI1"

Invoke-Command -ComputerName $HCInode -Credential $lcred -ScriptBlock {
        Rename-Computer -NewName "$Using:HCINodeName"
        $WinFeatures = "BitLocker", "Data-Center-Bridging", "Failover-Clustering", "FS-FileServer", "FS-Data-Deduplication", "Hyper-V", `
                "Hyper-V-PowerShell", "RSAT-AD-Powershell", "RSAT-Clustering-PowerShell", "NetworkATC", "Storage-Replica"

        Install-WindowsFeature -Name $WinFeatures -IncludeAllSubFeature -IncludeManagementTools
        Restart-Computer -Force
}
