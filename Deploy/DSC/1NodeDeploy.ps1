##Phase 1A #

$lcred=Get-Credential -UserName "Administrator" -Message "Local Credential"
Invoke-Command -ComputerName 10.50.10.253 -Credential $lcred -ScriptBlock {
        Rename-Computer -NewName "SAHCI"
        $WinFeatures = "Hyper-V-Powershell", "Hyper-V", "Hyper-V-Tools"
        ForEach ($f in $WinFeatures) {
        Install-WindowsFeature -Name $f -IncludeAllSubFeature -IncludeManagementTools -Restart 
}

}


$LocalCreds=Get-Credential -UserName "SAHCI\Administrator" -Message "Provide Local Credentials"

##Step 1A
Invoke-Command -ComputerName 10.50.10.253 -Credential $localcreds -ScriptBlock {

        #Paramters
        Write-Verbose "Asking for Domain Credentials to use in new Domain"
       # $domaincred=Get-Credential 

        $dscuri="https://github.com/mgodfre3/Single-Node-POC/blob/main/Single-NodeHCI/SingleNodeHCI.zip?raw=true"

        New-item -Path "C:\" -ItemType Directory -Name DSCConfigs
        Invoke-WebRequest -Uri $dscuri -OutFile C:\DSCConfigs\SingleNodeHCI.zip
        Expand-Archive C:\DSCConfigs\SingleNodeHCI.zip -DestinationPath C:\DSCConfigs -Force 

}



#Step 2B
#Copy Modules to C:
Invoke-Command -ComputerName 10.50.10.253 -Credential $localcreds -ScriptBlock {
        Write-Verbose "Copying Required Modules to Local Powershell Folder"

        $modulepath="$env:SystemDrive\Program Files\WindowsPowerShell\Modules"
        get-childitem C:\DSCConfigs\Modules\ | copy-item -Destination $modulepath -Recurse -Force  

}


#step 2c ##
Invoke-Command -ComputerName 10.50.10.253 -Credential $localcreds -ScriptBlock {
        $server2019_uri="https://aka.ms/AAgscek"
        New-Item -Path C:\ -Name HCIVHDs -ItemType Directory
        $testpath=(Test-Path "C:\hcivms\Gui.vhdx")
        if ($testpath -eq $null){
        Invoke-webrequest -URI $server2019_uri -OutFile C:\HCIVHDs\GUI.vhdx
        }

        else {Write-Verbose "The Sysprepd Server VHD already exists"
        }

        New-Item -Path C:\ -Name VMS\ContosoDC\VHD -ItemType Directory
        New-VHD -Path C:\vms\ContosoDC\vhd\ContosoDC-OS.vhdx -ParentPath C:\HCIVHDs\GUI.vhdx  -Differencing

        Mount-VHD C:\vms\ContosoDC\vhd\ContosoDC-OS.vhdx
        Get-Volume | Where-Object {$_.size -gt 90GB -and $_.DriveLetter -eq $null} | Get-Partition | Set-Partition -NewDriveLetter v

        $dcmofuri="https://github.com/mgodfre3/Single-Node-POC/blob/main/ContosoDC/ContosoDC.zip?raw=true"
        New-Item -Name Temp -Path C:\ -ItemType Directory
        Invoke-WebRequest -Uri $dcmofuri -OutFile c:\temp\ContosoDC.zip
        Expand-Archive C:\temp\ContosoDC.zip -DestinationPath C:\temp -Force
        Copy-item C:\Temp\ContosoDC.mof -Destination "v:\Windows\System32\Configuration\pending.mof"
        Get-ChildItem C:\temp\Modules | Copy-item  -Destination "V:\Program Files\WindowsPowerShell\Modules" -Force -Recurse
        Dismount-vhd C:\vms\ContosoDC\vhd\ContosoDC-OS.vhdx
    }






## Step 2D

#Create MOF
Invoke-Command -ComputerName 10.50.10.253 -Credential $localcreds -ScriptBlock {
. C:\DSCCOnfigs\SingleNodeHCI.ps1
Write-Verbose "Compling MOF File"
SingleNodeHCI -ConfigurationData $configdata -OutputPath C:\DSCConfigs\DSC\SingleNodeHCI\SingleNodeHCI\

Start-DscConfiguration -Path C:\DSCConfigs\DSC\SingleNodeHCI\SingleNodeHCI\ -Wait -Force 
}
