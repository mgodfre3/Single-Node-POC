
<#
Install-PackageProvider -Name NuGet -Force 
Install-Module -Name PowershellGet -Force -Confirm:$false
Install-Module -Name 'PSDesiredStateConfiguration' -Force 
Install-Module -Name 'xPSDesiredStateConfiguration' -Force
Install-Module -Name 'xCredSSP' -Force
Install-Module -Name 'DSCR_Shortcut' -Force
Install-Module -Name 'xHyper-V' -Force
Install-Module -Name 'NetworkingDSC' -Force
#>


#Paramters
Write-Verbose "Asking for Domain Credentials to use in new Domain"
$domaincred=Get-Credential 

$dscuri="https://github.com/mgodfre3/Single-Node-POC/blob/main/Single-NodeHCI/SingleNodeHCI.zip?raw=true"

New-item -Path "C:\" -ItemType Directory -Name DSCConfigs
Invoke-WebRequest -Uri $dscuri -OutFile C:\DSCConfigs\SingleNodeHCI.zip
Expand-Archive C:\DSCConfigs\SingleNodeHCI.zip -DestinationPath C:\DSCConfigs 

#Copy Modules to C:
Write-Verbose "Copying Required Modules to Local Powershell Folder"

$modulepath="$env:SystemDrive\Program Files\WindowsPowerShell\Modules"
Copy-Item C:\DSCConfigs\Modules -Destination $modulepath -Recurse -Force  

Install-WindowsFeature Hyper-V-Powershell
Install-WindowsFeature Hyper-V -Restart 


$server2019_uri="https://aka.ms/AAgscek"
New-Item -Path C:\ -Name VMS\ContosoDC\VHD -ItemType Directory
New-VHD -Path C:\vms\ContosoDC\vhd\ContosoDC-OS.vhdx -ParentPath C:\HCIVHDs\GUI.vhdx  -Differencing

Mount-VHD C:\vms\ContosoDC\vhd\ContosoDC-OS.vhdx
Get-Volume | Where-Object {$_.size -gt 90GB -and $_.DriveLetter -eq $null} | Get-Partition | Set-Partition -NewDriveLetter v

$dcmofuri="https://github.com/mgodfre3/Single-Node-POC/blob/main/ContosoDC/ContosoDC.zip?raw=true"
New-Item -Name Temp -Path C:\ -ItemType Directory
Invoke-WebRequest -Uri $dcmofuri -OutFile c:\temp\ContosoDC.zip
Expand-Archive C:\temp\ContosoDC.zip -DestinationPath C:\temp
Copy-item C:\Temp\ContosoDC.mof -Destination "v:\Windows\System32\Configuration\pending.mof"
Dismount-vhd C:\vms\ContosoDC\vhd\ContosoDC-OS.vhdx








#Create MOF

. C:\DSCCOnfigs\SingleNodeHCI.ps1
Write-Verbose "Compling MOF File"
SingleNodeHCI -ConfigurationData $configdata -OutputPath C:\DSCConfigs\DSC\SingleNodeHCI\SingleNodeHCI\

Start-DscConfiguration -Path C:\DSCConfigs\DSC\SingleNodeHCI\SingleNodeHCI\ -Wait -Force 

