
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

#Create MOF

. C:\DSCCOnfigs\SingleNodeHCI.ps1
Write-Verbose "Compling MOF File"
SingleNodeHCI -ConfigurationData $configdata 

Start-DscConfiguration -Path C:\DSCConfigs\DSC\SingleNodeHCI\SingleNodeHCI\ -Wait -Force 

