
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



$dscuri="https://github.com/mgodfre3/Single-Node-POC/blob/main/Single-NodeHCI.zip?raw=true"

New-item -Path "C:\" -ItemType Directory -Name DSCConfigs
Invoke-WebRequest -Uri $dscuri -OutFile C:\DSCConfigs\Single-NodeHCI
Expand-Archive C:\DSCConfigs\Single-NodeHCI.zip -DestinationPath C:\DSCConfigs 

#Copy Modules to C:


#Create MOF


Start-DscConfiguration -Path C:\DSCConfigs\Single-NodeHCI -Wait -Force 

