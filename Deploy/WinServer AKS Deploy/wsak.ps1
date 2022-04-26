
# Parameter help description
[Parameter(Mandatory)]
[String]$password

[Parameter(Mandatory)]
[String]$ResourceGroupName

[Parameter(Mandatory)]
[String]$AKSClusterName

# Functions # 
function  Create-SecurePassword {
    param (
        $password
    )
    if ($password -eq "true"){
            $spw=ConvertTo-SecureString -String $password -AsPlainText -Force
        }
}


Function Get-AZCreds {
#Set Azure Context 
$azcred=Get-AzContext

if (-not (Get-AzContext)){
    $azcred=Login-AzAccount -UseDeviceAuthentication
}

#select context
$context=Get-AzContext -ListAvailable
if (($context).count -gt 1){
    $context=$context | Out-GridView -OutputMode Single
    $context | Set-AzContext
}

#location (all locations where HostPool can be created)
$region=(Get-AzLocation | Where-Object Providers -Contains "Microsoft.DesktopVirtualization" | Out-GridView -OutputMode Single -Title "Please select Location for AVD Host Pool metadata").Location
}

function Install-AKS {
    param (
        OptionalParameters
    )
    New-AzAksCluster -ResourceGroupName $ResourceGroupName -Name $AKSClusterName -NodeCount 2 -NetworkPlugin azure -NodeVmSetType VirtualMachineScaleSets -WindowsProfileAdminUserName $Username -WindowsProfileAdminUserPassword $Password
}

##

