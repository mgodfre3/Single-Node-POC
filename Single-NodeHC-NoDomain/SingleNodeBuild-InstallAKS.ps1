#Set Variables for Install
$aksvar= @{
    HostList="10.50.10.202"
    AKSvnetname = "vnet1"
    AKSvSwitchName = "HCI-Uplink"
    AKSNodeStartIP = "10.50.10.25"
    AKSNodeEndIP = "10.50.10.100"
    AKSVIPStartIP = "10.50.10.125"
    AKSVIPEndIP = "10.50.10.200"
    AKSIPPrefix = "10.50.10.0/24"
    AKSGWIP = "10.50.10.1"
    AKSDNSIP = "10.50.10.1"
    AKSCSV="C:\ClusterStorage\Volume 1"
    AKSImagedir = "C:\ClusterStorage\Volume 1\aks\Images"
    AKSWorkingdir = "C:\ClusterStorage\Volume 1\aks\Workdir"
    AKSCloudConfigdir = "C:\ClusterStorage\Volume 1\aks\CloudConfig"
    AKSCloudSvcidr = "10.50.10.204/24"
    AKSCloudAgentName="CA-CloudAgent"
    AKSVlanID="0"
    AKSResourceGroupName = "ASHCI-Nested-AKS"


}
##Local Admin Credentials
$LocalCreds=Get-Credential -UserName "SAHCI\Administrator" -Message "Local Credentials"


## Azure  Credentials ##

#login to Azure
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
        $region=(Get-AzLocation | Where-Object Providers -Contains "Microsoft.DesktopVirtualization"



##Install AKS onto the Cluster ##

#Install latest versions of Nuget and PowershellGet

    
  Write-Host "Install latest versions of Nuget and PowershellGet" -ForegroundColor Green -BackgroundColor Black

    
        Enable-PSRemoting -Force
        Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted
        Install-PackageProvider -Name NuGet -Force 
        Install-Module -Name PowershellGet -Force -Confirm:$false
        
 
     Write-Host -ForegroundColor Green -BackgroundColor Black "Install necessary AZ modules plus AksHCI module and initialize akshci on each node"
    #Install necessary AZ modules plus AksHCI module and initialize akshci on each node
    
        Write-Host "Installing Required Modules" -ForegroundColor Green -BackgroundColor Black
        Enable-PSRemoting -Force
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
      
        $ModuleNames="Az.Resources","Az.Accounts", "AzureAD", "AKSHCI"
        foreach ($ModuleName in $ModuleNames){
            if (!(Get-InstalledModule -Name $ModuleName -ErrorAction Ignore)){
                Install-Module -Name $ModuleName -Force -AcceptLicense 
            }
        }
        Import-Module Az.Accounts
        Import-Module Az.Resources
        Import-Module AzureAD
        Import-Module AksHci
        #Initialize-akshcinode
        
    
    Write-Host "Prepping AKS Install" -ForegroundColor Green -BackgroundColor Black
    #Install AksHci - only need to perform the following on one of the nodes
    
        $vnet = New-AksHciNetworkSetting -name $using:aksvar.AKSvnetname -vSwitchName $using:aksvar.AKSvSwitchName -k8sNodeIpPoolStart $using:aksvar.AKSNodeStartIP -k8sNodeIpPoolEnd $using:aksvar.AKSNodeEndIP -vipPoolStart $using:aksvar.AKSVIPStartIP -vipPoolEnd $using:aksvar.AKSVIPEndIP -ipAddressPrefix $using:aksvar.AKSIPPrefix -gateway $using:aksvar.AKSGWIP -dnsServers $using:aksvar.AKSDNSIP -vlanID $aksvar.vlanid        
        Set-AksHciConfig -imageDir $using:aksvar.AKSImagedir -workingDir $using:aksvar.AKSWorkingdir -cloudConfigLocation $using:aksvar.AKSCloudConfigdir -vnet $vnet -cloudservicecidr $using:aksvar.AKSCloudSvcidr -clusterRoleName $aksvar.AKSCloudAgentName
        $cloudFqdnIP = $AKSCloudSvcidr.Substring(0,($AKSCloudSvcidr.IndexOf("/")))
        Set-MocConfigValue -Name "cloudFqdn" -value "$cloudFqdnIP"
        $hostsEntry = "$cloudFqdnIP $AKSCloudAgentName"
        Out-File -FilePath C:\Windows\system32\drivers\etc\hosts -Append -Encoding utf8 -InputObject $hostsEntry
        $azurecred=Connect-AzAccount -UseDeviceAuthentication
        $armtoken = Get-AzAccessToken
        $graphtoken = Get-AzAccessToken -ResourceTypeName AadGraph
        Set-AksHciRegistration -subscriptionId $azurecred.Context.Subscription.Id -resourceGroupName $using:aksvar.AKSResourceGroupName -AccountId $azurecred.Context.Account.Id -ArmAccessToken $armtoken.Token -GraphAccessToken $graphtoken.Token
        Write-Host -ForegroundColor Green -Object "Ready to Install AKS on HCI Cluster"
        Install-AksHci 
    
