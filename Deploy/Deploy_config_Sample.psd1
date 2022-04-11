

@{


    # This is the PowerShell datafile used to provide configuration information for the Azure Stack HCI Cluster Deployment.
    
    # Version 1.0.0
    
    #Node Parameters
    Node01 = "sahci" #Set Short Name for Node01
    
    
    node01_MgmtIP="" #Set MGMT IP address for Node01
    
    MGMTSubnet="" #Please provide MGMT Subnet
    GWIP = "" #Set Default Gateway IP for MGMT Network
    
    ADDomain = "contoso.com" #Please provide domain FQDN
    DNSIP = "1.1.1.1" #Set DNS IP(s) for DNS servers i.e. Domain Controllers
    
    #Cluster Paramters
    ClusterName = "sahcicl" #Set Short name of Cluster. This account can be Prestaged in Active Directory, just make sure it is "Disabled."
    ClusterIP = "" #Provide Cluster IP Address
    
    #Storage Spaces Direct Paramters
    StoragePoolName= "SAHCICL Storage Pool 1" #Provide Desired Friendly name of Storage Pool
    
    CSVFriendlyname="Volume01" #Provide First Cluster Shared Volume Friendly Name, this will be created as a Nested-2-Way Mirror Volume by default.
    CSVSize=100GB #Size in GB of First Cluster Shared Volume, Remember Nested-2 Way Mirror is a Storage Efficency of 25%, so 1 TB uses 4 TB of the Storage Pool.
    
    #######################################################################################
        #AKS-HCI parameters
        AKSEnable="true" #Provide True or False if you would like to deploy AKS.  See for more info https://docs.microsoft.com/en-us/azure-stack/aks-hci/system-requirements?tabs=allow-table
        AKSvnetname = "aksvnet" #provide AKS VNet name
        AKSvSwitchName = "ConvergedSwitch(hci)" #Default Name if you used Deployment Script As Is.
        AKSNodeStartIP = "" #Provide IP for AKS Node Pool Start
        AKSNodeEndIP = "" #Provide  IP for AKS Node Pool End
        AKSVIPStartIP = "" #Provide IP for VIP Pool Start in AKS VLAN
        AKSVIPEndIP = ""#Provide IP for VIP Pool end
        AKSIPPrefix = "" #Provide CIDR notation of AKS Vlan ex. "10.10.10.0/24"
        AKSGWIP = "" #Provide GW IP addess of AKS Vlan
        AKSDNSIP = "" #Provide DNS IP Addresses, seperated by commas
        AKSImagedir = "c:\clusterstorage\Volume01\Images"
        AKSWorkingdir = "c:\clusterstorage\Volume01\Workdir"
        AKSCloudConfigdir = "c:\clusterstorage\Volume01\Config"
        AKSCloudSvcidr = "" #Needs to be an IP in the MGMT Vlan
        AKSResourceGroupName = "sahcicl-aks-rg"
        AKSVLanID="" #Provide VLAN Tag ID, please ensure this vlan is trunked to the Physical Ports being used for the vSwitch used above.
    
    #########################SET ALL  Azure VARIABLES########################### 
    
    AzureSubID = "" #Please Provide Subscription ID Number for Azure Subscription
    
    
    }
    
    
    