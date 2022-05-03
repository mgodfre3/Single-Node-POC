### Welcome to Single Node ASHCI Deployment with No Domain ### 

This package of scripts will help you to deploy a Single Node Stak HCI Cluster with no requimements for a Domain Controller.

#### Requirments ####
You will need to complete this install:
A x86 Server with :
2 Processors
64 GB of Memory
1  SSD or NVME for the Operating System (40GB+)
2 SSD or NVME 100GB+ for Data
1 1GBe or better Network Card

A Windows  Workstation with Network Access to the Physical Host

PowerShell 7.2

Copy of Azure Stack HCI OS

Drivers for your Hardware

Routable Network that has Internet Access, or Required Firewalls for Azure Stack HCI. It is suggested to use a /24 Subnet if possiable.



#### Step 1 ####
Install Azure Stack HCI OS and Drivers on Phyiscal Hardware.

In OS, Please Set Public Firewall Profile to disabled, to allow Remote Management with Local Credentials (if workstation is not in same subnet) 

```{Powershell}
Set-NetfirewallProfile -Name Public -Enabled:false 
```

Please note the IP Address of the Node, or provide a Static IP Address Assignment.


### Step 2 ####
On your Windows Workstation open the SingleNodeBuild-Step1.ps1 in PowerShell ISE and edit the Parameters for your network.

Include the Name of the New HCI Node and the IP Address from Step 1.

Run the Script after updating the Paramters, and the node should reboot.


#### Step 3 ####
On your Windows Workstation open the SingleNodeBuild-Step2.ps1 in PowerShell ISE and edit the Parameters for your environment.


Run the Script after updating the Paramters, this will prompt you for your Azure Active Directory Account with the correct Permissisons to Register the HCI Resource, as well as build the cluster.



