@{

    # This is the PowerShell datafile used to provide configuration information for the SDN Nested lab environment. Product keys and password are not encrypted and will be available on all hosts during installation.
    
    # Version 1.0.0

    # Multiple Host Setup Parameters
    MultipleHyperVHosts                  = $false                                # Set to $true if deploying the Nested VM environment across multiple hosts. Set to $false if deploying to a single host. 
    MultipleHyperVHostNames              = @("localhost")           # (Deprecated - May work?) Array of all of the hosts which make up the Nested VM environment. Only 2 or 4 hosts supported 
    MultipleHyperVHostExternalSwitchName = "External"                          # Name of the External Hyper-V VM Switch identical on all hosts.

    # VHDX Paths 
    guiVHDXPath                          = "C:\VMs\gui.vhdx"               # This value controls the location of the GUI VHDX.              
    azsHCIVHDXPath                       = "C:\VMs\azshci.vhdx"           # This value controls the location of the Azure Stack HCI VHDX. 
    

    # SDN Lab Admin Password
    SDNAdminPassword                     = "Password01"                          # Password for all local and domain accounts. Do not include special characters in the password otherwise some unattended installs may fail.

    # VM Configuration
    HostVMPath                           = "C:\VMs"                              # This value controls the path where the Nested VMs will be stored on all hosts.
    NestedVMMemoryinGB                   = 30GB                                  # This value controls the amount of RAM for each Nested Hyper-V Host (AzSHOST1-2).
    AzSMGMTMemoryinGB                    = 16GB                                  # This value controls the amount of RAM for the AzSMGMT Nested VM which contains only the Console, Router, Admincenter, and DC VMs.
    InternalSwitch                       = "InternalSwitch"                      # Name of internal switch that the SDN Lab VMs will use in Single Host mode. This only applies when using a single host.
    ExternalSwitch                       = "HCI"

    # ProductKeys
    GUIProductKey                        = "WMDGN-G9PQG-XVVXX-R3X43-63DFG"        # Product key for Windows Server 2019 (Desktop Experience) Datacenter Installation

    # SDN Lab Domain
    SDNDomainFQDN                        = "contoso.com"                          # Limit name (not the .com) to 14 characters as the name will be used as the NetBIOS name. 
    DCName                               = "contosodc"                            # Name of the domain controller virtual machine (limit to 14 characters)


    # NAT Configuration
    natHostSubnet                        = "192.168.128.0/24"
    natHostVMSwitchName                  = "InternalNAT"
    natConfigure                         = $true
    natSubnet                            = "192.168.46.0/24"                      # This value is the subnet is the NAT router will use to route to  AzSMGMT to access the Internet. It can be any /24 subnet and is only used for routing.
    natDNS                               = "1.1.1.1"                              # DNS address for forwarding from Domain Controller. Using Cloudflare DNS.



   
    ################################################################################################################
    # Edit at your own risk. If you edit the subnets, ensure that you keep using the PreFix /24.                   #
    ################################################################################################################

    # AzSMGMT Management VM's Memory Settings
    MEM_DC                               = 2GB                                     # Memory provided for the Domain Controller VM
 



    # SDN Host IPs
    AzSMGMTIP                            = "192.168.1.11/24"

    # Physical Host Internal IP
    PhysicalHostInternalIP               = "192.168.1.20"                          # IP Address assigned to Internal Switch vNIC in a Single Host Configuration

    # SDN Lab DNS
    SDNLABDNS                            = "192.168.1.254" 

    # SDN Lab Gateway
    SDNLABRoute                          = "192.168.1.1"

    #Management IPs for Console and Domain Controller
    DCIP                                 = "192.168.1.254/24"

    # BGP Router Config
    BGPRouterIP_MGMT                     = "192.168.1.1/24"

    # VLANs

    mgmtVLAN                             = 0
    

    # Subnets
    MGMTSubnet                           = "192.168.1.0/24"

    # SDDCInstall
    SDDCInstall                          = $false 

}