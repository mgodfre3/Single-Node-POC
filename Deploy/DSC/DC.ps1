 <#
   
$ComputerName = "ContosoDC"  
$Password = "Password01"  
$DomainName = "Contoso.com"  
  
#Encrypt Passwords  
$Cred = ConvertTo-SecureString -String $Password -Force -AsPlainText  
$DomainCredential = New-Object System.Management.Automation.PSCredential ("$(($DomainName -split '\.')[0])\Administrator", $Cred)  
$DSRMpassword = New-Object System.Management.Automation.PSCredential ('No UserName', $Cred)  
 #>
 
Configuration DomainController {  
  param (  
    [Parameter(Mandatory)]   
    [PSCredential]$DomainCredential,  
    [Parameter(Mandatory)]   
    [PSCredential]$DSRMpassword  
  )  

  Import-DscResource -ModuleName "xActiveDirectory"  
  Node $ComputerName {  
     #Install Active Directory role and required tools  
    
     WindowsFeature ActiveDirectory {  
      Ensure = 'Present'  
      Name = 'AD-Domain-Services'  
    }  
    
    WindowsFeature ActiveDirectoryTools {  
      Ensure = 'Present'  
      Name = 'RSAT-AD-Tools'  
      DependsOn = "[WindowsFeature]ActiveDirectory"  
    }  
    
    WindowsFeature DNSServerTools {  
      Ensure = 'Present'  
      Name = 'RSAT-DNS-Server'  
      DependsOn = "[WindowsFeature]ActiveDirectoryTools"  
    }  
    
    WindowsFeature ActiveDirectoryPowershell {  
      Ensure = "Present"  
      Name  = "RSAT-AD-PowerShell"  
      DependsOn = "[WindowsFeature]DNSServerTools"  
    }  
    
    #Configure Active Directory Role   
    
     xADDomain RootDomain {  
      Domainname = $DomainName  
      SafemodeAdministratorPassword = $DSRMpassword  
      DomainAdministratorCredential = $DomainCredential  
      #DomainNetbiosName = ($DomainName -split '\.')[0]  
      DependsOn = "[WindowsFeature]ActiveDirectory", "[WindowsFeature]ActiveDirectoryPowershell"  
    }  
    
    #LCM Configuration  
    
    LocalConfigurationManager {        
      ActionAfterReboot = 'ContinueConfiguration'        
      ConfigurationMode = 'ApplyOnly'        
      RebootNodeIfNeeded = $true        
    }        
  }  
}  
 