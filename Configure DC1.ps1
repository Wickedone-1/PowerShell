#CNE 270
#
#Script for creating lab environment
#
#Requirements:  Virtual machines:
    #Windows Server 2016 evaluation
        #https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2016/
    
    #Windows 10 Enterprise evaluation
        #https://www.microsoft.com/en-us/evalcenter/evaluate-windows-10-enterprise
    
    #Setup Files located at c:\LabSetup
    mkdir c:\LabSetup

#Build VMs in VMware Workstation Player using the following defaults:
    #Default 60GB HD
    #1 Processor
    #2GB RAM (if the host system can cope)
    
#Install Windows Server 2016 on DC1 and complete OOBE setup
    
#region - To name the computer, run the following 2 lines of code on DC1:
        Rename-Computer -NewName DC1
        Restart-Computer 
#endregion

#region - To set IP, Timezone, Install AD and DNS, run the following region of code on DC1

    #Set IP Address
        New-NetIPAddress -IPAddress 192.168.12.3 `
        -PrefixLength 24 `
        -DefaultGateway 192.168.12.2 `
        -InterfaceAlias Ethernet0
    #Set TimeZone
        Tzutil.exe /s "Pacific Standard Time"
    #Install AD & DNS
       #Install ADDS Role and Mgt Tools
        Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
       ##Import ADDSDeployment Module
        Import-Module ADDSDeployment
       ##Install a new AD Forest
        Install-ADDSForest `
	        -CreateDnsDelegation:$false `
	        -DatabasePath "C:\Windows\NTDS" `
	        -DomainMode "WinThreshold" `
	        -DomainName "cne270.pri" `
	        -DomainNetbiosName "cne270" `
	        -ForestMode "WinThreshold" `
	        -InstallDns:$true `
	        -LogPath "C:\Windows\NTDS" `
	        -NoRebootOnCompletion:$false `
	        -SysvolPath "C:\Windows\SYSVOL" `
	        -Force:$true
#endregion

#region DNS,DHCP, File Shares, and AD Objects     
    #Set DNS Forwarder
        Set-DnsServerForwarder -IPAddress 8.8.8.8 -ComputerName DC1
    #Install DHCP
        Install-WindowsFeature -ComputerName DC1 -Name DHCP -IncludeManagementTools
    
    #Complete Post Configuration
        #Create DHCP Security Groups (DHCP Administrators and DHCP Users) 
        #Members of the DHCP Administrators group have administrative access to the DHCP Server service.
        #Members of the DHCP Users group have read-only access to the DHCP Server service.
        #Both the DHCP Administrators group and DHCP Users group are created automatically when the DHCP
        #server role is installed using Server Manager.
        netsh dhcp add securitygroups

        #Add Server to Active 
        #After installing the DHCP role on Windows Server 2016 (or earlier versions), one of the first actions that will need 
        #to be completed is to authorize the server in the Active Directory infrastructure.This action is necessary so that the 
        #DHCP Server will distribute IP addresses to Active Directory clients. Otherwise, if a DHCP Server is unauthorized, 
        #the IP address distribution will stop. 
        #When the DHCP role is installed on a Domain Controller, then the server is automatically authorized. When it is installed 
        #on a member server, the authorization process must be performed
        #As this machine is a DC, the following step is not really necessary
        Add-DhcpServerInDC -IPAddress 192.168.12.3 -DnsName dc1.cne270.pri
    
    #Create Initial Scope for 192.168.12.0 subnet
        Add-DhcpServerv4Scope -Name 'Production Scope' `
            -ComputerName DC1.cne270.pri `
            -StartRange 192.168.12.50 `
            -EndRange 192.168.12.100 `
            -SubnetMask 255.255.255.0 `
            -LeaseDuration 08:00:00
        
    #Sets IPv4 option values (at the server, scope, or reservation level). Here we set Default Gateway (-router) and
    #DNS Server options for the scope
        set-DhcpServerv4OptionValue `
            -ScopeId 192.168.12.0 `
            -ComputerName DC1.cne270.pri `
            -DnsDomain cne270.pri `
            -router 192.168.12.2 `
            -DnsServer 192.168.12.3

    #Create \\dc1\LabSetup share
    New-SmbShare -Path c:\LabSetup -Name LabSetup -FullAccess 'cne270\domain users'

    #Add Printers
        Add-PrinterDriver -Name 'Dell 1130 Laser Printer' -ComputerName DC1 -Verbose

        Add-Printer `
            -Name 'Printer1' `
            -PortName 'file:' `
            -Comment 'Phantom Printer' `
            -DriverName 'Dell 1130 Laser Printer' `
            -ComputerName DC1 `
            -Shared -ShareName 'Printer1'

        Add-Printer `
            -Name 'Printer2' `
            -PortName 'LPT2:' `
            -Comment 'Phantom Printer' `
            -DriverName 'Dell 1130 Laser Printer' `
            -ComputerName DC1 `
            -Shared -ShareName 'Printer2'
    #Add AD Objects
        #Add OUs
        New-ADOrganizationalUnit `
            -Name MyCompany `
            -path "DC=cne270,DC=pri"
        New-ADOrganizationalUnit `
            -Name Seattle `
            -Path "OU=MyCompany,DC=cne270,DC=pri"
        New-ADOrganizationalUnit `
            -Name Puyallup `
            -path "OU=MyCompany,DC=cne270,DC=pri"
        New-ADOrganizationalUnit `
            -name Computers `
            -path "OU=Puyallup,OU=MyCompany,DC=cne270,DC=pri"
        New-ADOrganizationalUnit `
            -Name Users `
            -Path "OU=Puyallup,OU=MyCompany,DC=cne270,DC=pri"
        New-ADOrganizationalUnit `
            -Name Member-Servers `
            -path "Ou=Computers,OU=Puyallup,OU=MyCompany,DC=cne270,DC=pri"
        #Add Users
        c:\LabSetup\CreateUsers.ps1
#endregion

#region Verify
    cls
    Get-ADObject -SearchBase "OU=MyCompany,DC=cne270,DC=pri" -Filter * | Format-Table
    get-printer | Format-Table
    get-smbshare -Name LabSetup 
    Get-DhcpServerv4Scope | Format-Table
	ping 8.8.8.8
#endregion