#region Build Windows 10 Client - Client1
    #
    Rename-Computer -NewName Client1
    Restart-Computer

    Add-computer -DomainName Changeme!.pri -Credential (Get-Credential -Message "Enter Username and Password of Domain Administrator Account") #Changes needed
    Restart-Computer
#endregion

#Create a CIM Session for remoting to server
help about_cimsession

#Create Variable for cimsession
#The PowerShell command below ASSUMES that Server1 has acquired the IP address 192.168.12.51 from DHCP. 
#Check whether this is the correct address for Server1 before using it in the command below.
#The command below will fail. Read the error message it produces.
$cimsession = New-CimSession -Credential (Get-Credential -Message "Enter Username and Password of the Server1 Administrator Account") -ComputerName 192.168.12.51

#If we were connecting to another computer that was a domain member, Kerberos authentication would have taken 
#care of creating the cimsession. But the remote machine is not a domain member, so it must be added to this 
#machine's TrustedHosts list. Run the first Get-Item command below to show that the TrustedHosts list is empty. 
#Then run the Set-Item command below to add all machines to the TrustedHosts list. After running Set-Item, run 
#Get-Item again to observe the change to the trusted hosts list. Then run the New-CimSession command (above)  
#again. It should now work.
Get-Item WSMAN:\localhost\Client\TrustedHosts
#The previous command prompts you to start WinRM. However, it doesn't work, hence the next command. 
Start-Service WinRM
Set-Item WSMAN:\localhost\Client\TrustedHosts -Value *
Enable-PSRemoting  #needed to open filewall for remote commands in later labs

#Get the IP Configuration of the Remote Machine and note the value of the Interface Index property in the 
#response (for use in the New-NetIPAddress command below)
Get-NetIPConfiguration -CimSession $cimsession

#Set the IP Configuration on the remote system using a static address
New-NetIPAddress `
-CimSession $cimsession `
-IPAddress 192.168.12.4 `
-PrefixLength 24 `
-DefaultGateway 192.168.12.2 `
-InterfaceIndex 5 #Warning: It may not be 5 - use value discovered from previous Get-NetIPConfiguration command

#Get the IP Configuration of the Remote Machine. The command will fail because we have changed the remote machine's 
#IP address and our cimsession object still connects to the old address.
Get-NetIPConfiguration -CimSession $cimsession

#Reconnect to remote machine using its new address
$cimsession = New-CimSession -Credential (get-credential -Message "Enter Username and Password of the Server1 Administrator Account") -ComputerName 192.168.12.4

#Get the IP Configuration of the Remote Machine.
Get-NetIPConfiguration -CimSession $cimsession

#Note that because the New-NetIPAddress disabled getting the address from DHCP, the IP configuration does not
#include the address of a DNS server. Redo the Get-NetIPConfiguration command after this one to see the effect.
Set-DnsClientServerAddress `
-CimSession $cimsession `
-InterfaceIndex 5 `
-ServerAddresses 192.168.12.3

#Rename Server to Server1. The following command will start a remote PowerShell seession on the remote machine.
#The commands below must be entered manually at the remote prompt.
Enter-PSSession -ComputerName 192.168.12.4 -Credential (Get-Credential -Message "Enter Username and Password of the Server1 Administrator Account")
 	#hostname
    #Rename-Computer -NewName Server1
    #Set Time Zone
    #Tzutil.exe /?
    #Tzutil.exe /g
    #Tzutil.exe /s "Pacific Standard Time"
    #Restart-Computer -Force

#Domain Join Server1
#Note that $using:cred (below) lets us use the $cred variable, which was created on the local 
#machine,in a command running on the remote machine, where the $cred variable does not exist.
#Enter the credential for the Domain system (i.e. cne270\Administrator)
$cred = Get-Credential -Message "Enter Username and Password of the Server1 Administrator Account"
Invoke-Command `
-ComputerName 192.168.12.4 `
-Credential $cred `
-scriptblock {Add-Computer -DomainName Changeme!.pri -Credential $using:cred -Restart}   #Changes needed 
 

#Verify that Server1 has been added in to the domain. The -Credential parameter may be omitted if
#you are already logged into this (Client1) machine as the cne270 domain administrator.
#If the following command is not recognized, you probably failed to install RSAT Active Directory Domain 
#Services and Lightweight Directory Services Tools at the start of this lab.
Get-ADComputer -Credential (Get-Credential "Changeme!\Administrator") -Filter * | Format-Table #Changes needed
