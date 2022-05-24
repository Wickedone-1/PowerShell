# Administering Active Directory
#region 1 - Add Active Directory Role to Server1 and make it a Domain Controller

    #Install AD
    Install-WindowsFeature -ComputerName Server1 -Name AD-Domain-Services
    Enter-PSSession -ComputerName Server1
    Get-Command -Module ADDSDeployment

    #Promote to a Domain Controller
    Install-ADDSDomainController `
        -Credential (Get-Credential "Changeme!\Administrator" -Message 'Enter Domain Administrator Credentials') `  #Changes needed
        -InstallDns:$True `
        -DomainName 'Changeme!.pri' `                         #Changes needed
        -DatabasePath 'C:\Windows\NTDS' `
        -LogPath 'C:\Windows\NTDS' `
        -SysvolPath 'C:\Windows\SYSVOL' `
        -NoGlobalCatalog:$false `
        -SiteName 'Default-First-Site-Name' `
        -NoRebootOnCompletion:$False `
        -Force
    Exit-PSSession
    
    #Check that Server1 is one of the Domain Controllers in the Domain
    Get-DnsServerResourceRecord -ComputerName Server1 -ZoneName changeme!.pri -RRType NS                #changes needed
    Get-ADDomainController -Filter * -Server Server1 |
        Format-Table Name,ComputerObjectDN,IsGlobalCatalog
#endregion 1

#region 2 - Gather Information from Active Directory
    #View AD Hierarchy
    Get-ADObject -Filter * | Format-Table name,objectclass
    
    Get-ADObject -Filter {ObjectClass -eq "OrganizationalUnit"}
    
    Get-ADObject -SearchBase 'OU=MyCompany,DC=changeme!,DC=pri' `                           #Changes needed
        -Filter {ObjectClass -eq "OrganizationalUnit"}|
        Format-Table Name,DistinguishedName -AutoSize
    
    #Find Objects
    Get-ADObject -Filter * | Get-Member  
    
    Get-ADObject -Filter * -Properties * | Get-Member # -Properties * exposes extended Properties
    
    Get-ADObject -Filter {(name -like '*mbtest*') -and (ObjectClass -eq 'user')} -Properties *|
        ft Name,DistinguishedName
    
    #Find specific user objects
    Get-ADObject `
        -Identity 'CN=JamaG,OU=Users,OU=Puyallup,OU=MyCompany,DC=changeme!,DC=pri' `                  #Changes needed
        -Properties * | FL

    Get-ADObject -Filter {SamAccountName -eq 'mbadmin'} -Properties * | FL

    #Add OU for Users and Computer under the Seattle OU
    New-ADOrganizationalUnit `
        -Name Users `
        -Path 'OU=Seattle,OU=MyCompany,DC=changeme!,DC=pri' `                                    #Changes needed
        -Verbose
    
    New-ADOrganizationalUnit `
        -Name Computers `
        -Path 'OU=Seattle,OU=MyCompany,DC=changeme!,DC=pri' `                               #Changes needed!
        -Verbose
    
    Get-ADObject -SearchBase 'OU=MyCompany,DC=changeme!,DC=pri' `                               #Changes needed
        -Filter {ObjectClass -eq "OrganizationalUnit"}
#endregion 2

#region 3 - users

#Get User Information
Get-ADUser -Filter * -Properties *| gm

Get-ADUser -Filter * -Properties *| fl Name,DistinguishedName,City

Get-ADUser -Filter * -SearchBase 'OU=MyCompany,DC=changeme!,DC=pri'|                              #changes needed
     ft Name,DistinguishedName -AutoSize

Get-ADUser -Filter {Name -like '*jama*'}  -Properties * |
 ft Name,DistinguishedName -AutoSize

Get-ADUser -Identity 'mbadmin' -Properties *

#Find all users in Puyallup and in IT department; Export to CSV file 

New-Item -ItemType Directory c:\Text
Get-ADUser -Filter {(City -eq 'Puyallup') -and (Department -eq 'IT')} -Properties *|
    Select-Object Name,City,Enabled,EmailAddress|
    Export-Csv -Path C:\Text\PuyallupItUsers.csv

notepad C:\Text\PuyallupItUsers.csv

#Create a new user with PowerShell
$SetPass = Read-Host -Prompt "Enter password for New Account:" -AsSecureString
New-ADUser `
	-Server DC1 `
	-Path 'OU=Users,OU=Puyallup,OU=MyCompany,DC=changeme!,DC=pri' `                              #Changes needed
	-department IT `
	-SamAccountName MaryB `
	-Name MaryB `
	-Surname Bedel `
	-GivenName Mary `
	-UserPrincipalName MaryB@changeme!.pri `                                        #Changes needed
	-City Puyallup `
	-AccountPassword $setpass `
	-ChangePasswordAtLogon $True `
	-Enabled $False -Verbose 

Get-ADUser -Identity 'MaryB'

#Modify single user object
Set-ADuser -Identity 'MaryB' -Enabled $True -Description 'Mary is an IT user' -Title 'IT User'
Get-ADUser -Identity 'MaryB' -Properties *| FL Name,Description,Title,Enabled

#Modify All existing users whose state is blank to change state to Washington by piping list
#of blank-state users into Set-ADUser cmdlet
#
#check users before changing the state to "WA"
Get-ADUser  `
    -filter { -not( State -like '*') } `
    -SearchBase 'OU=MyCompany,DC=Changeme!,DC=pri' -SearchScope Subtree -Properties *|                          #Changes needed
    Format-Table Name,SamAccountName,State

#change the state 
Get-ADUser  `
    -filter { -not( State -like '*') } `
    -SearchBase 'OU=MyCompany,DC=changeme!,DC=pri' -SearchScope Subtree|                       #Changes needed
    Set-ADUser -State 'WA' -Verbose

#check users after changing the state to "WA" 
Get-ADUser -Filter {State -eq 'WA'} -Properties *|
        Format-Table name,SamAccountName,State

#Find users whose accounts are disabled, then enable them
    Get-ADUser -Filter {Enabled -eq $false} `
        -SearchBase 'OU=Users,OU=Puyallup,OU=MyCompany,DC=changeme!,DC=pri'|                    #Changes needed
        ft Name,SamAccountName,Enabled -AutoSize

    Get-ADUser -Filter {enabled -eq $false} `
        -SearchBase 'OU=Users,OU=Puyallup,OU=MyCompany,DC=changeme!,DC=pri'|                     #Changes needed
        Set-ADUser -Enabled $true

    Get-ADUser -Filter * `
        -SearchBase 'OU=Users,OU=Puyallup,OU=MyCompany,DC=changeme!,DC=pri'|                     #changes needed
        ft Name,SamAccountName,Enabled -AutoSize

#Determine status of LockedOut Account (there are no locked accounts in our case!)
    Search-ADAccount -LockedOut | select Name  
        
    Unlock-ADAccount -Identity 'mbtest'

#Reset Password - skip (because I won't remember new password!)
    $newPassword = (Read-Host -Prompt "Provide New Password" -AsSecureString)
#    Set-ADAccountPassword -Identity mbtest -NewPassword $newPassword -Reset
#    Set-ADuser -Identity mbtest -ChangePasswordAtLogon $True

#endregion 3

#region 4 - Computers

#Find all the computers in the domain
Get-ADComputer -Filter * -Properties * |ft Name,DNSHostName,OperatingSystem

Get-ADComputer -Filter {OperatingSystem -eq 'Windows 10 Enterprise Evaluation'} -Properties *|
    ft Name,DNSHostName,OperatingSystem

#View information for Server1
Get-ADComputer -Identity 'Server1' -Properties *

#Modify Description of a Computer. The -PassThru parameter causes the return of an ADComputer 
#object. By default, the Set-ADComputer cmdlet does not generate any output
Set-ADComputer -Identity 'Server1' -Description 'This is a Server for App/Dev Testing' -PassThru| 
    Get-ADComputer -Properties * | ft Name,DNSHostName,Description

#Move computer to OU
Get-ADComputer -Identity Server1 |
    Move-ADObject -TargetPath 'OU=Computers,OU=Seattle,OU=MyCompany,DC=Changeme!,DC=pri'                #Changes needed!

Get-ADComputer -Identity Server1 -Properties * | FT Name,DistinguishedName
#endregion 4

#region 5 - Groups
#View all Groups
Get-ADGroup -Filter * -Properties *| FT Name,Description -AutoSize -Wrap

#View Specific Group
Get-ADGroup -Identity 'Domain Users' -Properties *

#create a new group for IT users
New-ADGroup `
    -Name 'IT Users' `
    -GroupCategory Security `
    -GroupScope Global

Set-ADGroup -Identity 'IT Users' -Description 'This is a group for IT Users'

Get-ADGroup -Identity 'IT Users' -Properties * | fl Name,Description

#View Group Membership of Group
Get-ADGroupMember -Identity 'Domain Users'|ft Name

#Add Users to Group for IT
Get-ADGroupMember -Identity 'IT Users'

Add-ADGroupMember `
    -Identity 'IT Users' `
    -Members (get-aduser -Filter {department -eq 'IT'})

Get-ADGroupMember -Identity 'IT Users'|ft Name

#Remove IT Users Group
Remove-ADGroup -Identity 'IT Users'

#endregion 5
