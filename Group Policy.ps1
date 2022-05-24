#Group Policy Management

#region 1
#Share the c:\LabSetup\wallpaper folder with share name 'Wallpaper'
New-SmbShare -Path c:\LabSetup\Wallpaper -Name Wallpaper -FullAccess 'Changeme!\domain users'  #Changes needed

#Create the Wallpaper GPOs
New-GPO 'GPO-BasicWallpaper'
New-GPO 'GPO-BeachWallpaper'
New-GPO 'GPO-RockWallpaper'
New-GPO 'GPO-SeaWallpaper'

#Review Desktop ADMX File
Notepad C:\Windows\PolicyDefinitions\desktop.admx

#Set GPO-BasicWallpaper's Wallpaper value
Set-GPRegistryValue `
    -Name 'GPO-BasicWallpaper' `
    -key HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System `
    -ValueName Wallpaper `
    -Type String `
    -value \\DC1\Wallpaper\img0.jpg -Verbose

#Set GPO-BeachWallpaper's Wallpaper value
Set-GPRegistryValue `
    -Name 'GPO-BeachWallpaper' `
    -key HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System `
    -ValueName Wallpaper `
    -Type String `
    -value \\DC1\Wallpaper\img1.jpg -Verbose

#Set GPO-SeaWallpaper's Wallpaper value
Set-GPRegistryValue `
    -Name 'GPO-SeaWallpaper' `
    -key HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System `
    -ValueName Wallpaper `
    -Type String `
    -value \\DC1\Wallpaper\img2.jpg -Verbose

#Set GPO-RockWallpaper's Wallpaper value
Set-GPRegistryValue `
    -Name 'GPO-RockWallpaper' `
    -key HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System `
    -ValueName Wallpaper `
    -Type String `
    -value \\DC1\Wallpaper\img3.jpg -Verbose

#Create a folder C:\GPReports 
New-Item -ItemType Directory C:\GPReports 

#View all the GPOs in the Domain
Get-GPO -All -Domain Changeme!.pri | ft DisplayName,GPOStatus,Description -AutoSize                #Changes needed

#Review a Specific GPO
Get-GPO -Name 'GPO-BasicWallpaper'

Get-GPOReport -Name 'GPO-BasicWallpaper' -ReportType Xml -Path C:\GPReports\gpreport.xml
Notepad C:\GPReports\gpreport.xml

Get-GPOReport -Name 'GPO-BasicWallpaper' -ReportType Html -Path C:\GPReports\gpreport.html
C:\GPReports\gpreport.html

#endregion 1

#region 2 - Group Policies In Action
#Change Desktop Backgrounds to see how processing works
#Domain Level Policy: img1.jpg (GPO-BeachWallpaper)
#MyCompany level Policy: img3.jpg (GPO-RockWallpaper)
#Users OU in Puyallup Level Policy: img2.jpg (GPO-SeaWallpaper)

#Enable Remote Scheduled Tasks Management firewall rules
Invoke-Command `
	 -ComputerName Client1 `
	 -ScriptBlock {Get-NetFirewallRule -Name *RemoteTask* | Set-NetFirewallRule -Enabled True}
Invoke-GPUpdate -Computer Client1 -Force -RandomDelayInMinutes 0

#Link and Enable GPO-BeachWallpaper at Domain Level
New-GPLink -Name 'GPO-BeachWallpaper' `
	-LinkEnabled Yes `
	-Target 'DC=Changeme!,dc=pri'                                            #Changes needed
Invoke-GPUpdate -Computer Client1 -Force -RandomDelayInMinutes 0
    
#Enable GPO-RockWallpaper at MyCompany level
New-GPLink -Name 'GPO-RockWallpaper' `
	-LinkEnabled Yes `
	-Target 'OU=MyCompany,DC=Changeme!,dc=pri'                                            #Changes needed
Invoke-GPUpdate -Computer Client1 -Force -RandomDelayInMinutes 0

#Set Blocking of OUs at Users level and Enable GPO-SeaWallpaper at Users level
Set-GPInheritance `
	-Target 'OU=Users,OU=Puyallup,OU=MyCompany,DC=Changeme!,dc=pri'                                            #Changes needed
	-IsBlocked Yes `
	-Domain Changeme!.pri `                                                                   #Changes needed 
	-Server DC1
Invoke-GPUpdate -Computer Client1 -Force -RandomDelayInMinutes 0

New-GPLink -Name 'GPO-SeaWallpaper' `
	-LinkEnabled Yes `
	-Target 'OU=Users,OU=Puyallup,OU=MyCompany,DC=Changeme!,dc=pri'                                            #Changes needed
Invoke-GPUpdate -Computer Client1 -Force -RandomDelayInMinutes 0

#Set Enforcement
Set-GPLink -Name 'GPO-RockWallpaper' `
	-LinkEnabled Yes `
	-Enforced Yes `
	-Target 'OU=MyCompany,DC=Changeme!,dc=pri'                                            #Changes needed 
Invoke-GPUpdate -Computer Client1 -Force -RandomDelayInMinutes 0

#Change Permissions on GPO-RockWallpaper
New-ADGroup `
	-Name 'GPO-GPUsers' `
	-GroupCategory Security `
	-GroupScope Global

Add-ADGroupMember -Identity 'GPO-GPUsers' `
	-Members 'ClarkA'

Get-GPPermission -Name 'GPO-RockWallpaper' -All 

Set-GPPermission -Name 'GPO-RockWallpaper' `
	-PermissionLevel GpoRead `
	-TargetName 'Authenticated Users' `
	-TargetType Group `
	-Replace

Set-GPPermission -Name 'GPO-RockWallpaper' `
	-PermissionLevel GpoApply `
	-TargetName 'GPO-GPUsers' `
	-TargetType Group

Invoke-GPUpdate -Computer Client1 -Force -RandomDelayInMinutes 0


#Running Resultant Set of Policies report on user logging on Client1
Get-GPResultantSetOfPolicy `
	-User cne270\ClarkA `
	-Computer Client1.Changeme!.pri `                              #Changes needed
	-ReportType Html `
	-Path C:\GPReports\GPResult-ClarkA.html

C:\GPReports\GPResult-ClarkA.html

#endregion 2 
