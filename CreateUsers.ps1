#UserSetup
$SetPass = Read-Host "Enter initial password that all new users will share" -assecurestring
$Users =Import-CSV "c:\LabSetup\NewUsers.csv" 
$cred = Get-Credential -Message "Enter Domain administrator username and password"

#get-aduser -Filter * -Properties *| gm

ForEach ($user in $users){     
    New-ADUser `
        -Credential $cred `
        -Path $user.DistinguishedName `
        -department $user.Department `
        -SamAccountName $user.SamAccountName `
        -Name $user.Name `
        -Surname $user.Surname `
        -GivenName $user.GivenName `
        -UserPrincipalName $user.UserPrincipalName `
        -City $user.city `
        -ChangePasswordAtLogon $False `
        -AccountPassword $SetPass `
        -Enabled $False -Verbose
        }

#Enable accounts
    Set-ADUser -Identity 'mbtest' -Enabled $True
    Set-ADUser -Identity 'mbadmin' -Enabled $True

#Add mbadmin account to Admin Groups
Add-ADGroupMember -Identity 'Domain Admins' -Members 'mbadmin'
Add-ADGroupMember -Identity 'Enterprise Admins' -Members 'mbadmin'
Add-ADGroupMember -Identity 'Schema Admins' -Members 'mbadmin'