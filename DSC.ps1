#Create a DSC configuration to support IIS and remote management configuration
Configuration IISConfig {

    #define input parameter
    param(
        [string[]]$ComputerName = 'Server1'
    )

    #Target machines based on input parameter
    node $ComputerName {
        
        #Come back and do the following commands at the end of the lab
        # configure the local configuration manager
        #LocalConfigurationManager {
        #    ConfigurationMode = "ApplyAndAutoCorrect"
        #    ConfigurationModeFrequencyMins = 15
        #    RefreshMode = "Push"
        #}
        
        # install the IIS server role
        WindowsFeature IIS {
            Ensure = 'Present'
            Name = 'Web-Server'
        }

        # install the IIS remote management service
        WindowsFeature IISManagement {
            Ensure = 'Present'
            Name = 'Web-Mgmt-Service'
            DependsOn = @('[WindowsFeature]IIS')
        }

        # enable IIS remote management
        Registry RemoteManagement {
            Key = 'HKLM:\Software\Microsoft\WebManagement\Server'
            ValueName = 'EnableRemoteManagement'
            ValueType = 'Dword'
            ValueData = '1'
            DependsOn = @('[WindowsFeature]IIS','[WindowsFeature]IISManagement')

        }

        # configure Web remote management service
        Service WMSVC {
            Name = 'WMSVC'
            StartupType = 'Automatic'
            State = 'Running'
            DependsOn = '[Registry]RemoteManagement'
        }
    }
}

    # create the configuration (.mof) file
    IISConfig -ComputerName Server1 -OutputPath c:\MOFfiles

    # push the Desired State Configuration and the Local Configuration Manager settings to Server1
    Start-DscConfiguration -Path c:\MOFfiles -Wait -Verbose
    Set-DscLocalConfigurationManager -Path c:\MOFfiles -Verbose

    # enter remote session on Server1
    Enter-PSSession -ComputerName Server1

    # view installed features
    Get-WindowsFeature | Where-Object Installed -EQ True

    # view LCM properties
    Get-DscLocalConfigurationManager

    # view configuration state
    Get-DscConfigurationStatus

    # test configuration drift
    Test-DscConfiguration

    # exit remote session on Server1
    Exit-PSSession
