param (
    [Parameter(Mandatory = $true)]
    [ValidateSet(
        'all',
        'help',
        'Remove-PreInstalledApps',
        'Disable-Telemetry',
        'Disable-Services',
        'Enable-FullScreenExclusive',
        'Enable-GPUTweaks',
        'Disable-MouseAcceleration',
        'Disable-PowerThrottling',
        'Set-HardwareDataQueueSize',
        'Enable-UltimatePerformance'
    )]
    $Command
)

function Show-Message {
    param (
        [string]$Message,
        [string]$Color
    )

    switch ($Color) {
        'Error' {
            Write-Host $Message -ForegroundColor Red
        }
        'Warning' {
            Write-Host $Message -ForegroundColor Yellow
        }
        'Information' {
            Write-Host $Message -ForegroundColor Blue
        }
        'Success' {
            Write-Host $Message -ForegroundColor Green
        }
    }
}

function Get-Help {
    Write-Host "Options available for the command:"
    Write-Host "  all                           : Executes all available tweaks."
    Write-Host "  Remove-PreInstalledApps       : Removes Microsoft apps from the system."
    Write-Host "  Disable-Telemetry             : Disables system telemetry."
    Write-Host "  Disable-Services              : Disables specific system services."
    Write-Host "  Enable-FullScreenExclusive    : Enables full-screen exclusive mode for gaming."
    Write-Host "  Enable-GPUTweaks              : Applies performance tweaks for the GPU."
    Write-Host "  Disable-MouseAcceleration     : Disables mouse acceleration."
    Write-Host "  Disable-PowerThrottling       : Disables power throttling."
    Write-Host "  Set-HardwareDataQueueSize     : Sets mouse and keyboard data queue size."
    Write-Host "  Enable-UltimatePerformance    : Enables the ultimate performance mode."
    Write-Host ""
    Write-Host "To execute a specific command, use the -Command parameter followed by the command name."
    Write-Host "Example: .\run.ps1 -Command Remove-PreInstalledApps"
    Write-Host "         .\run.ps1 Remove-PreInstalledApps"
    Write-Host ""
    Write-Host "To execute all available tweaks, use the -Command parameter with 'all'."
    Write-Host "Example: .\run.ps1 -Command all"
    Write-Host "         .\run.ps1 all"
}

function Remove-PreInstalledApps {
    $app_list = @(
        '*549981C3F5F10*',
        '*bing*',
        '*BingWeather*',
        '*Disney*',
        '*Facebook*',
        '*GetHelp*',
        '*Getstarted*',
        '*Instagram*',
        '*Microsoft3DViewer*',
        '*MicrosoftOfficeHub*',
        '*MicrosoftSolitaireCollection*',
        '*MicrosoftStickyNotes*',
        '*MixedReality*',
        '*MSPaint*',
        '*Netflix*',
        '*OneDrive*',
        '*OneNote*',
        '*People*',
        '*Skype*',
        '*SkypeApp*',
        '*SolitaireCollection*',
        '*StickyNotes*',
        '*Twitter*',
        '*WindowsCamera*',
        '*windowscommunicationsapps*'
        '*WindowsFeedbackHub*',
        '*WindowsMaps*',
        '*WindowsSoundRecorder*',
        '*YourPhone*'
    )

    foreach ($app in $app_list) {
        $result = winget uninstall --purge --id $app 2>&1
        if ($LASTEXITCODE -eq 0) {
            Show-Message -Message "App '$app' removed successfully." -Color 'Success'
        } else {
            Show-Message -Message "Failed to remove app '$app'`n$result`n" -Color 'Error'
        }
    }
}

function Disable-Telemetry {
    $tasks = @(
        '\Microsoft\Windows\Customer Experience Improvement Program\Consolidator',
        '\Microsoft\Windows\Customer Experience Improvement Program\BthSQM',
        '\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask',
        '\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip',
        '\Microsoft\Windows\Customer Experience Improvement Program\Uploader',
        '\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser',
        '\Microsoft\Windows\Application Experience\ProgramDataUpdater',
        '\Microsoft\Windows\Application Experience\StartupAppTask',
        '\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector',
        '\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver',
        '\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem',
        '\Microsoft\Windows\Shell\FamilySafetyMonitor',
        '\Microsoft\Windows\Shell\FamilySafetyRefresh',
        '\Microsoft\Windows\Shell\FamilySafetyUpload',
        '\Microsoft\Windows\Autochk\Proxy',
        '\Microsoft\Windows\Maintenance\WinSAT',
        '\Microsoft\Windows\Application Experience\AitAgent',
        '\Microsoft\Windows\Windows Error Reporting\QueueReporting',
        '\Microsoft\Windows\CloudExperienceHost\CreateObjectTask',
        '\Microsoft\Windows\DiskFootprint\Diagnostics',
        '\Microsoft\Windows\FileHistory\File History (maintenance mode)',
        '\Microsoft\Windows\PI\Sqm-Tasks',
        '\Microsoft\Windows\NetTrace\GatherNetworkInfo',
        '\Microsoft\Windows\AppID\SmartScreenSpecific',
        '\Microsoft\Office\OfficeTelemetryAgentFallBack2016',
        '\Microsoft\Office\OfficeTelemetryAgentLogOn2016'
    )

    foreach ($task in $tasks) {
        $result = schtasks /end /tn $task 2>&1
        if ($LASTEXITCODE -eq 0) {
            Show-Message -Message "Task '$task' ended successfully." -Color 'Success'
        } else {
            Show-Message -Message "Failed to end task '$task': $result" -Color 'Error'
        }

        $result = schtasks /change /tn $task /disable 2>&1
        if ($LASTEXITCODE -eq 0) {
            Show-Message -Message "Task '$task' disabled successfully." -Color 'Success'
        } else {
            Show-Message -Message "Failed to disable task '$task': $result" -Color 'Error'
        }
    }
}

function Disable-Services {
    $servicesList = @(
        'wuauserv',             # Windows Update Service
        'TapiSrv',              # Telephony service
        'LanmanWorkstation',    # Workstation service
        'StiSvc'                # Windows Image Acquisition Service
    )

    foreach ($service in $servicesList) {
        $result = Set-Service -Name $service -StartupType Manual -Force 2>&1
        if ($LASTEXITCODE -eq 0) {
            Show-Message -Message "Service '$service' set to manual startup successfully." -Color 'Success'
        } else {
            Show-Message -Message "Failed to set service '$service' to manual startup: $result" -Color 'Error'
        }

        $result = Stop-Service -Name $service -Force 2>&1
        if ($LASTEXITCODE -eq 0) {
            Show-Message -Message "Service '$service' stopped successfully." -Color 'Success'
        } else {
            Show-Message -Message "Failed to stop service '$service': $result" -Color 'Error'
        }
    }
}

function Update-RegistryProperties {
    param (
        [Parameter(Mandatory = $true)]
        [array]$Properties
    )

    foreach ($property in $Properties) {
        foreach ($item in $property.Items) {
            if ($item.Action -eq 'Remove') {
                $result = Remove-ItemProperty -Path $property.Path -Name $item.Name -ErrorAction SilentlyContinue -Force 2>&1
                if ($LASTEXITCODE -eq 0) {
                    Show-Message -Message "Registry property '$($property.Path)\$($item.Name)' removed successfully." -Color 'Success'
                } else {
                    Show-Message -Message "Failed to remove registry property '$($property.Path)\$($item.Name)': $result" -Color 'Error'
                }
            } elseif ($item.Action -eq 'Set') {
                $result = Set-ItemProperty -Path $property.Path -Name $item.Name -Value $item.Value -Type $item.Type -Force 2>&1
                if ($LASTEXITCODE -eq 0) {
                    Show-Message -Message "Registry property '$($property.Path)\$($item.Name)' set successfully." -Color 'Success'
                } else {
                    Show-Message -Message "Failed to set registry property '$($property.Path)\$($item.Name)': $result" -Color 'Error'
                }
            }
        }
    }
}

function Enable-FullScreenExclusive {
    $properties = @(
        @{
            Path = 'HKCU:\System\GameConfigStore'
            Items = @(
                @{
                    Name = 'Win32_AutoGameModeDefaultProfile'
                    Action = 'Remove'
                },
                @{
                    Name = 'Win32_GameModeRelatedProcesses'
                    Action = 'Remove'
                },
                @{
                    Name = 'GameDVR_DSEBehavior'
                    Value = 2
                    Type = 'DWORD'
                    Action = 'Set'
                },
                @{
                    Name = 'GameDVR_DXGIHonorFSEWindowsCompatible'
                    Value = 1
                    Type = 'DWORD'
                    Action = 'Set'
                },
                @{
                    Name = 'GameDVR_EFSEFeatureFlags'
                    Value = 0
                    Type = 'DWORD'
                    Action = 'Set'
                },
                @{
                    Name = 'GameDVR_Enabled'
                    Value = 0
                    Type = 'DWORD'
                    Action = 'Set'
                },
                @{
                    Name = 'GameDVR_FSEBehavior'
                    Value = 2
                    Type = 'DWORD'
                    Action = 'Set'
                },
                @{
                    Name = 'GameDVR_FSEBehaviorMode'
                    Value = 2
                    Type = 'DWORD'
                    Action = 'Set'
                },
                @{
                    Name = 'GameDVR_HonorUserFSEBehaviorMode'
                    Value = 1
                    Type = 'DWORD'
                    Action = 'Set'
                }
            )
        },
        @{
            Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR'
            Items = @(
                @{
                    Name = 'AllowGameDVR'
                    Value = 0
                    Type = 'DWORD'
                    Action = 'Set'
                }
            )
        },
        @{
            Path = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR'
            Items = @(
                @{
                    Name = 'value'
                    Value = 0
                    Type = 'DWORD'
                    Action = 'Set'
                }
            )
        }
    )

    Update-RegistryProperties -Properties $properties
}

function Enable-GPUTweaks {
    $properties = @(
        @{
            Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile'
            Items = @(
                @{
                    Name = 'NetworkThrottlingIndex'
                    Value = 10
                    Type = 'DWORD'
                    Action = 'Set'
                },
                @{
                    Name = 'SystemResponsiveness'
                    Value = 10
                    Type = 'DWORD'
                    Action = 'Set'
                },
                @{
                    Name = 'NoLazyMode'
                    Value = 1
                    Type = 'DWORD'
                    Action = 'Set'
                }
            )
        },
        @{
            Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games'
            Items = @(
                @{
                    Name = 'Background Only'
                    Value = 'False'
                    Type = 'STRING'
                    Action = 'Set'
                },
                @{
                    Name = 'GPU Priority'
                    Value = 18
                    Type = 'DWORD'
                    Action = 'Set'
                },
                @{
                    Name = 'Priority'
                    Value = 6
                    Type = 'DWORD'
                    Action = 'Set'
                },
                @{
                    Name = 'Scheduling Category'
                    Value = 'High'
                    Type = 'STRING'
                    Action = 'Set'
                },
                @{
                    Name = 'SFIO Priority'
                    Value = 'High'
                    Type = 'STRING'
                    Action = 'Set'
                }
            )
        },
        @{
            Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers'
            Items = @(
                @{
                    Name = 'HwSchMode'
                    Value = 2
                    Type = 'DWORD'
                    Action = 'Set'
                }
            )
        }
    )

    Update-RegistryProperties -Properties $properties
}

function Disable-MouseAcceleration {
    $properties = @(
        @{
            Path = 'HKCU:\Control Panel\Mouse'
            Items = @(
                @{
                    Name = 'MouseSpeed'
                    Value = '0'
                    Type = 'STRING'
                    Action = 'Set'
                },
                @{
                    Name = 'MouseThreshold1'
                    Value = '0'
                    Type = 'STRING'
                    Action = 'Set'
                },
                @{
                    Name = 'MouseThreshold2'
                    Value = '0'
                    Type = 'STRING'
                    Action = 'Set'
                }
            )
        }
    )

    Update-RegistryProperties -Properties $properties
}

function Disable-PowerThrottling {
    $properties = @(
        @{
            Path = 'HKLM:\SYSTEM\ControlSet001\Control\Power\PowerThrottling'
            Items = @(
                @{
                    Name = 'PowerThrottlingOff'
                    Value = '1'
                    Type = 'STRING'
                    Action = 'Set'
                }
            )
        }
    )

    Update-RegistryProperties -Properties $properties
}

function Set-HardwareDataQueueSize {
    param (
         [Parameter(Mandatory = $false)]
         [string]$Size = '20' # Windows default: 100
    )

    $properties = @(
        @{
            Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\mouclass\Parameters'
            Items = @(
                @{
                    Name = 'MouseDataQueueSize'
                    Value = $Size
                    Type = 'DWORD'
                    Action = 'Set'
                }
            )
        },
        @{
            Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters'
            Items = @(
                @{
                    Name = 'KeyboardDataQueueSize'
                    Value = $Size
                    Type = 'DWORD'
                    Action = 'Set'
                }
            )
        }
    )

    Update-RegistryProperties -Properties $properties
}

function Enable-UltimatePerformance {
    $hibernateResult = POWERCFG /HIBERNATE OFF 2>&1
    if ($LASTEXITCODE -eq 0) {
        Show-Message -Message "Hibernate mode disabled successfully." -Color 'Success'
    } else {
        Show-Message -Message "Failed to disable hibernate mode: $hibernateResult" -Color 'Error'
    }

    $output = Invoke-Expression 'POWERCFG /DUPLICATESCHEME e9a42b02-d5df-448d-aa00-03f14749eb61' 2>&1
    if ($LASTEXITCODE -eq 0) {
        $guid = ($output -split ': ')[1].Trim()
        $guid = ($guid -split ' ')[0].Trim()
        Show-Message -Message "Power scheme duplicated successfully. GUID: $guid" -Color 'Success'
    } else {
        Show-Message -Message "Failed to duplicate power scheme: $output" -Color 'Error'
        return
    }

    $setActiveResult = POWERCFG /SETACTIVE $guid 2>&1
    if ($LASTEXITCODE -eq 0) {
        Show-Message -Message "Power scheme set as active successfully." -Color 'Success'
    } else {
        Show-Message -Message "Failed to set power scheme as active: $setActiveResult" -Color 'Error'
    }
}

function Invoke-RunAllTweaks {
    TASKKILL /F /IM explorer.exe | Out-Null

    Remove-PreInstalledApps
    Disable-Telemetry
    Disable-Services
    Enable-FullScreenExclusive
    Enable-GPUTweaks
    Disable-MouseAcceleration
    Disable-PowerThrottling
    Set-HardwareDataQueueSize
    Enable-UltimatePerformance

    Start-Process explorer
}


if ($Command -eq 'all') {
    Invoke-RunAllTweaks
} else {
    & $Command
}
