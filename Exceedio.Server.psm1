Configuration Exceedio2022Hypervisor {

    param (
        [String] $ComputerName,
        [PSCredential] $LocalAdminCredential,
        [String[]] $VirtualHardDiskStorageDisks,
        [String[]] $ExternalVirtualSwitchNics,
        [String] $ExternalVirtualSwitchName,
        [String] $VirtualMachinePath,
        [String] $VirtualHardDiskPath,
        [String] $InstallMediaPath
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName PSDscResources
    Import-DscResource -ModuleName ComputerManagementDsc
    Import-DscResource -ModuleName HyperVDsc
    Import-DscResource -ModuleName NetworkingDsc
    Import-DscResource -ModuleName StorageDsc
    Import-DscResource -ModuleName xWindowsUpdate

    Node localhost
    {
        LocalConfigurationManager {
            ConfigurationMode  = "ApplyOnly"
            RebootNodeIfNeeded = $false
        }

        WindowsFeature EnableHyperV {
            Name                 = 'Hyper-V'
            IncludeAllSubFeature = $true
            Ensure               = 'Present'
        }

        WindowsFeature EnableSNMP {
            Name   = 'SNMP-Service'
            Ensure = 'Present'
        }

        Service EnableW32Time {
            Name        = 'W32Time'
            StartupType = 'Automatic'
            State       = 'Running'
        }

        User CreateLocalAdmin {
            Ensure                   = 'Present'
            UserName                 = $($LocalAdminCredential).UserName
            FullName                 = $($LocalAdminCredential).UserName
            Password                 = $LocalAdminCredential
            PasswordChangeNotAllowed = $true
            PasswordChangeRequired   = $false
            PasswordNeverExpires     = $true
        }

        Group AddLocalAdminToLocalAdminsGroup {
            GroupName        = 'Administrators'
            Ensure           = 'Present'
            MembersToInclude = $($LocalAdminCredentials).UserName
            DependsOn        = '[User]CreateLocalAdmin'
        }

        Registry DisablePrinterMappingForRemoteDesktop {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueName = 'fDisableCpm'
            ValueType = 'Dword'
            ValueData = '1'
        }

        RemoteDesktopAdmin EnableRemoteDesktop {
            IsSingleInstance   = 'Yes'
            Ensure             = 'Present'
            UserAuthentication = 'Secure'
        }

        Firewall AllowRemoteDesktop-UserMode-In-TCP {
            Ensure  = 'Present'
            Name    = 'RemoteDesktop-UserMode-In-TCP'
            Profile = 'Any'
            Enabled = 'True'
        }

        Firewall AllowRemoteDesktop-Shadow-In-TCP {
            Ensure  = 'Present'
            Name    = 'RemoteDesktop-Shadow-In-TCP'
            Profile = 'Any'
            Enabled = 'True'
        }

        FirewallProfile EnablePrivateFirewallProfile {
            Name                    = 'Private'
            Enabled                 = 'True'
            DefaultInboundAction    = 'Block'
            DefaultOutboundAction   = 'Allow'
            AllowInboundRules       = 'NotConfigured'
            AllowLocalFirewallRules = 'NotConfigured'
            AllowLocalIPsecRules    = 'NotConfigured'
            NotifyOnListen          = 'False'
            LogFileName             = '%systemroot%\system32\LogFiles\Firewall\privatefw.log'
            LogMaxSizeKilobytes     = 16384
            LogAllowed              = 'True'
            LogBlocked              = 'True'
            LogIgnored              = 'NotConfigured'
        }

        FirewallProfile EnableDomainFirewallProfile {
            Name                    = 'Domain'
            Enabled                 = 'True'
            DefaultInboundAction    = 'Block'
            DefaultOutboundAction   = 'Allow'
            AllowInboundRules       = 'NotConfigured'
            AllowLocalFirewallRules = 'NotConfigured'
            AllowLocalIPsecRules    = 'NotConfigured'
            NotifyOnListen          = 'False'
            LogFileName             = '%systemroot%\system32\LogFiles\Firewall\domainfw.log'
            LogMaxSizeKilobytes     = 16384
            LogAllowed              = 'True'
            LogBlocked              = 'True'
            LogIgnored              = 'NotConfigured'
        }

        FirewallProfile EnablePublicFirewallProfile {
            Name                    = 'Public'
            Enabled                 = 'True'
            DefaultInboundAction    = 'Block'
            DefaultOutboundAction   = 'Allow'
            AllowInboundRules       = 'NotConfigured'
            AllowLocalFirewallRules = 'False'
            AllowLocalIPsecRules    = 'False'
            NotifyOnListen          = 'False'
            LogFileName             = '%systemroot%\system32\LogFiles\Firewall\publicfw.log'
            LogMaxSizeKilobytes     = 16384
            LogAllowed              = 'True'
            LogBlocked              = 'True'
            LogIgnored              = 'NotConfigured'
        }

        for ($i = 0; $i -lt $VirtualHardDiskStorageDisks.Count; $i++) {
            
            Disk "DataVolume$i" {
                DiskId             = $VirtualHardDiskStorageDisks[$i]
                DiskIdType         = 'UniqueId'
                DriveLetter        = @('D', 'E', 'F', 'G', 'H')[$i]
                FSFormat           = 'ReFS'
                FSLabel            = 'Data'
                AllocationUnitSize = 64KB
                AllowDestructive   = $false
            }
        }

        VMHost ConfigureHost {
            IsSingleInstance    = 'Yes'
            NumaSpanningEnabled = $true
            VirtualMachinePath  = $VirtualMachinePath
            VirtualHardDiskPath = $VirtualHardDiskPath
            DependsOn           = '[Disk]DataVolume0'
        }

        Script CreateExternalVirtualSwitch {
            SetScript  = {
                New-VMSwitch `
                    -AllowManagementOS $false `
                    -EnableEmbeddedTeaming $true `
                    -EnableIov (Get-VMHost).IovSupport `
                    -MinimumBandwidthMode 'Weight' `
                    -Name $using:ExternalVirtualSwitchName `
                    -NetAdapterName $using:ExternalVirtualSwitchNics
            }
            TestScript = {
                ($null -ne (Get-VMSwitch -Name $using:ExternalVirtualSwitchName))
            }
            GetScript  = {
                return @{
                    Result = ''
                }
            }
            DependsOn  = '[WindowsFeature]EnableHyperV'
        }

        File CreateISOFolder {
            Ensure          = 'Present'
            Type            = 'Directory'
            DestinationPath = $InstallMediaPath
        }

        File DeleteDefaultVirtualMachinePath {
            Ensure          = 'Absent'
            Type            = 'Directory'
            DestinationPath = 'C:\Users\Public\Documents\Hyper-V'
            Force           = $true
            DependsOn       = '[VMHost]ConfigureHost'
        }

        TimeZone SetTimezone {
            IsSingleInstance = 'Yes'
            TimeZone         = 'Pacific Standard Time'
        }

        Computer ComputerNameAndDescription {
            Name        = $ComputerName
            Description = 'Hypervisor'
        }

        xWindowsUpdateAgent ConfigureAndInstallWindowsUpdates {
            IsSingleInstance = 'Yes'
            Category         = @('Security', 'Important')
            Notifications    = 'Disabled'
            Source           = 'MicrosoftUpdate'
            UpdateNow        = $true
            DependsOn        = '[Computer]ComputerNameAndDescription'
        }

        if ((Get-CimInstance CIM_ComputerSystem).Manufacturer -eq 'Dell Inc.') {

            Package InstallDellSystemUpdate {
                Name      = 'Dell System Update 2.0.2.0'
                Path      = 'https://dl.dell.com/FOLDER09663875M/1/Systems-Management_Application_RWVV0_WN64_2.0.2.0_A00.EXE'
                ProductId = ''
                Arguments = '/S'
                Ensure    = 'Present'
                DependsOn = '[xWindowsUpdateAgent]ConfigureAndInstallWindowsUpdates'
            }

            MsiPackage InstallDellServiceModule {
                ProductId = '{40432BC5-76F7-4B12-81D1-8EDE05204716}'
                Path      = 'https://github.com/exceedio/Exceedio.Server/releases/download/v1.0.0/iDRACSvcMod.msi'
                Ensure    = 'Present'
                DependsOn = '[xWindowsUpdateAgent]ConfigureAndInstallWindowsUpdates'
            }

            MsiPackage InstallDellOpenManageServerAdministrator {
                ProductId = '{D5E7D351-DAD8-4995-ACF9-41C41C147328}'
                Path      = 'https://github.com/exceedio/Exceedio.Server/releases/download/v1.0.0/SysMgmtx64.msi'
                Ensure    = 'Present'
                DependsOn = '[xWindowsUpdateAgent]ConfigureAndInstallWindowsUpdates'
            }

            Firewall AllowDellOMSA-In-TCP {
                Ensure      = 'Present'
                Name        = 'Dell-OMSA-In-TCP'
                DisplayName = 'Dell OpenManage Server Administrator'
                Enabled     = 'True'
                Profile     = 'Any'
                Direction   = 'Inbound'
                LocalPort   = '1311'
                Protocol    = 'TCP'
                Description = 'Firewall rule to allow traffic to TCP/1311 for Dell OMSA'
            }
    
            Script SecureDellOpenManageServerAdministrator {
                SetScript  = {
                    & "C:\Program Files\Dell\SysMgt\oma\bin\omconfig.exe" --% preferences webserver attribute=ciphers setting=TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
                    & "C:\Program Files\Dell\SysMgt\oma\bin\omconfig.exe" --% preferences webserver attribute=sslprotocol setting=TLSv1.2
                    & "C:\Program Files\Dell\SysMgt\oma\bin\omconfig.exe" --% system webserver action=restart
                }
                TestScript = {
                    $protocols = & "C:\Program Files\Dell\SysMgt\oma\bin\omreport.exe" --% preferences webserver attribute=getsslprotocol
                    return ([bool] ($protocols -notlike '*TLSv1.1*'))
                }
                GetScript  = {
                    return @{ Result = "" }
                }
                DependsOn  = '[MsiPackage]InstallDellOpenManageServerAdministrator' 
            }
        }
    }
}

Configuration Exceedio2022MemberServer {
    
}

Configuration Exceedio2022VirtualMachine {
    
    param (
        [String] $ComputerName,
        [String] $OSDiskPath,
        [UInt64] $OSDiskSizeBytes,
        [String] $DataDiskPath,
        [UInt64] $DataDiskSizeBytes,
        [UInt32] $Cores,
        [UInt64] $Memory,
        [String] $Switch,
        [String] $VlanId,
        [String] $InstallMediaISOPath,
        [Boolean] $IsDomainController,
        [Int32] $AutomaticStartDelayInSeconds
    )

    $OSDiskName = "$ComputerName-OS.vhdx"
    $AutomaticStartDelayInSeconds = if ($IsDomainController) { 0 } else { $AutomaticStartDelayInSeconds }
    $AutomaticStopAction = if ($IsDomainController) { 'Shutdown' } else { 'Save' }

    Import-DscResource -ModuleName HyperVDsc
    Import-DscResource -ModuleName PSDscResources

    Node localhost
    {
        LocalConfigurationManager {
            ConfigurationMode  = "ApplyOnly"
            RebootNodeIfNeeded = $false
        }

        Vhd CreateOSDisk {
            Name             = $OSDiskName
            Path             = $OSDiskPath
            MaximumSizeBytes = $OSDiskSizeBytes
            Generation       = 'Vhdx'
            Type             = 'Fixed'
            Ensure           = 'Present'
        }

        if ($DataDiskSizeBytes -gt 0) {
            Vhd CreateDataDisk {
                Name             = "$ComputerName-Data.vhdx"
                Path             = $DataDiskPath
                MaximumSizeBytes = $DataDiskSizeBytes
                Generation       = 'Vhdx'
                Type             = 'Fixed'
                Ensure           = 'Present'
                DependsOn        = '[Vhd]CreateOSDisk'
            }
        }

        VMHyperV NewVM {
            Name                        = $ComputerName
            VhdPath                     = Join-Path $OSDiskPath $OSDiskName
            Generation                  = 2
            StartupMemory               = $Memory
            ProcessorCount              = $Cores
            SecureBoot                  = $true
            EnableGuestService          = $false
            AutomaticCheckpointsEnabled = $false
            Ensure                      = 'Present'
            DependsOn                   = '[Vhd]CreateOSDisk'
        }

        VMNetworkAdapter NIC1 {
            Id         = 'Network Adapter'
            Name       = 'Network Adapter'
            SwitchName = $Switch
            VMName     = $ComputerName
            VlanId     = $VlanId
            Ensure     = 'Present'
            DependsOn  = '[VMHyperV]NewVM'
        }

        VMDvdDrive DVD1 {
            VMName             = $ComputerName
            ControllerNumber   = 0
            ControllerLocation = 1
            Path               = $InstallMediaISOPath
            Ensure             = 'Present'
            DependsOn          = '[VMHyperV]NewVM'
        }

        Script DisableTimeSynchronization {
            SetScript  = {
                Get-VMIntegrationService -VMName $using:ComputerName -Name 'Time Synchronization' | Disable-VMIntegrationService
            }
            TestScript = {
                -not (Get-VMIntegrationService -VMName $using:ComputerName -Name 'Time Synchronization').Enabled
            }
            GetScript  = {
                return @{
                    Result = "Time synchronization enabled: {0}" -f (Get-VMIntegrationService -VMName $using:ComputerName -Name 'Time Synchronization').Enabled
                }
            }
            DependsOn  = '[VMHyperV]NewVM'
        }

        Script SetBootOrder {
            SetScript  = {
                Set-VMFirmware -VMName $using:ComputerName -BootOrder ((Get-VMHardDiskDrive -VMName $using:ComputerName -ControllerNumber 0 -ControllerLocation 0), (Get-VMDvdDrive -VMName $using:ComputerName))
            }
            TestScript = {
                $false
            }
            GetScript  = {
                return @{
                    Result = Get-VMFirmware -VMName $using:ComputerName | Select-Object BootOrder
                }
            }
            DependsOn  = '[VMDvdDrive]DVD1'
        }

        Script AutomaticStartDelay {
            SetScript  = {
                Get-VM -Name $using:ComputerName | Set-VM -AutomaticStartDelay $using:AutomaticStartDelayInSeconds
            }
            TestScript = {
                (Get-VM -Name $using:ComputerName).AutomaticStartDelay -eq $using:AutomaticStartDelayInSeconds
            }
            GetScript  = {
                return @{
                    Result = (Get-VM -Name $using:ComputerName).AutomaticStartDelay
                }
            }
            DependsOn  = '[VMHyperV]NewVM'
        }

        Script AlwaysAutomaticallyStart {
            SetScript  = {
                Get-VM -Name $using:ComputerName | Set-VM -AutomaticStartAction Start
            }
            TestScript = {
                (Get-VM -Name $using:ComputerName).AutomaticStartAction -eq 'Start'
            }
            GetScript  = {
                return @{
                    Result = (Get-VM -Name $using:ComputerName).AutomaticStartAction
                }
            }
            DependsOn  = '[VMHyperV]NewVM'
        }

        Script AutomaticStopActionShutdown {
            SetScript  = {
                Get-VM -Name $using:ComputerName | Set-VM -AutomaticStopAction $using:AutomaticStopAction
            }
            TestScript = {
                (Get-VM -Name $using:ComputerName).AutomaticStopAction -eq $using:AutomaticStopAction
            }
            GetScript  = {
                return @{
                    Result = (Get-VM -Name $using:ComputerName).AutomaticStopAction
                }
            }
            DependsOn  = '[VMHyperV]NewVM'
        }
    }
}

function Initialize-ExceedioHypervisor {
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, HelpMessage = 'Name of physical machine (e.g. SV12345)')]
        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerName,
        [Parameter(HelpMessage = 'The credentials for a local administrator that will be created')]
        [PSCredential]
        $LocalAdminCredential,
        [Parameter(HelpMessage = 'One or more UniqueId values from Get-Disk where virtual hard disks will be stored')]
        [String[]]
        $VirtualHardDiskStorageDisks,
        [Parameter(HelpMessage = 'Physical network adapter(s) that will be part of switch embedded team (SET)')]
        [String[]]
        $ExternalVirtualSwitchNics,
        [Parameter(HelpMessage = 'The name of the external virtual switch to create')]
        [String]
        $ExternalVirtualSwitchName = 'External Virtual Switch',
        [Parameter(HelpMessage = 'The default path where virtual machine files (not disks) will be stored')]
        [String]
        $VirtualMachinePath = 'D:\Hyper-V',
        [Parameter(HelpMessage = 'The default path where virtual hard disks will be stored')]
        [String]
        $VirtualHardDiskPath = 'D:\Hyper-V\Virtual Hard Disks',
        [Parameter(HelpMessage = 'The default path where ISO installation media files will be stored')]
        [String]
        $InstallMediaPath = 'C:\Users\Public\Documents\ISO',
        [Parameter(HelpMessage = 'The folder in which DSC will store MOF file(s) (normally no need to change this)')]
        [String]
        $OutputPath = "$env:temp\dsc"
    )

    if (-not $ExternalVirtualSwitchNics) {
        Get-NetAdapter | Sort-Object Name | Format-Table Name, Status, MacAddress, LinkSpeed -AutoSize
        $ExternalVirtualSwitchNics = Read-Host 'Which NIC(s) belong to the team that handles virtual machines (e.g. NIC2,NIC3,NIC4)?'
    }

    if (-not $VirtualHardDiskStorageDisks) {
        Get-Disk | Where-Object { $_.BusType -ne 'USB' } | Sort-Object Size -Descending | Format-Table UniqueId, FriendlyName, BusType, @{name = "Size (GB)"; Expression = { ($_.Size / 1GB).ToString('#.##') } }
        Write-Host 'Important: You need to provide at least one unique ID here. If you have multiple disks'
        Write-Host 'that you wish to use for virtual hard disk storage you can separate unique IDs using'
        Write-Host 'commas with no spaces. Include your fastest disk first and then slower disk(s).'
        Write-Host ''
        Write-Host 'ANY DISKS CHOSEN HERE WILL BE FORMATTED!!!' -ForegroundColor Yellow
        Write-Host ''
        $VirtualHardDiskStorageDisks = Read-Host "Unique ID(s) of data disk(s)?"
    }

    Exceedio2022Hypervisor `
        -ComputerName $ComputerName `
        -LocalAdminCredential $LocalAdminCredential `
        -VirtualHardDiskStorageDisks $VirtualHardDiskStorageDisks `
        -ExternalVirtualSwitchNics $ExternalVirtualSwitchNics `
        -ExternalVirtualSwitchName $ExternalVirtualSwitchName `
        -VirtualMachinePath $VirtualMachinePath `
        -VirtualHardDiskPath $VirtualHardDiskPath `
        -InstallMediaPath $InstallMediaPath `
        -OutputPath $OutputPath

    Set-DscLocalConfigurationManager -Path $OutputPath
    Start-DscConfiguration -Path $OutputPath -Force -Wait -Verbose
}

function Initialize-ExceedioMemberServer {

}

function New-ExceedioVM {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, HelpMessage = 'Name of new virtual machine (e.g. VM12345)')]
        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerName,
        [Parameter(HelpMessage = 'Number of processor cores to assign (defaults to 4)')]
        [UInt32]
        [ValidateRange(1, 256)]
        $Cores = 4,
        [Parameter(HelpMessage = 'Amount of memory to assign (defaults to 8GB)')]
        [UInt64]
        $Memory = 8GB,
        [Parameter(HelpMessage = 'The path at which the OS virtual hard disk will be created')]
        [String]
        $OSDiskPath = 'D:\Hyper-V\Virtual Hard Disks',
        [UInt64]
        $OSDiskSizeBytes = 120GB,
        [Parameter(HelpMessage = 'The path at which the Data virtual hard disk will be created')]
        [String]
        $DataDiskPath = 'D:\Hyper-V\Virtual Hard Disks',
        [Parameter()]
        [UInt64]
        $DataDiskSizeBytes = 0,
        [Parameter(HelpMessage = 'The virtual switch to which the virtual machine will be attached')]
        [String]
        $Switch = 'External Virtual Switch',
        [Parameter(HelpMessage = 'The VLAN on which the virtual machine will be placed by default')]
        [String]
        $VlanId = '1',
        [Parameter(HelpMessage = 'The ISO that will be attached to the virtual machine for OS installation')]
        [String]
        $InstallMediaISOPath = 'C:\Users\Public\Documents\ISO\SW_DVD9_Win_Server_STD_CORE_2022_2108.18_64Bit_English_DC_STD_MLF_X23-37922.iso',
        [Parameter(HelpMessage = 'Indicates whether the new VM will be a domain controller')]
        [Boolean]
        $IsDomainController = $false,
        [Parameter(HelpMessage = 'The number of seconds to delay upon hypervisor startup before starting this virtual machine (defaults to 0 for domain controllers, otherwise 60)')]
        [Int32]
        $AutomaticStartDelayInSeconds = 60,
        [Parameter(HelpMessage = 'The folder in which DSC will store MOF file(s) (normally no need to change this)')]
        [String]
        $OutputPath = "$env:temp\dsc"
    )

    <#
    .SYNOPSIS
        Creates a new virtual machine.
    .DESCRIPTION
        Use this function to create a new virtual machine on a Windows Server 2022 or later Hyper-V server.
    .EXAMPLE
        New-ExceedioVM -ComputerName VM12345
    .EXAMPLE
        New-ExceedioVM -ComputerName VM12345 -Cores 2 -Memory 2GB
    .EXAMPLE
        New-ExceedioVM -ComputerName VM12345 -Cores 2 -Memory 2GB -VlanId 20
    .EXAMPLE
        New-ExceedioVM -ComputerName VM12345 -IsDomainController $true
    .EXAMPLE
        New-ExceedioVM -ComputerName VM12345 -InstallMediaISOPath C:\Users\Public\Downloads\alpine-linux.iso
    #>

    Exceedio2022VirtualMachine `
        -ComputerName $ComputerName `
        -OSDiskPath $OSDiskPath `
        -OSDiskSizeBytes $OSDiskSizeBytes `
        -DataDiskPath $DataDiskPath `
        -DataDiskSizeBytes $DataDiskSizeBytes `
        -Cores $Cores `
        -Memory $Memory `
        -Switch $Switch `
        -VlanId $VlanId `
        -InstallMediaISOPath $InstallMediaISOPath `
        -IsDomainController $IsDomainController `
        -AutomaticStartDelayInSeconds $AutomaticStartDelayInSeconds `
        -OutputPath $OutputPath

    Set-DscLocalConfigurationManager -Path $OutputPath
    Start-DscConfiguration -Path $OutputPath -Force -Wait -Verbose
}