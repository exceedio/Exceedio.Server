# Exceedio.Server

This module is designed to configure physical servers (e.g. Dell) and create and configure virtual servers.

## Installation

Run the following command in an elevated PowerShell session to install the module:

```powershell
Install-Module -Name Exceedio.Server
```

This module runs on Windows PowerShell 5.1 with [.NET Framework 4.7.2](https://dotnet.microsoft.com/download/dotnet-framework-runtime) or greater.

If you have an earlier version of the Exceedio Exchange PowerShell module installed from the PowerShell Gallery and would like to update to the latest version, run the following commands in an elevated PowerShell session:

```powershell
Update-Module -Name Exceedio.Server
```

`Update-Module` installs the new version side-by-side with previous versions. It does not uninstall the previous versions.

## Usage

Open an elevated PowerShell prompt and use ```Import-Module -Name Exceedio.Server``` before doing anything else.

### Initialize a Windows Server 2022 Physical Server

Using defaults:

```powershell
Initialize-ExceedioHypervisor -ComputerName SV12345 -LocalAdminCredential (Get-Credential)
```

Using all possible options:

```powershell
Initialize-ExceedioHypervisor `
  -ComputerName SV12345 `
  -LocalAdminCredential (Get-Credential) `
  -VirtualHardDiskStorageDisks '5002538E409D13D2,5002538E409D13D3' `
  -ExternalVirtualSwitchNics 'NIC2,NIC3,NIC4' `
  -ExternalVirtualSwitchName 'External Virtual Switch' `
  -VirtualMachinePath 'D:\Hyper-V' `
  =VirtualHardDiskPath 'D:\Hyper-V\Virtual Hard Disks' `
  -InstallMediaPath 'C:\Users\Public\Documents\ISO'
```

You'll be prompted to answer some questions if the answers weren't provided as command line parameters. Specifically, you'll need to provide a comma-separated list of network interfaces to be used for VM traffic (e.g. NIC2,NIC3,NIC4) as well as a comma-separated list of disk IDs to be used for VM disk storage. You'll be presented with a list of possible disks to help make selection easier.