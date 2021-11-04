<#
    .SYNOPSIS
        Windows Server hardening script

    .DESCRIPTION
    This script will harden Windows Server 2008 R2 and above. It is based on a small subset of the CIS standards.
    The following changes are made:
    * Disable insecure encryption protocols
    * Disable frequently unused services

    .EXAMPLE
    .\Set-WIndowsHardening.ps1
    This will apply the changes to the local server or workstation.

    .EXAMPLE
    .\Set-WindowsHardening.ps1 -Rollback
    This will reverse the hardening changes to the default values in case of issues arising from hardening.
    Note that this will not guarantee that the server will be in the same state as prior to hardening, it is setting default values only.

    .NOTES
        Author          : Glen Buktenica
        License         : MIT
        Initial Release : 2017 05 24
        Version         : 2021 11 04
        Repository      : https://github.com/gbuktenica/HardenWindows
#>
[CmdletBinding()]
param (
    [switch]$Rollback
)
function Disable-Cryptography {
    param (
        [switch]$Rollback
    )
    $sChannel = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL"
    if ($Rollback ) {
        $Enabled = "1"
        $DisabledByDefault = "1"
        $Action = "Enabling"
    } else {
        $Enabled = "0"
        $DisabledByDefault = "1"
        $Action = "Disabling"
    }
    $Hashes = "Hashes\MD5"
    foreach ($Hash in $Hashes) {
        if (-not (Test-Path "$sChannel\$Hash" -ErrorAction SilentlyContinue)) {
            Write-Host "Creating key: $sChannel\$Hash"
            New-Item -Path "$sChannel\$Hash" -ErrorAction Stop | Out-Null
        }
        if ((Get-ItemProperty -Path "$sChannel\$Hash" -ErrorAction SilentlyContinue).Enabled -ne $Enabled) {
            Write-Host "$Action Hash: $Hash"
            New-ItemProperty -Path "$sChannel\$Hash" -Name Enabled -Value $Enabled -Force -PropertyType DWord | Out-Null
        }
    }

    $Ciphers = @()
    $Ciphers += "DES 56/56"
    $Ciphers += "NULL"
    $Ciphers += "RC2 128/128"
    $Ciphers += "RC2 40/128"
    $Ciphers += "RC2 56/128"
    $Ciphers += "RC4 128/128"
    $Ciphers += "RC4 40/128"
    $Ciphers += "RC4 56/128"
    $Ciphers += "RC4 64/128"

    # Note the following OpenSubKey and CreateSubKey methods are required as New-Item does not support forward slashes even when escaped.
    $Key = (Get-Item HKLM:\).OpenSubKey("SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers", $true)
    foreach ($Cipher in $Ciphers) {
        if (-not (Test-Path "$sChannel\Ciphers\$Cipher" -ErrorAction SilentlyContinue)) {
            Write-Host "Creating key: $sChannel\Ciphers\$Cipher"
            $Key.CreateSubKey($Cipher)
        }
        $EscapedCipher = $Cipher.Replace("/", "\\/")
        if ((Get-ItemProperty -Path "$sChannel\Ciphers\$EscapedCipher" -ErrorAction SilentlyContinue).Enabled -ne "0") {
            Write-Host "$Action Cipher: $Cipher"
            New-ItemProperty -Path "$sChannel\Ciphers\$EscapedCipher" -Name Enabled -Value $Enabled -Force -PropertyType DWord | Out-Null
        }
    }
    $Key.Close()

    $Protocols = @()
    $Protocols += "Multi-Protocol Unified Hello"
    $Protocols += "PCT 1.0"
    $Protocols += "SSL 2.0"
    $Protocols += "SSL 3.0"
    $Protocols += "TLS 1.0"
    $Protocols += "TLS 1.1"
    $Protocols += "TLS 1.2"

    foreach ($Protocol in $Protocols) {
        if (-not (Test-Path "$sChannel\Protocols\$Protocol" -ErrorAction SilentlyContinue)) {
            Write-Host "Creating key: $sChannel\Protocols\$Protocol"
            New-Item -Path "$sChannel\Protocols\$Protocol" -ErrorAction Stop | Out-Null
        }
        if (-not (Test-Path "$sChannel\Protocols\$Protocol\Server" -ErrorAction SilentlyContinue)) {
            Write-Host "Creating key: $sChannel\Protocols\$Protocol\Server"
            New-Item -Path "$sChannel\Protocols\$Protocol\Server" -ErrorAction Stop | Out-Null
        }
        if ((Get-ItemProperty -Path "$sChannel\Protocols\$Protocol\Server" -ErrorAction SilentlyContinue).Enabled -ne $Enabled -and $Protocol -ne "TLS 1.2") {
            Write-Host "$Action Protocol: $Protocol"
            New-ItemProperty -Path "$sChannel\Protocols\$Protocol\Server" -Name Enabled -Value $Enabled -Force -PropertyType DWord | Out-Null
            New-ItemProperty -Path "$sChannel\Protocols\$Protocol\Server" -Name DisabledByDefault -Value $DisabledByDefault -Force -PropertyType DWord | Out-Null
        }
    }
    if ((Get-ItemProperty -Path "$sChannel\Protocols\TLS 1.2\Server" -ErrorAction SilentlyContinue).Enabled -ne "1" ) {
        Write-Host "Enabling Protocol: TLS 1.2"
        New-ItemProperty -Path "$sChannel\Protocols\TLS 1.2\Server" -Name Enabled -Value 0x00000001 -Force -PropertyType DWord | Out-Null
        New-ItemProperty -Path "$sChannel\Protocols\TLS 1.2\Server" -Name DisabledByDefault -Value 0x00000000 -Force -PropertyType DWord | Out-Null
    }
}

function Disable-Services {
    param (
        [switch]$Rollback
    )
    $Services = @()
    $Services += "Application Layer Gateway Service"
    $Services += "Auto Time Zone Updater"
    $Services += "AVCTP Service"
    $Services += "Bluetooth Audio Gateway Service"
    $Services += "Bluetooth Support Service"
    $Services += "Certificate Propagation"
    $Services += "Device Management Enrollment Service"
    $Services += "Diagnostic Policy Service"
    $Services += "Diagnostic Service Host"
    $Services += "Diagnostic System Host"
    $Services += "Distributed Link Tracking Client"
    $Services += "Download Maps Manager"
    $Services += "Geolocation Service"
    $Services += "Microsoft Account Sign-in Assistant"
    $Services += "Offline Files"
    $Services += "Payments and NFC/SE Manager"
    $Services += "Phone Service"
    $Services += "Program Compatibility Assistant Service"
    $Services += "Remote Registry"
    $Services += "Routing and Remote Service"
    $Services += "Secondary Logon"
    $Services += "Sensor Service"
    $Services += "Smartcard"
    $Services += "Sysmain"
    $Services += "WalletService"
    $Services += "Windows Biometric Service"
    $Services += "Windows Camera Frame Server"
    $Services += "Windows Error Reporting Service"
    $Services += "Windows Image Acquisition"
    $Services += "Windows Insider Service"
    $Services += "Windows Media Player Network Sharing Service"
    $Services += "Windows Mobile Hotspot Service"
    $Services += "Windows Search"

    if ($Rollback) {
        foreach ($Service in $Services) {
            $ServiceObject = Get-Service -DisplayName $Service -ErrorAction SilentlyContinue | Select-Object Name, StartType, Status
            if ($ServiceObject.StartType -eq "Disabled" -and ($ServiceObject.Name).length -gt 0) {
                Write-Output "Enabling Service: $Service"
                Set-Service -Name $ServiceObject.Name -StartupType Manual
            }
        }
    } else {
        foreach ($Service in $Services) {
            $ServiceObject = Get-Service -DisplayName $Service -ErrorAction SilentlyContinue | Select-Object Name, StartType, Status
            if ($ServiceObject.Status -eq "Running") {
                Write-Output "Stopping Service: $Service"
                Stop-Service -DisplayName $Service
            }
            if ($ServiceObject.StartType -ne "Disabled" -and ($ServiceObject.Name).length -gt 0) {
                Write-Output "Disabling Service: $Service"
                Set-Service -Name $ServiceObject.Name -StartupType Disabled
            }
        }
    }
}
Write-Output "Disabling Cryptography"
Disable-Cryptography -Rollback:$Rollback
Write-Output "Disabling Services"
Disable-Services -Rollback:$Rollback
