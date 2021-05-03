function Get-TlsConfiguration {
    <#
    .SYNOPSIS
        Read the actually deployed TLS configuration from the registry of the target host.
    
    .DESCRIPTION
        Read the actually deployed TLS configuration from the registry of the target host.
        Specifically returns information on:
        - Strong Crypto enabled in .NET
        - TLS 1.0/1.1/1.2 Enabled registry keys
        - SSL 2.0/3.0 Enabled registry keys
        - RC2/RC4/DES Cypher Suites
    
    .PARAMETER ComputerName
        The computers to scan
    
    .EXAMPLE
        PS C:\> Get-TlsConfiguration

        Read the actually deployed TLS configuration from the registry of the local computer.

    .EXAMPLE
        PS C:\> Get-TlsConfiguration -ComputerName (Get-ADComputer -Filter *)

        Read the actually deployed TLS configuration for every single computer in the current domain.
    #>
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline = $true)]
        [PSFComputer[]]
        $ComputerName = $env:COMPUTERNAME
    )
	
    begin {
        #region Gather Code
		$gatherCode = {
            $registryLocations = @(
                @{ Name = 'SSL2Client'; Property = 'Enabled'; Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' }
                @{ Name = 'SSL2Server'; Property = 'Enabled'; Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' }
                @{ Name = 'SSL3Client'; Property = 'Enabled'; Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' }
                @{ Name = 'SSL3Server'; Property = 'Enabled'; Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' }
                @{ Name = 'TLS1_0Client'; Property = 'Enabled'; Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' }
                @{ Name = 'TLS1_0Server'; Property = 'Enabled'; Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' }
                @{ Name = 'TLS1_1Client'; Property = 'Enabled'; Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' }
                @{ Name = 'TLS1_1Server'; Property = 'Enabled'; Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' }
                @{ Name = 'TLS1_2Client'; Property = 'Enabled'; Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' }
                @{ Name = 'TLS1_2Server'; Property = 'Enabled'; Key = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' }
                @{ Name = 'RC2_40_128'; Property = 'Enabled'; Key = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40$([char]0x2215)128" }
                @{ Name = 'RC2_56_128'; Property = 'Enabled'; Key = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56$([char]0x2215)128" }
                @{ Name = 'RC2_128_128'; Property = 'Enabled'; Key = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128$([char]0x2215)128" }
                @{ Name = 'RC4_40_128'; Property = 'Enabled'; Key = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40$([char]0x2215)128" }
                @{ Name = 'RC4_56_128'; Property = 'Enabled'; Key = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56$([char]0x2215)128" }
                @{ Name = 'RC4_64_128'; Property = 'Enabled'; Key = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64$([char]0x2215)128" }
                @{ Name = 'RC4_128_128'; Property = 'Enabled'; Key = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128$([char]0x2215)128" }
                @{ Name = 'DES_56_56'; Property = 'Enabled'; Key = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56$([char]0x2215)56" }
                @{ Name = 'StrongCrypto_35'; Property = 'SchUseStrongCrypto'; Key = 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727'; NullIsDisabled = $true }
                @{ Name = 'StrongCrypto_45'; Property = 'SchUseStrongCrypto'; Key = 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319'; NullIsDisabled = $true }
                @{ Name = 'StrongCrypto_x86_35'; Property = 'SchUseStrongCrypto'; Key = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727'; NullIsDisabled = $true }
                @{ Name = 'StrongCrypto_x86_45'; Property = 'SchUseStrongCrypto'; Key = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319'; NullIsDisabled = $true }
            )
            $enabledHash = @{
                $false = 'Disabled'
                $true = 'Enabled'
                0 = 'Disabled'
                1 = 'Enabled'
            }
            $results = @{
                ComputerName = $env:COMPUTERNAME
            }
            foreach ($location in $registryLocations) {
                if (-not (Test-Path -Path $location.Key)) {
                    $results[$location.Name] = $enabledHash[(-not $location.NullIsDisabled)]
                    continue
                }
                $properties = Get-ItemProperty -Path $location.Key
                if ($properties.PSObject.Properties.Name -notcontains $location.Property) {
                    $results[$location.Name] = $enabledHash[(-not $location.NullIsDisabled)]
                    continue
                }
                $results[$location.Name] = $enabledHash[$properties.$($location.Property)]
            }
            [PSCustomObject]$results
        }
        #endregion Gather Code
    }
    process {
        Invoke-PSFCommand -ComputerName $ComputerName -ScriptBlock $gatherCode | ConvertFrom-RawTlsData
    }
}
