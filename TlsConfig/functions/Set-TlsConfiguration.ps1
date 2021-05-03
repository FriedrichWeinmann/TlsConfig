function Set-TlsConfiguration {
    <#
    .SYNOPSIS
        Change the allowed ssl/tls protocols and cipher suites.
    
    .DESCRIPTION
        Change the allowed ssl/tls protocols and cipher suites.
        Note: Most changes require a restart of the target computer.
        
    .PARAMETER ComputerName
        The computer to process.
        Defaults to localhost.
    
    .PARAMETER Enable
        Which protocol/cipher suite to enable.
    
    .PARAMETER Disable
        Which protocol/cipher suite to disable.
    
    .PARAMETER EnableSecure
        Enable all protocols considered secure.
        - Configures .NET to use strong cryptography by default.
        - Enables TLS1.2
    
    .PARAMETER DisableSecure
        Disable all protocols considered secure.
        - Configures .NET to NOT use strong cryptography by default.
        - Disables TLS1.2
        Why the heck would you do this?!
    
    .PARAMETER EnableInsecure
        Enable all protocols and cipher suites considered insecure.
        - Enables SSL2.0 & 3.0
        - Enables TLS1.0 & 1.1
        - Enables RC2 / RC4 / DES
        Only use this if you need to temporarily roll back after all.
    
    .PARAMETER DisableInsecure
        Disable all protocols and cipher suites considered insecure.
        - Disables SSL2.0 & 3.0
        - Disables TLS1.0 & 1.1
        - Disables RC2 / RC4 / DES
        Yehaw!
    
    .EXAMPLE
        PS C:\> Set-TlsConfiguration -EnableSecure -DisableInsecure

        Secures the allowed network protocols on the local computer.

    .EXAMPLE
        PS C:\> Set-TlsConfiguration -EnableSecure -DisableInsecure -ComputerName (Get-ADComputer -Filter *)

        Secures all computers in the entire active directory domain.
    #>
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline = $true)]
        [PSFComputer[]]
        $ComputerName = $env:COMPUTERNAME,

        [ValidateSet('TLS1_2Client', 'TLS1_2Server', 'StrongCrypto_35', 'StrongCrypto_45', 'StrongCrypto_x86_35', 'StrongCrypto_x86_45', 'DES_56_56', 'RC2_128_128', 'RC2_40_128', 'RC2_56_128', 'RC4_128_128', 'RC4_40_128', 'RC4_56_128', 'RC4_64_128', 'SSL3Client', 'SSL3Server', 'TLS1_0Client', 'TLS1_0Server', 'TLS1_1Client', 'TLS1_1Server', 'SSL2Client', 'SSL2Server')]
        [string[]]
        $Enable,

        [ValidateSet('TLS1_2Client', 'TLS1_2Server', 'StrongCrypto_35', 'StrongCrypto_45', 'StrongCrypto_x86_35', 'StrongCrypto_x86_45', 'DES_56_56', 'RC2_128_128', 'RC2_40_128', 'RC2_56_128', 'RC4_128_128', 'RC4_40_128', 'RC4_56_128', 'RC4_64_128', 'SSL3Client', 'SSL3Server', 'TLS1_0Client', 'TLS1_0Server', 'TLS1_1Client', 'TLS1_1Server', 'SSL2Client', 'SSL2Server')]
        [string[]]
        $Disable,

        [switch]
        $EnableSecure,

        [switch]
        $DisableSecure,

        [switch]
        $EnableInsecure,

        [switch]
        $DisableInsecure
    )
	
    begin {
        #region Remote Scriptblock
        $setCode = {
            param (
                $Parameters
            )

            #region Locations
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
            #endregion Locations

            #region Enable Protocols
            $toEnable = @()
            foreach ($protocol in $Parameters.Enable) {
                $toEnable += $protocol
            }
            if ($Parameters.EnableSecure) {
                $toEnable += $Parameters.SecureOptions
            }
            if ($Parameters.EnableInsecure) {
                $toEnable += $Parameters.InsecureOptions
            }

            foreach ($protocol in $toEnable) {
                $location = $registryLocations | Where-Object { $_.Name -eq $protocol }

                if (-not (Test-Path -Path $location.Key)) {
                    $null = New-Item -Path $location.Key -Force
                }

                Set-ItemProperty -Path $location.Key -Name $location.Property -Value 1
            }
            #endregion Enable Protocols

            #region Disable Protocols
            $toDisable = @()
            foreach ($protocol in $Parameters.Disable) {
                $toDisable += $protocol
            }
            if ($Parameters.DisableSecure) {
                $toDisable += $Parameters.SecureOptions
            }
            if ($Parameters.DisableInsecure) {
                $toDisable += $Parameters.InsecureOptions
            }

            foreach ($protocol in $toDisable) {
                $location = $registryLocations | Where-Object { $_.Name -eq $protocol }

                if (-not (Test-Path -Path $location.Key)) {
                    $null = New-Item -Path $location.Key -Force
                }

                Set-ItemProperty -Path $location.Key -Name $location.Property -Value 0
            }
            #endregion Disable Protocols
        }
        #region Remote Scriptblock
        
        $parameters = $PSBoundParameters | ConvertTo-PSFHashtable -Include Enable, Disable, EnableSecure, DisableSecure, EnableInsecure, DisableInsecure
        $parameters += @{
            SecureOptions   = 'TLS1_2Client', 'TLS1_2Server', 'StrongCrypto_35', 'StrongCrypto_45', 'StrongCrypto_x86_35', 'StrongCrypto_x86_45'
            InsecureOptions = 'DES_56_56', 'RC2_128_128', 'RC2_40_128', 'RC2_56_128', 'RC4_128_128', 'RC4_40_128', 'RC4_56_128', 'RC4_64_128', 'SSL3Client', 'SSL3Server', 'TLS1_0Client', 'TLS1_0Server', 'TLS1_1Client', 'TLS1_1Server', 'SSL2Client', 'SSL2Server'
        }
    }
    process {
        Invoke-PSFCommand -ComputerName $ComputerName -ScriptBlock $setCode -ArgumentList $parameters
    }
}
