function ConvertFrom-RawTlsData {
    <#
    .SYNOPSIS
        Converts raw tls information objects into structured, processed data.
    
    .DESCRIPTION
        Converts raw tls information objects into structured, processed data.
    
    .PARAMETER InputObject
        The TLS configuration object returned from the remote hosts.
    
    .EXAMPLE
        PS C:\> $data | ConvertFrom-RawTlsData

        Converts raw tls information objects into structured, processed data.
    #>
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline = $true)]
        $InputObject
    )

    process {
        foreach ($object in $InputObject) {
            $object.PSObject.TypeNames.Insert(0, 'TLS.Configuration')

            Add-Member -InputObject $object -MemberType ScriptProperty -Name SecureOnly -Value {
                $default = $false

                # Shouldn't disable good stuff
                if ($this.StrongCrypto_35 -eq "Disabled") { return $default }
                if ($this.StrongCrypto_45 -eq "Disabled") { return $default }
                if ($this.StrongCrypto_x86_35 -eq "Disabled") { return $default }
                if ($this.StrongCrypto_x86_45 -eq "Disabled") { return $default }
                if ($this.TLS1_2Client -eq "Disabled") { return $default }
                if ($this.TLS1_2Server -eq "Disabled") { return $default }

                # Insecure Protocols / Ciphers are bad
                if ($this.DES_56_56 -eq "Enabled") { return $default }
                if ($this.RC2_128_128 -eq "Enabled") { return $default }
                if ($this.RC2_40_128 -eq "Enabled") { return $default }
                if ($this.RC2_56_128 -eq "Enabled") { return $default }
                if ($this.RC4_128_128 -eq "Enabled") { return $default }
                if ($this.RC4_40_128 -eq "Enabled") { return $default }
                if ($this.RC4_56_128 -eq "Enabled") { return $default }
                if ($this.RC4_64_128 -eq "Enabled") { return $default }
                if ($this.SSL2Client -eq "Enabled") { return $default }
                if ($this.SSL2Server -eq "Enabled") { return $default }
                if ($this.SSL3Client -eq "Enabled") { return $default }
                if ($this.SSL3Server -eq "Enabled") { return $default }
                if ($this.TLS1_0Client -eq "Enabled") { return $default }
                if ($this.TLS1_0Server -eq "Enabled") { return $default }
                if ($this.TLS1_1Client -eq "Enabled") { return $default }
                if ($this.TLS1_1Server -eq "Enabled") { return $default }

                $true
            }

            Add-Member -InputObject $object -MemberType ScriptProperty -Name SecureEnabled -Value {
                # Shouldn't disable good stuff
                if ($this.StrongCrypto_35 -eq "Disabled") { return $false }
                if ($this.StrongCrypto_45 -eq "Disabled") { return $false }
                if ($this.StrongCrypto_x86_35 -eq "Disabled") { return $false }
                if ($this.StrongCrypto_x86_45 -eq "Disabled") { return $false }
                if ($this.TLS1_2Client -eq "Disabled") { return $false }
                if ($this.TLS1_2Server -eq "Disabled") { return $false }

                $true
            }

            Add-Member -InputObject $object -MemberType ScriptProperty -Name InsecureEnabled -Value {
                $default = $true
                
                # Insecure Protocols / Ciphers are bad
                if ($this.DES_56_56 -eq "Enabled") { return $default }
                if ($this.RC2_128_128 -eq "Enabled") { return $default }
                if ($this.RC2_40_128 -eq "Enabled") { return $default }
                if ($this.RC2_56_128 -eq "Enabled") { return $default }
                if ($this.RC4_128_128 -eq "Enabled") { return $default }
                if ($this.RC4_40_128 -eq "Enabled") { return $default }
                if ($this.RC4_56_128 -eq "Enabled") { return $default }
                if ($this.RC4_64_128 -eq "Enabled") { return $default }
                if ($this.SSL2Client -eq "Enabled") { return $default }
                if ($this.SSL2Server -eq "Enabled") { return $default }
                if ($this.SSL3Client -eq "Enabled") { return $default }
                if ($this.SSL3Server -eq "Enabled") { return $default }
                if ($this.TLS1_0Client -eq "Enabled") { return $default }
                if ($this.TLS1_0Server -eq "Enabled") { return $default }
                if ($this.TLS1_1Client -eq "Enabled") { return $default }
                if ($this.TLS1_1Server -eq "Enabled") { return $default }

                $false
            }

            $object
        }
    }
}