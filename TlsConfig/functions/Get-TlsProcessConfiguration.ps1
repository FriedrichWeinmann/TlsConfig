function Get-TlsProcessConfiguration {
    <#
    .SYNOPSIS
        Get the current processes' network security settings.
    
    .DESCRIPTION
        Get the current processes' network security settings.
    
    .EXAMPLE
        PS C:\> Get-TlsProcessConfiguration

        Get the current processes' network security settings.
    #>
    [CmdletBinding()]
    param ( )

    process {
        $spm = [System.Net.ServicePointManager]
        [PSCustomObject]@{
            CheckCertificateRevocationList      = $spm::CheckCertificateRevocationList
            DefaultConnectionLimit              = $spm::DefaultConnectionLimit
            DefaultNonPersistentConnectionLimit = $spm::DefaultNonPersistentConnectionLimit
            DefaultPersistentConnectionLimit    = $spm::DefaultPersistentConnectionLimit
            DnsRefreshTimeout                   = $spm::DnsRefreshTimeout
            EnableDnsRoundRobin                 = $spm::EnableDnsRoundRobin
            EncryptionPolicy                    = $spm::EncryptionPolicy
            Expect100Continue                   = $spm::Expect100Continue
            MaxServicePointIdleTime             = $spm::MaxServicePointIdleTime
            MaxServicePoints                    = $spm::MaxServicePoints
            ReusePort                           = $spm::ReusePort
            SecurityProtocol                    = $spm::SecurityProtocol
            ServerCertificateValidationCallback = $spm::ServerCertificateValidationCallback
            UseNagleAlgorithm                   = $spm::UseNagleAlgorithm
        }
    }
}