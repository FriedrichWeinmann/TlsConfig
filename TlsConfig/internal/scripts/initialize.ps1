if (-not (Get-PSFConfigValue -FullName 'TlsConfig.Disable.Auto1_2')) {
    Set-TlsProcessConfiguration -AddSecurityProtocol TLS12
}