function Set-TlsProcessConfiguration {
    <#
    .SYNOPSIS
        Configure local process network tls settings.
    
    .DESCRIPTION
        Configure local process network tls settings.
        This specifically allows you to define allowed TLS protocols, override certificate validation, port reuse and all the other myriad of settings supported by .NET.
    
    .PARAMETER CheckCertificateRevocationList
    	Sets a Boolean value that indicates whether the certificate is checked against the certificate authority revocation list.

    .PARAMETER DefaultConnectionLimit
    	Sets the maximum number of concurrent connections allowed by a ServicePoint object.

    .PARAMETER DnsRefreshTimeout
    	Sets a value that indicates how long a Domain Name Service (DNS) resolution is considered valid.

    .PARAMETER EnableDnsRoundRobin
    	Sets a value that indicates whether a Domain Name Service (DNS) resolution rotates among the applicable Internet Protocol (IP) addresses.

    .PARAMETER Expect100Continue
    	Sets a Boolean value that determines whether 100-Continue behavior is used.

    .PARAMETER MaxServicePointIdleTime
    	Sets the maximum idle time of a ServicePoint object.

    .PARAMETER MaxServicePoints
    	Sets the maximum number of ServicePoint objects to maintain at any time.

    .PARAMETER ReusePort
    	Setting this property value to true causes all outbound TCP connections from HttpWebRequest to use the native socket option SO_REUSE_UNICASTPORT on the socket. This causes the underlying outgoing ports to be shared. This is useful for scenarios where a large number of outgoing connections are made in a short time, and the app risks running out of ports.

    .PARAMETER AddSecurityProtocol
    	Adds a security protocol used by the ServicePoint objects managed by the ServicePointManager object.

    .PARAMETER RemoveSecurityProtocol
        Removes a security protocol used by the ServicePoint objects managed by the ServicePointManager object.

    .PARAMETER ServerCertificateValidationCallback
    	Set the validation logic used to validate certificates in https connections.
        Set it to { $true } to disable validation.

    .PARAMETER UseNagleAlgorithm
    	Determines whether the Nagle algorithm is used by the service points managed by this ServicePointManager object.

    .EXAMPLE
        PS C:\> Set-TlsProcessConfiguration -AddSecurityProtocol Tls12

        Addes TLS1.2 to the list of protocols used.
    #>
    [CmdletBinding()]
    param (
        [System.Boolean]
        $CheckCertificateRevocationList,

        [System.Int32]
        $DefaultConnectionLimit,

        [System.Int32]
        $DnsRefreshTimeout,

        [System.Boolean]
        $EnableDnsRoundRobin,

        [System.Boolean]
        $Expect100Continue,

        [System.Int32]
        $MaxServicePointIdleTime,

        [System.Int32]
        $MaxServicePoints,

        [System.Boolean]
        $ReusePort,

        [System.Net.SecurityProtocolType]
        $AddSecurityProtocol,

        [System.Net.SecurityProtocolType]
        $RemoveSecurityProtocol,

        [scriptblock]
        $ServerCertificateValidationCallback,

        [System.Boolean]
        $UseNagleAlgorithm
    )

    begin {
        $commonParam = 'Verbose','Debug','ErrorAction','WarningAction','InformationAction','ErrorVariable','WarningVariable','InformationVariable','OutVariable','OutBuffer','PipelineVariable','Confirm','WhatIf'
    }
    process {
        foreach ($parameter in $PSBoundParameters.GetEnumerator()) {
            if ($parameter.Key -in $commonParam) { continue }
            switch ($parameter.Key) {
                'AddSecurityProtocol' { [System.Net.ServicePointManager]::SecurityProtocol += $parameter.Value }
                'RemoveSecurityProtocol' { [System.Net.ServicePointManager]::SecurityProtocol -= $parameter.Value }
                default { [System.Net.ServicePointManager]::$($parameter.Key) = $parameter.Value }
            }
        }
    }
}