function Test-TlsProtocol {
    <#
        .SYNOPSIS
            A quick helper function to test supported TLS protocols
        
        .DESCRIPTION
            A quick helper function to test supported TLS protocols
        
        .PARAMETER ComputerName
            The hosts to check.
        
        .PARAMETER Port
            The Port to test against.
            Defaults to 443
        
        .EXAMPLE
            PS C:\> Test-TlsProtocol -ComputerName 'contoso.com'
        
            Tests contoso.com's supported TLS protocols (at least as far as the service listening on Port 443 is concerned).
    #>
        [CmdletBinding()]
        param (
            [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
            [ValidateNotNullOrEmpty()]
            [string[]]
            $ComputerName,
            
            [UInt16]
            $Port = 443
        )
        begin {
            $tlsProtocols = [enum]::GetNames([System.Security.Authentication.SslProtocols]) | Where-Object { $_ -ne 'None' }
            $certificateCallback = [System.Net.Security.RemoteCertificateValidationCallback]{ $true }
        }
        process {
            :main foreach ($computer in $ComputerName) {
                $results = @{
                    Host          = $computer
                    Port          = $Port
                    KeyExhange    = $null
                    HashAlgorithm = $null
                    Error          = @{ }
                }
                
                foreach ($tlsProtocol in $tlsProtocols) {
                    $tcpClient = [Net.Sockets.TcpClient]::new()
                    try { $tcpClient.Connect($computer, $Port) }
                    catch {
                        $tcpClient.Dispose()
                        Write-Warning "[$computer] Error connecting: $($_.Exception.GetBaseException().Message)"
                        Write-Error $_
                        if ($_.Exception.InnerException.SocketErrorCode -eq 'HostNotFound') { continue main }
                        continue
                    }
                    
                    $sslStream = [Net.Security.SslStream]::new(
                        $tcpClient.GetStream(),
                        $true,
                        $certificateCallback
                    )
                    
                    try {
                        $sslStream.AuthenticateAsClient($results.Host, $null, $tlsProtocol, $false)
                        $results.KeyExhange = $sslStream.KeyExchangeAlgorithm
                        $results.HashAlgorithm = $sslStream.HashAlgorithm
                        $results.$tlsProtocol = $true
                    }
                    catch {
                        $results.$tlsProtocol = $false
                        $results.Error.$tlsProtocol = $_
                    }
                    finally {
                        $tcpClient.Dispose()
                        $sslStream.Dispose()
                    }
                }
                
                [pscustomobject]$results
            }
        }
    }