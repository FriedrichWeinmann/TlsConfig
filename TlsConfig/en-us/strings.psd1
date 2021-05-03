# This is where the strings go, that are written by
# Write-PSFMessage, Stop-PSFFunction or the PSFramework validation scriptblocks
@{
	'Test-TlsProtocol.Tcp.Failed' = 'Failed to connect to {0} on port {1}: {2}' # $computer, $port, $_.Exception.GetBaseException().Message
}