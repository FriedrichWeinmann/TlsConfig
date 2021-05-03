# TlsConfig

Module to manage your TLS configuration, by managing both security protocols and cipher suites used.

## Install

To install the module, run:

```powershell
Install-Module TlsConfig
```

## Use

### Read Configuration

```powershell
# Get configuration of current computer
Get-TlsConfiguration

# Get configuration of ALL domain computers
Get-TlsConfiguration -ComputerName (Get-ADComputer -Filter *)
```

### Write Configuration

```powershell
# Enable secure protocols without disabling insecure protocols
Set-TlsConfiguration -EnableSecure

# Enable secure protocols and disable insecure protocols on server1
Set-TlsConfiguration -ComputerName 'server1.contoso.com' -EnableSecure -DisableInsecure

# Enable the strong cryptography settings on all computers in the domain
Set-TlsConfiguration -ComputerName (Get-ADComputer -Filter *) -Enable StrongCrypto_35,StrongCrypto_45,StrongCrypto_x86_35,StrongCrypto_x86_45
```

### Read Current Process configuration

```powershell
# Get the settings of the current process
Get-TlsProcessConfiguration
```

### Write Current Process configuration

```powershell
# Add Tls12 to the protocols supported by the current session
Set-TlsProcessConfiguration -AddSecurityProtocol Tls12
```
