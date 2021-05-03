﻿@{
	# Script module or binary module file associated with this manifest
	RootModule = 'TlsConfig.psm1'
	
	# Version number of this module.
	ModuleVersion = '1.0.0'
	
	# ID used to uniquely identify this module
	GUID = '81cd39bc-0526-420c-b4b0-2276162c08a4'
	
	# Author of this module
	Author = 'Friedrich Weinmann'
	
	# Company or vendor of this module
	CompanyName = 'Microsoft'
	
	# Copyright statement for this module
	Copyright = 'Copyright (c) 2021 Friedrich Weinmann'
	
	# Description of the functionality provided by this module
	Description = 'Manage TLS Configuration settings'
	
	# Minimum version of the Windows PowerShell engine required by this module
	PowerShellVersion = '5.0'
	
	# Modules that must be imported into the global environment prior to importing
	# this module
	RequiredModules = @(
		@{ ModuleName='PSFramework'; ModuleVersion='1.6.198' }
	)
	
	# Assemblies that must be loaded prior to importing this module
	# RequiredAssemblies = @('bin\TlsConfig.dll')
	
	# Type files (.ps1xml) to be loaded when importing this module
	# TypesToProcess = @('xml\TlsConfig.Types.ps1xml')
	
	# Format files (.ps1xml) to be loaded when importing this module
	FormatsToProcess = @('xml\TlsConfig.Format.ps1xml')
	
	# Functions to export from this module
	FunctionsToExport = @(
        'Get-TlsConfiguration'
        'Get-TlsProcessConfiguration'
        'Set-TlsConfiguration'
        'Set-TlsProcessConfiguration'
        'Test-TlsProtocol'
    )
	
	# List of all modules packaged with this module
	ModuleList = @()
	
	# List of all files packaged with this module
	FileList = @()
	
	# Private data to pass to the module specified in ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
	PrivateData = @{
		
		#Support for PowerShellGet galleries.
		PSData = @{
			
			# Tags applied to this module. These help with module discovery in online galleries.
			Tags = @('Tls')
			
			# A URL to the license for this module.
			LicenseUri = 'https://github.com/FriedrichWeinmann/TlsConfig/blob/master/LICENSE'
			
			# A URL to the main website for this project.
			ProjectUri = 'https://github.com/FriedrichWeinmann/TlsConfig'
			
			# A URL to an icon representing this module.
			# IconUri = ''
			
			# ReleaseNotes of this module
			ReleaseNotes = 'https://github.com/FriedrichWeinmann/TlsConfig/blob/master/TlsConfig/changelog.md'
			
		} # End of PSData hashtable
		
	} # End of PrivateData hashtable
}