### Modifications in this Fork

----

*PowerUp* is a great script to quickly identify privilege escalation vulnerabilities on a Windows operating systems. However, while Windows changes it's internals from patch to patch, 
*PowerUp* stayed static and was no longer maintained for a long period of time. This lead to some checks being not useful anymore and other checks were just missing by default.
The following points summarize some of these problems:

* The service checks of *PowerUp* rely on WMI access, which is not granted per default to low privileged user accounts.
* The scheduled task checks rely on access to the ``C:\Windows\System32\tasks`` folder, which is not readable by low privileged user accounts.
* There are no checks or functions for writable registry paths
* The different check functions support only very basic error handling, making them hard to use for manual enumeration.

The following changes were applied to get rid of the above mentioned problems:

* TODO

Furthermore, a *PowerUpLight.ps1* version was added. This version of *PowerUp* should be fully functional, but excludes all abuse related functions. This makes it possible
to strip the more malicious stuff like base64 encoded malicious binaries that were shipped normally by default.


### Original README.md Content:

-----

To install this module, drop the entire Privesc folder into one of your module directories. The default PowerShell module paths are listed in the $Env:PSModulePath environment variable.

The default per-user module path is: "$Env:HomeDrive$Env:HOMEPATH\Documents\WindowsPowerShell\Modules"
The default computer-level module path is: "$Env:windir\System32\WindowsPowerShell\v1.0\Modules"

To use the module, type `Import-Module Privesc`

To see the commands imported, type `Get-Command -Module Privesc`

For help on each individual command, Get-Help is your friend.

Note: The tools contained within this module were all designed such that they can be run individually. Including them in a module simply lends itself to increased portability.


## PowerUp

PowerUp aims to be a clearinghouse of common Windows privilege escalation
vectors that rely on misconfigurations.

Running Invoke-AllChecks will output any identifiable vulnerabilities along
with specifications for any abuse functions. The -HTMLReport flag will also
generate a COMPUTER.username.html version of the report.

Author: @harmj0y
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None


### Token/Privilege Enumeration/Abuse:
    Get-ProcessTokenGroup               -   returns all SIDs that the current token context is a part of, whether they are disabled or not
    Get-ProcessTokenPrivilege           -   returns all privileges for the current (or specified) process ID
    Enable-Privilege                    -   enables a specific privilege for the current process

### Service Enumeration/Abuse:
    Test-ServiceDaclPermission          -   tests one or more passed services or service names against a given permission set
    Get-UnquotedService                 -   returns services with unquoted paths that also have a space in the name
    Get-ModifiableServiceFile           -   returns services where the current user can write to the service binary path or its config
    Get-ModifiableService               -   returns services the current user can modify
    Get-ServiceDetail                   -   returns detailed information about a specified service
    Set-ServiceBinaryPath               -   sets the binary path for a service to a specified value
    Invoke-ServiceAbuse                 -   modifies a vulnerable service to create a local admin or execute a custom command
    Write-ServiceBinary                 -   writes out a patched C# service binary that adds a local admin or executes a custom command
    Install-ServiceBinary               -   replaces a service binary with one that adds a local admin or executes a custom command
    Restore-ServiceBinary               -   restores a replaced service binary with the original executable

### DLL Hijacking:
    Find-ProcessDLLHijack               -   finds potential DLL hijacking opportunities for currently running processes
    Find-PathDLLHijack                  -   finds service %PATH% DLL hijacking opportunities
    Write-HijackDll                     -   writes out a hijackable DLL
    
### Registry Checks:
    Get-RegistryAlwaysInstallElevated   -   checks if the AlwaysInstallElevated registry key is set
    Get-RegistryAutoLogon               -   checks for Autologon credentials in the registry
    Get-ModifiableRegistryAutoRun       -   checks for any modifiable binaries/scripts (or their configs) in HKLM autoruns

### Miscellaneous Checks:
    Get-ModifiableScheduledTaskFile     -   find schtasks with modifiable target files
    Get-UnattendedInstallFile           -   finds remaining unattended installation files
    Get-Webconfig                       -   checks for any encrypted web.config strings
    Get-ApplicationHost                 -   checks for encrypted application pool and virtual directory passwords
    Get-SiteListPassword                -   retrieves the plaintext passwords for any found McAfee's SiteList.xml files
    Get-CachedGPPPassword               -   checks for passwords in cached Group Policy Preferences files

### Other Helpers/Meta-Functions:
    Get-ModifiablePath                  -   tokenizes an input string and returns the files in it the current user can modify
    Write-UserAddMSI                    -   write out a MSI installer that prompts for a user to be added
    Invoke-WScriptUACBypass             -   performs the bypass UAC attack by abusing the lack of an embedded manifest in wscript.exe
    Invoke-PrivescAudit                 -   runs all current escalation checks and returns a report (formerly Invoke-AllChecks)
