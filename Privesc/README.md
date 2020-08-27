### Modifications in this Fork

----

*PowerUp* is a great script to quickly identify privilege escalation vulnerabilities on a Windows operating systems. However, while Windows changes it's internals from patch to patch, 
*PowerUp* stayed static and was no longer maintained for a long period of time. This lead to some checks being not useful anymore and other checks were just missing by default.
The following points summarize some of these problems:

* The service checks of *PowerUp* rely on WMI access, which is not granted per default to low privileged user accounts.
* The scheduled task checks rely on access to the ``C:\Windows\System32\tasks`` folder, which is not readable by low privileged user accounts.
* There are no checks or functions for writable registry paths
* The different check functions support only very basic error handling, making them hard to use for manual enumeration.

The following changes were applied to get rid of the above mentioned problems (for a list of modified or new methods, check the list at the end of this README):

* The service enumeration capabilities of *PowerUp* were improved. Previously, *PowerUp* did only support service enumeration together with a specific check.
  E.g. the ``Get-ModifiableServiceFile`` and ``Get-UnquotedService`` functions both enumerated the available services separately, causing superfluous computational
  effort. Furthermore, all service checks relied on *WMI* access. In this fork of *PowerUp*, services can be gathered by three different methods ``Get-ServiceReg``,
  ``Get-ServiceApi`` and ``Get-ServiceWmi``. According to their names, they use the *Windows Registry*, *Advapi32* and *WMI* to enumerate available services. At least
  the registry based enumeration should work on almost any system. All methods create an array of ``PowerUp.Service`` objects. All other service checks take these
  type of objects as input and operated on them. This is faster than the previous approach and also improves the user experience during manual enumeration.
* The ``Get-ModifiablePath`` and the new ``Get-ModifiableReg`` functions were improved regarding their error handling and their manual usage. For manual enumeration,
  these functions have to be proven very useful and you should definitely take a look on them. Furthermore, invoking a ``Get-ModifiableReg`` on the ``HKLM:\SYSTEM\CurrentControlSet\Services``
  registry hive was included as a standard check for ``Invoke-AllChecks``.
* The scheduled task enumeration was also improved quite a bit. In the previous versions, *PowerUp* relied on access to ``C:\Windows\System32\Tasks`` to enumerate available scheduled
  tasks. However, this folder is no longer readable for low privileged user accounts. In this fork, *PowerUp* uses the ``schtasks.exe`` to enumerate available scheduled tasks
  (I know, this is lazy. Maybe we switch to COM enumeration someday) and returns the results as ``PowerUp.ScheduledTask`` objects. The new ``Get-ModifiableScheduledTaskFile2`` function
  operates on these objects to find scheduled tasks with weak file permissions on their executable paths.

Compared to other popular privilege escalation enumeration tools, *PowerUp* still lacks a lot of stuff. However, I really like it because it is overviewable and can be
great incorporated into manually enumeration. When I find the time, I will add some checks to improve the automated enumeration capabilities and I'm happy for anyone
who contributes. I guess, together we can make *PowerUp* great again :)

### Installation:

-----

To install this module, drop the entire Privesc folder into one of your module directories. The default PowerShell module paths are listed in the $Env:PSModulePath environment variable.

The default per-user module path is: "$Env:HomeDrive$Env:HOMEPATH\Documents\WindowsPowerShell\Modules"
The default computer-level module path is: "$Env:windir\System32\WindowsPowerShell\v1.0\Modules"

To use the module, type `Import-Module Privesc`

To see the commands imported, type `Get-Command -Module Privesc`

For help on each individual command, Get-Help is your friend.

Note: The tools contained within this module were all designed such that they can be run individually. Including them in a module simply lends itself to increased portability.


### PowerShell v2 Compatibility

----

During the changes no attention was paid on PowerShell v2 compatibility and certain functions probably do not work with PowerShell v2. Following functions are known to not
work anymore with PowerShell version 2:

* ``Set-ServiceBinaryPath`` and ``Set-ServiceUser`` - These functions rely on the Windows API call ``ChangeServiceConfig`` that is imported at the end of the PowerUp script. The original import was:
  ```powershell
  (func advapi32 ChangeServiceConfig ([Bool]) @([IntPtr], [UInt32], [UInt32], [UInt32], [String], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [IntPtr]) -SetLastError -Charset Unicode)
  ```
  This worked fine for ``Set-ServiceBinaryPath``, but to introduce the ``Set-ServiceUser`` function, it was changed to:
  ```powershell
  (func advapi32 ChangeServiceConfig ([Bool]) @([IntPtr], [UInt32], [UInt32], [UInt32], [String], [IntPtr], [IntPtr], [IntPtr], [String], [IntPtr], [IntPtr]) -SetLastError -Charset Unicode)
  ```
  Since there are now two ``String`` parameters inside the definition, it is required to pass the ``[NullString]::Value`` if only one of these properties should change. The ``[NullString]`` type
  was first introduced in Powershell version 3 and therfore is not compatible to Powershell version 2. If you require to use on of these functions with Powershell version 2, just change the import
  of ``ChangeServiceConfig`` to take only one string or add the desired binPath/startName manually into the function call.

In future, we may investigate all compatibility issues and release a Powershell version 2 compatible version.


### Usage:

----

PowerUp aims to be a clearinghouse of common Windows privilege escalation
vectors that rely on misconfigurations.

Running Invoke-PrivescAudit will output any identifiable vulnerabilities along
with specifications for any abuse functions. The -HTMLReport flag will also
generate a COMPUTER.username.html version of the report.

Author: Will Schroeder (@harmj0y)
Edited: Tobias Neitzel (@qtc-de)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None


#### Token/Privilege Enumeration/Abuse:
    Enable-Privilege                  (not modified)   -   enables a specific privilege for the current process
    Get-ProcessTokenGroup             (not modified)   -   returns all SIDs that the current token context is a part of, whether they are disabled or not
    Get-ProcessTokenPrivilege         (not modified)   -   returns all privileges for the current (or specified) process ID

### Service Enumeration/Abuse:
    Install-ServiceBinary             (removed)        -   was removed from the script
    Invoke-ServiceAbuse               (removed)        -   was removed from the script
    Get-ModifiableServiceFile         (modified)       -   returns services where the current user can write to the service binary path or its config
    Get-UnquotedService               (modified)       -   returns services with unquoted paths that also have a space in the name
    Get-ServiceApi                    (new)            -   enumerate services using Advapi32 and the Service Control Manager (outpus PowerUp.Service objects)
    Get-ServiceReg                    (new)            -   enumerate services using the HKLM:\SYSTEM\CurrentControlSet\Services registry hive (outpus PowerUp.Service objects)
    Get-ServiceWmi                    (new)            -   enumerate services using WMI (outpus PowerUp.Service objects)
    Restore-ServiceBinary             (removed)        -   was removed from the script
    Set-ServiceBinaryPath             (modified)       -   sets the binary path for a service to a specified value
    Set-ServiceUser                   (new)            -   sets the service user for a service to a specified value
    Show-ServicePermission            (new)            -   Transform access permissions of a PowerUp.Service object into a human readable format
    Test-ServiceDaclPermission        (modified)       -   tests one or more passed services against a given permission set
    Write-ServiceBinary               (removed)        -   was removed from the script
    Write-Exe                         (new)            -   write a precompiled executable onto disk that executes a specified .bat file

### DLL Hijacking:
    Find-PathDLLHijack                (not modified)   -   finds service %PATH% DLL hijacking opportunities
    Find-ProcessDLLHijack             (not modified)   -   finds potential DLL hijacking opportunities for currently running processes
    Write-HijackDll                   (removed)        -   was removed from the script
    Write-Dll                         (new)            -   replacement for Write-HijackDll. Writes a precompiled DLL onto the disk that executes a specified .bat file
    
### Registry Checks:
    Get-ModifiableReg                 (new)            -   returns registry paths where the current user has write access
    Get-ModifiableRegistryAutoRun     (not modified)   -   checks for any modifiable binaries/scripts (or their configs) in HKLM autoruns
    Get-ModifiableRegistryService     (new)            -   enumerates the HKLM:\SYSTEM\CurrentControlSet\Services registry hive for writable registry keys
    Get-RegistryAlwaysInstallElevated (not modified)   -   checks if the AlwaysInstallElevated registry key is set
    Get-RegistryAutoLogon             (not modified)   -   checks for Autologon credentials in the registry
    Get-KnownRegistryPasswords        (new)            -   checks for known registry locations storing passwords (VNC, Teamviewer, ...)
    Get-RegistryPasswords             (new)            -   search for password strings (pass, cred) inside the SOFTWARE registry

### Miscellaneous Checks:
    Get-ApplicationHost               (not modified)   -   checks for encrypted application pool and virtual directory passwords
    Get-CachedGPPPassword             (not modified)   -   checks for passwords in cached Group Policy Preferences files
    Get-ScheduledTasks                (new)            -   enumerates all available scheduled task objects (outpus PowerUp.ScheduledTask objects)
    Get-ModifiableScheduledTaskFile   (not modified)   -   find schtasks with modifiable target files
    Get-ModifiableScheduledTaskFile2  (new)            -   return schtasks with modifiable target files
    Get-SiteListPassword              (not modified)   -   retrieves the plaintext passwords for any found McAfee's SiteList.xml files
    Get-UnattendedInstallFile         (not modified)   -   finds remaining unattended installation files
    Get-Webconfig                     (not modified)   -   checks for any encrypted web.config strings

### Other Helpers/Meta-Functions:
    Invoke-WScriptUACBypass           (not modified)   -   performs the bypass UAC attack by abusing the lack of an embedded manifest in wscript.exe
    Invoke-PrivescAudit               (modified)       -   runs all current escalation checks and returns a report (formerly Invoke-AllChecks)
    Find-RegistryString               (new)            -   search for specific strings inside the registry
    Get-ModifiablePath                (modified)       -   tokenizes an input string and returns the files in it the current user can modify
    Get-TokenInformation              (not modified)   -   returns token groups or privileges for a passed process/thread token
    Write-UserAddMSI                  (not modified)   -   write out a MSI installer that prompts for a user to be added
