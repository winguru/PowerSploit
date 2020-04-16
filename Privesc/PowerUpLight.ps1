########################################################
#
# Resources Enumeration
#
########################################################

function Get-ModifiablePath {
<#
.SYNOPSIS

Parses a passed string containing multiple possible file/folder paths and returns
the file paths where the current user has modification rights.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None  
EditedBy: Tobias Neitzel (@qtc-de)

.DESCRIPTION

Takes a complex path specification of an initial file/folder path with possible
configuration files, 'tokenizes' the string in a number of possible ways, and
enumerates the ACLs for each path that currently exists on the system. Any path that
the current user has modification rights on is returned in a custom object that contains
the modifiable path, owner, associated permission set, and the IdentityReference with the
specified rights. The SID of the current user and any group he/she are a part of are used
as the comparison set against the parsed path DACLs.

.PARAMETER Path

The string path to parse for modifiable files. Required

.PARAMETER Literal

Switch. Treat all paths as literal (i.e. don't do 'tokenization').

.EXAMPLE

'"C:\Temp\blah.exe" -f "C:\Temp\config.ini"' | Get-ModifiablePath

Path                       Permissions                IdentityReference
----                       -----------                -----------------
C:\Temp\blah.exe           {ReadAttributes, ReadCo... NT AUTHORITY\Authentic...
C:\Temp\config.ini         {ReadAttributes, ReadCo... NT AUTHORITY\Authentic...

.EXAMPLE

Get-ChildItem C:\ProgramData -File -Recurse -ErrorAction SilentlyContinue | Get-ModifiablePath -Literal

ModifiablePath                                            Owner                  IdentityReference        Permissions                                                                           
--------------                                            -----                  -----------------        -----------                                                                           
C:\ProgramData\chocolatey\logs\choco.summary.log          BUILTIN\Administrators BUILTIN\Users            {WriteAttributes, Synchronize, AppendData/AddSubdirectory, WriteExtendedAttributes...}
C:\ProgramData\chocolatey\logs\chocolatey.log             BUILTIN\Administrators BUILTIN\Users            {WriteAttributes, Synchronize, AppendData/AddSubdirectory, WriteExtendedAttributes...}
...

.OUTPUTS

PowerUp.TokenPrivilege.ModifiablePath

Custom PSObject containing the Permissions, Owner, ModifiablePath and IdentityReference for
a modifiable path.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerUp.ModifiablePath')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('FullName')]
        [String[]]
        $Path,

        [Alias('LiteralPaths')]
        [Switch]
        $Literal
    )

    BEGIN {
        # from http://stackoverflow.com/questions/28029872/retrieving-security-descriptor-and-getting-number-for-filesystemrights
        $AccessMask = @{
            [uint32]'0x80000000' = 'GenericRead'
            [uint32]'0x40000000' = 'GenericWrite'
            [uint32]'0x20000000' = 'GenericExecute'
            [uint32]'0x10000000' = 'GenericAll'
            [uint32]'0x02000000' = 'MaximumAllowed'
            [uint32]'0x01000000' = 'AccessSystemSecurity'
            [uint32]'0x00100000' = 'Synchronize'
            [uint32]'0x00080000' = 'WriteOwner'
            [uint32]'0x00040000' = 'WriteDAC'
            [uint32]'0x00020000' = 'ReadControl'
            [uint32]'0x00010000' = 'Delete'
            [uint32]'0x00000100' = 'WriteAttributes'
            [uint32]'0x00000080' = 'ReadAttributes'
            [uint32]'0x00000040' = 'DeleteChild'
            [uint32]'0x00000020' = 'Execute/Traverse'
            [uint32]'0x00000010' = 'WriteExtendedAttributes'
            [uint32]'0x00000008' = 'ReadExtendedAttributes'
            [uint32]'0x00000004' = 'AppendData/AddSubdirectory'
            [uint32]'0x00000002' = 'WriteData/AddFile'
            [uint32]'0x00000001' = 'ReadData/ListDirectory'
        }

        # this is an xor of GenericWrite, GenericAll, MaximumAllowed, WriteOwner, WriteDAC, AppendData/AddSubdirectory, WriteData/AddFile, Delete
        $MAccessMask = 0x520d0006
        
        # possible separator character combinations
        $SeparationCharacterSets = @('"', "'", ' ', "`"'", '" ', "' ", "`"' ")

        $UserIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $CurrentUserSids = $UserIdentity.Groups | Select-Object -ExpandProperty Value
        $CurrentUserSids += $UserIdentity.User.Value
        $TranslatedIdentityReferences = @{}
    }

    PROCESS {

        ForEach($TargetPath in $Path) {

            $CandidatePaths = @()

            if ($PSBoundParameters['Literal']) {

                $TempPath = $([System.Environment]::ExpandEnvironmentVariables($TargetPath))

                if (Test-Path -Path $TempPath -ErrorAction SilentlyContinue) {
                    $CandidatePaths += Resolve-Path -Path $TempPath | Select-Object -ExpandProperty Path
                }
                else {
                    # if the path doesn't exist, check if the parent folder allows for modification
                    $ParentPath = Split-Path -Path $TempPath -Parent  -ErrorAction SilentlyContinue
                    if ($ParentPath -and (Test-Path -Path $ParentPath)) {
                        $CandidatePaths += Resolve-Path -Path $ParentPath -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path
                    } else {
                        Write-Verbose "Skipping: $TempPath [Not Found]"
                    }
                }
            }
            else {

                ForEach($SeparationCharacterSet in $SeparationCharacterSets) {
                    $TargetPath.Split($SeparationCharacterSet) | Where-Object {$_ -and ($_.trim() -ne '')} | ForEach-Object {

                        if (($SeparationCharacterSet -notmatch ' ')) {

                            $TempPath = $([System.Environment]::ExpandEnvironmentVariables($_)).Trim()

                            if ($TempPath -and ($TempPath -ne '')) {
                                if (Test-Path -Path $TempPath -ErrorAction SilentlyContinue) {
                                    # if the path exists, resolve it and add it to the candidate list
                                    $CandidatePaths += Resolve-Path -Path $TempPath | Select-Object -ExpandProperty Path
                                }

                                else {
                                    # if the path doesn't exist, check if the parent folder allows for modification
                                    try {
                                        $ParentPath = (Split-Path -Path $TempPath -Parent -ErrorAction SilentlyContinue).Trim()
                                        if ($ParentPath -and ($ParentPath -ne '') -and (Test-Path -Path $ParentPath  -ErrorAction SilentlyContinue)) {
                                            $CandidatePaths += Resolve-Path -Path $ParentPath -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path
                                        }
                                    }
                                    catch {}
                                }
                            }
                        }
                        else {
                            # if the separator contains a space
                            $CandidatePaths += Resolve-Path -Path $([System.Environment]::ExpandEnvironmentVariables($_)) -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path | ForEach-Object {$_.Trim()} | Where-Object {($_ -ne '') -and (Test-Path -Path $_)}
                        }
                    }
                }
            }

            $CandidatePaths | Sort-Object -Unique | ForEach-Object {
                
                $CandidatePath = $_

                try {
                    $Acl = Get-Acl -Path $CandidatePath -ErrorAction Stop
                    $Owner = $Acl.Owner;
                    
                    if( $Owner -notmatch '^S-1-5.*' ) {
                        if( -not $TranslatedIdentityReferences[$Owner] ) {
                            $IdentityUser = New-Object System.Security.Principal.NTAccount($Owner)
                            $TranslatedIdentityReferences[$Owner] = $IdentityUser.Translate([System.Security.Principal.SecurityIdentifier]) | Select-Object -ExpandProperty Value
                        }
                        $IdentitySID = $TranslatedIdentityReferences[$Owner]
                    } else {
                        $IdentitySID = $Owner
                    }

                    # If we are owner, we have implicit full control over the object. Only the Owner property is imporant here, as the security group of an object
                    # gets ignored (https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc961983(v=technet.10)?redirectedfrom=MSDN
                    if( $CurrentUserSids -contains $IdentitySID ) {
                        $Out = New-Object PSObject
                        $Out | Add-Member Noteproperty 'ModifiablePath' $CandidatePath
                        $out | Add-Member Noteproperty 'Owner' $Owner
                        $Out | Add-Member Noteproperty 'IdentityReference' $Owner
                        $Out | Add-Member Noteproperty 'Permissions' @('Owner')
                        $Out.PSObject.TypeNames.Insert(0, 'PowerUp.ModifiablePath')
                        $Out
                    }

                } catch [System.UnauthorizedAccessException] {
                    Write-Verbose "Skipping: $CandidatePath [Access Denied]"
                    continue
                }

                $Acl | Select-Object -ExpandProperty Access | Where-Object {($_.AccessControlType -match 'Allow')} | ForEach-Object {

                    $FileSystemRights = $_.FileSystemRights.value__

                    if( $FileSystemRights -band $MAccessMask )  {

                        $Permissions = $AccessMask.Keys | Where-Object { $FileSystemRights -band $_ } | ForEach-Object { $AccessMask[$_] }

                        $IdentityRef = $_.IdentityReference
                        if ($IdentityRef -notmatch '^S-1-5.*') {

                            if (-not ($TranslatedIdentityReferences[$IdentityRef])) {
                                $IdentityUser = New-Object System.Security.Principal.NTAccount($IdentityRef)
                                try {
                                    $TranslatedIdentityReferences[$IdentityRef] = $IdentityUser.Translate([System.Security.Principal.SecurityIdentifier]) | Select-Object -ExpandProperty Value
                                } catch {
                                    $TranslatedIdentityReferences[$IdentityRef] = $IdentityUser
                                }
                            }
                            $IdentitySID = $TranslatedIdentityReferences[$_.IdentityReference]

                        }
                        else {
                            $IdentitySID = $_.IdentityReference
                        }

                        if ($CurrentUserSids -contains $IdentitySID) {
                            $Out = New-Object PSObject
                            $Out | Add-Member Noteproperty 'ModifiablePath' $CandidatePath
                            $out | Add-Member Noteproperty 'Owner' $Owner
                            $Out | Add-Member Noteproperty 'IdentityReference' $_.IdentityReference
                            $Out | Add-Member Noteproperty 'Permissions' $Permissions
                            $Out.PSObject.TypeNames.Insert(0, 'PowerUp.ModifiablePath')
                            $Out
                        }
                    }
                }
            }
        }
    }
}


function Get-ModifiableReg {
<#
.SYNOPSIS

Takes multiple strings containing registry paths and returns
the registry paths where the current user has modification rights.

Author: Tobias Neitzel (@qtc-de)  
License: BSD 3-Clause  
Required Dependencies: None  

.DESCRIPTION

Takes a number of registry paths and enumerates the ACLs on them. Any path that
the current user has modification rights on is returned in a custom object that contains
the modifiable path, the owner, associated permission set, and the IdentityReference with 
the specified rights. The SID of the current user and any group he/she are a part of are 
used as the comparison set against the parsed path DACLs.

.PARAMETER Path

The registry path. Required

.EXAMPLE

"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ASP.NET_4.0.30319\Names" | Get-ModifiableReg

ModifiablePath                                                                   Owner                   IdentityReference                 Permissions
--------------                                                                   -----                   -----------------                 -----------
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ASP.NET_4.0.30319\Names     NT AUTHORITY\SYSTEM     BUILTIN\Performance Log Users     {CreateSubKey, SetValue, ReadPermissions, Notify...}


.EXAMPLE

Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Services\ -Recurse -ErrorAction SilentlyContinue | Get-ModifiableReg

ModifiablePath                                                                                    Owner                       IdentityReference                Permissions
--------------                                                                                    -----                       -----------------                -----------
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ASP.NET_4.0.30319\Names                      NT AUTHORITY\SYSTEM         BUILTIN\Performance Log Users    {CreateSubKey, SetValue, ReadPermissions, Notify...}
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BTAGService\Parameters\Settings              NT SERVICE\TrustedInstaller NT AUTHORITY\INTERACTIVE         {CreateSubKey, SetValue, ReadPermissions}
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BTAGService\Parameters\Settings              NT SERVICE\TrustedInstaller NT AUTHORITY\Authenticated Users {CreateSubKey, SetValue, ReadPermissions}
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BTAGService\Parameters\Settings\AudioGateway NT AUTHORITY\SYSTEM         NT AUTHORITY\INTERACTIVE         {CreateSubKey, SetValue, ReadPermissions}
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BTAGService\Parameters\Settings\AudioGateway NT AUTHORITY\SYSTEM         NT AUTHORITY\Authenticated Users {CreateSubKey, SetValue, ReadPermissions}
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BTAGService\Parameters\Settings\HandsFree    NT AUTHORITY\SYSTEM         NT AUTHORITY\INTERACTIVE         {CreateSubKey, SetValue, ReadPermissions}
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BTAGService\Parameters\Settings\HandsFree    NT AUTHORITY\SYSTEM         NT AUTHORITY\Authenticated Users {CreateSubKey, SetValue, ReadPermissions}
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\embeddedmode\Parameters                      NT AUTHORITY\SYSTEM         NT AUTHORITY\INTERACTIVE         {CreateSubKey, ReadPermissions, EnumerateSubKeys, QueryValues}
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\embeddedmode\Parameters                      NT AUTHORITY\SYSTEM         NT AUTHORITY\Authenticated Users {CreateSubKey, ReadPermissions, Notify, EnumerateSubKeys...}
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vds\Alignment                                NT AUTHORITY\SYSTEM         NT AUTHORITY\Authenticated Users {CreateSubKey, ReadPermissions, EnumerateSubKeys, QueryValues}

.OUTPUTS

PowerUp.TokenPrivilege.ModifiableReg

Custom PSObject containing the Permissions, Owner, ModifiablePath and IdentityReference for
a modifiable registry path.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerUp.ModifiableReg')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('PSPath')]
        [Alias('Name')]
        [String[]]
        $Path
    )

    BEGIN {
        
        $AccessMask = @{
             [uint32]'0x80000000' = 'GenericRead'
             [uint32]'0x40000000' = 'GenericWrite'
             [uint32]'0x20000000' = 'GenericExecute'
             [uint32]'0x10000000' = 'GenericAll'
             [uint32]'0x02000000' = 'MaximumAllowed'
             [uint32]'0x00080000' = 'WriteOwner'
             [uint32]'0x00040000' = 'WriteDAC'
             [uint32]'0x00020000' = 'ReadPermissions'
             [uint32]'0x00010000' = 'Delete'
             [uint32]'0x00000020' = 'CreateLink'
             [uint32]'0x00000010' = 'Notify'
             [uint32]'0x00000008' = 'EnumerateSubKeys'
             [uint32]'0x00000004' = 'CreateSubKey'
             [uint32]'0x00000002' = 'SetValue'
             [uint32]'0x00000001' = 'QueryValues'
        }

        # this is an xor of GenericWrite, GenericAll, MaximumAllowed, WriteOwner, WriteDAC, CreateSubKey, SetValue, CreateLink, Delete
        # TODO: Evaluate the exploitation potential of CreateLink
        $MAccessMask = 0x520d0006

        $UserIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $CurrentUserSids = $UserIdentity.Groups | Select-Object -ExpandProperty Value
        $CurrentUserSids += $UserIdentity.User.Value
        $TranslatedIdentityReferences = @{}
    }

    PROCESS {

        ForEach($TargetPath in $Path) {

            $CandidatePath = $TargetPath
            if( -not $CandidatePath.StartsWith("Microsoft") ) {
                $CandidatePath = "Microsoft.PowerShell.Core\Registry::$($CandidatePath.replace(':',''))"
            }

            # registry Paths can contain wildcard and other special characters. Therefore they should not be
            # expanded or resolved befor processing
            if (-not (Test-Path -Path $CandidatePath -ErrorAction SilentlyContinue) ) {
                # if the path doesn't exist, check if the parent folder allows for modification.
                # This will not work if the leaf of the missing path contains a forward slash
                $ParentPath = Split-Path -Path $CandidatePath -Parent  -ErrorAction SilentlyContinue
                if (-not ($ParentPath -and (Test-Path -Path $ParentPath)) ) {
                    Write-Warning "Skipping: $CandidatePath [Not Found]"
                    continue
                } else {
                    $CandidatePath = $ParentPath
                }
            }

            try {
                # Get-Acl fails on paths containing special characters like '/' or '*'. Therefore, we use Get-Item.
                $Key = Get-Item -LiteralPath $CandidatePath -ErrorAction Stop
                $Acl = $Key.GetAccessControl()
                $Owner = $Acl.Owner;
            } catch [System.UnauthorizedAccessException] {
                Write-Warning "Skipping: $CandidatePath [Access Denied]"
                continue
            }

            $Acl | Select-Object -ExpandProperty Access | Where-Object {($_.AccessControlType -match 'Allow')} | ForEach-Object {

                $RegistryRights = $_.RegistryRights.value__

                if( $RegistryRights -band $MAccessMask )  {

                    $Permissions = $AccessMask.Keys | Where-Object { $RegistryRights -band $_ } | ForEach-Object { $AccessMask[$_] }

                    $IdentityRef = $_.IdentityReference
                    if ($IdentityRef -notmatch '^S-1-5.*') {

                        if (-not ($TranslatedIdentityReferences[$IdentityRef])) {
                            $IdentityUser = New-Object System.Security.Principal.NTAccount($IdentityRef)
                            try {
                                $TranslatedIdentityReferences[$IdentityRef] = $IdentityUser.Translate([System.Security.Principal.SecurityIdentifier]) | Select-Object -ExpandProperty Value
                            } catch {
                                $TranslatedIdentityReferences[$IdentityRef] = $IdentityUser
                            }
                        }
                        $IdentitySID = $TranslatedIdentityReferences[$_.IdentityReference]

                    }
                    else {
                        $IdentitySID = $_.IdentityReference
                    }

                    if ($CurrentUserSids -contains $IdentitySID) {
                        $Out = New-Object PSObject
                        $Out | Add-Member Noteproperty 'ModifiablePath' $CandidatePath
                        $out | Add-Member Noteproperty 'Owner' $Owner
                        $Out | Add-Member Noteproperty 'IdentityReference' $_.IdentityReference
                        $Out | Add-Member Noteproperty 'Permissions' $Permissions
                        $Out.PSObject.TypeNames.Insert(0, 'PowerUp.ModifiableReg')
                        $Out
                    }
                }
            }
        }
    }
}


########################################################
#
# Service enumeration
#
########################################################

function Get-ServiceReg {
<#
.SYNOPSIS

Enumerates services using the HKLM:\SYSTEM\CurrentControlSet\Services registry hive.
This circumvents restricted access to ordinary service enumeration like sc.exe or Get-Service.

Author: Tobias Neitzel
License: BSD 3-Clause  
Required Dependencies: ServiceAccessRights (Enum)  

.DESCRIPTION

Queries the HKLM:\SYSTEM\CurrentControlSet\Services Hive and enumerates all present services.

.PARAMETER Verbose

Switch. Show warning messages for services with non existing image paths

.PARAMETER IncludeDrivers

Switch. Include services associated with kernel and filesystem drivers

.EXAMPLE

Get-ServiceReg 

Name             : AJRouter
ServiceName      : AJRouter
DisplayName      : @%SystemRoot%\system32\AJRouter.dll,-2
RequiredServices : 
StartType        : Manual
ObtainedBy       : Registry
ObjectName       : NT AUTHORITY\LocalService
PathName         : C:\Program Files\AjRouter\Routing Solutions\aj-start.exe
Dacl             : {System.Security.AccessControl.CommonAce, System.Security.AccessControl.CommonAce, System.Security.AccessControl.CommonAce, System.Security.AccessControl.CommonAce...}

[...]

Get all non driver services that are available inside the registry.

.OUTPUTS

PowerUp.Service
#>
    [OutputType('PowerUp.Service')]
    [CmdletBinding()]
    param(
        [Switch]
        $IncludeDrivers
    )

    $StartupTypes = @{
        0 = 'On Boot'
        1 = 'System Controlled'
        2 = 'Autostart'
        3 = 'Manual'
        4 = 'Disabled'
        999 = 'unknown'
    }

    $DefaultSddl = 'D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CR;;;AU)'
    $DefaultSD =  New-Object Security.AccessControl.CommonSecurityDescriptor $false,$false,$DefaultSddl

    Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' | ForEach-Object {

        $ServiceName = $_.PSChildName
        $PathName = $_.GetValue("ImagePath")
        $Type = $_.GetValue("Type")
        $StartupType = if($_.GetValue("Start") -eq $null) { "999" } else { $_.GetValue("Start") }

        if( ($Type -band  0x3) -and (-not $IncludeDrivers) ){
            if( $PSBoundParameters['Verbose'] ) {
                Write-Warning "Skipping: $ServiceName [Driver]"
            }
            return
        }

        $Service = New-Object PSObject
        $Service | Add-Member -MemberType NoteProperty -Name Name -Value $ServiceName
        $Service | Add-Member -MemberType NoteProperty -Name ServiceName -Value $ServiceName
        $Service | Add-Member -MemberType NoteProperty -Name DisplayName -Value $_.GetValue("DisplayName")
        $Service | Add-Member -MemberType NoteProperty -Name RequiredServices -Value  $_.GetValue("DependOnService")
        $Service | Add-Member -MemberType NoteProperty -Name StartType -Value $StartupTypes[$StartupType]
        $Service | Add-Member -MemberType NoteProperty -Name ObtainedBy -Value "Registry"
        $Service | Add-Member -MemberType NoteProperty -Name ObjectName -Value $_.GetValue("ObjectName")
        $Service | Add-Member -MemberType NoteProperty -Name PathName -Value $PathName

        try {
            $Key = $_.OpenSubKey("Security")
        } catch [System.Management.Automation.MethodException] {
            if( $PSBoundParameters['Verbose'] ) {
                Write-Warning "Failure obtaining Security key for $ServiceName [Access Denied]"
            }
            $Service.PSObject.TypeNames.Insert(0, 'PowerUp.Service')
            return $Service
        }

        try {

            if( $Key -eq $null ) {
                $RawSecurityDescriptor = $DefaultSD
            } else {
                $Sec = $Key.GetValue("Security")
                $RawSecurityDescriptor = New-Object Security.AccessControl.CommonSecurityDescriptor $false,$false,$Sec,0
            }

            $Dacl = $RawSecurityDescriptor.DiscretionaryAcl | ForEach-Object {
                Add-Member -InputObject $_ -MemberType NoteProperty -Name AccessRights -Value ($_.AccessMask -as $ServiceAccessRights) -PassThru
            }
            $Service | Add-Member -MemberType NoteProperty -Name Dacl -Value  $Dacl

        } catch [System.Management.Automation.MethodException] {
            if( $PSBoundParameters['Verbose'] ) {
                Write-Warning "Failure parsing Security key for $ServiceName [Parsing Error]"
            }
        } finally {
            $Service.PSObject.TypeNames.Insert(0, 'PowerUp.Service')
            $Service
        }
    }
}


function Get-UnquotedService {
<#
.SYNOPSIS

Takes PowerUp.Service objects as input and returns services with unquoted image
paths that are modifiable by the current user.

Author: Tobias Neitzel (@qtc-de)
License: BSD 3-Clause  
Required Dependencies: 

.DESCRIPTION

This method is also implemented in the ordinary PowerUp script, but uses WMI to query
service information. WMI access is often disabled for low privileged user accounts.
Therefore, it is desireable to have an alternative method, which does not rely on WMI
access. By accepting PowerUp.Service objects as input parameters, it does not matter
how these were initially received. The only important thing is, that they include the
PathName property.

.EXAMPLE

Get-ServiceReg | Get-UnquotedService

Name             : AJRouter
ServiceName      : AJRouter
DisplayName      : @%SystemRoot%\system32\AJRouter.dll,-2
PathName         :  C:\Program Files\AjRouter\Routing Solutions\aj-start.exe
ObjectName       : NT AUTHORITY\LocalService
Access           : {System.Security.AccessControl.CommonAce, System.Security.AccessControl.CommonAce, System.Security.AccessControl.CommonAce, System.Security.AccessControl.CommonAce...}
RequiredServices : 
StartType        : Manual
ModifiablePath1  : "C:\Program Files\AjRouter"
ModifiablePath2  : "C:\Program Files\AjRouter\Routing Solutions\aj-start.exe"

.OUTPUTS

PowerUp.Service

.LINK

https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/local/trusted_service_path.rb
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerUp.Service')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True)]
        [PSObject[]]
        $Services
    )

    BEGIN {
        $Regex = [regex]"^[^`"'].* .*\.exe"
    }

    PROCESS {
        ForEach($Service in $Services) {

            if( $Service.PathName -eq $Null ) {
                Write-Warning "Skipping: $Service.Name [No Image Path]"
                continue
            }

            if( $Regex.Match($Service.PathName).Success ){

                $SplitPathArray = $Service.PathName.Trim().Split(' ')
                $ConcatPathArray = @()
                for ($i=1;$i -lt $SplitPathArray.Count; $i++) {
                            $ConcatPathArray += $SplitPathArray[0..$i] -join ' '
                }

                $count = 1
                $ModifiableFiles = $ConcatPathArray | Get-ModifiablePath
                $ModifiableFiles | Where-Object {$_ -and $_.ModifiablePath -and ($_.ModifiablePath -ne '') -and ($_.ModifiablePath -ne 'C:\')} | Foreach-Object {
                    $Service | Add-Member -MemberType NoteProperty -Name "ModifiablePath$count" -Value "`"$($_.ModifiablePath)`"" -Force
                    $count += 1
                }
                if( $count -gt 1 ) { 
                    $Service 
                }
            }
        }
    }
}

function Get-ModifiableServiceFile {
<#
.SYNOPSIS

Takes PowerUp.Service objects as input and returns services with modifiable service
files.

Author: Tobias Neitzel (@qtc-de)
License: BSD 3-Clause  
Required Dependencies: 

.DESCRIPTION

This method is also implemented in the ordinary PowerUp script, but uses WMI to query
service information. WMI access is often disabled for low privileged user accounts.
Therefore, it is desireable to have an alternative method, which does not rely on WMI
access. By accepting PowerUp.Service objects as input parameters, it does not matter
how these were initially received. The only important thing is, that they include the
PathName property.

.EXAMPLE

Get-ModifiableServiceFile

Get a set of potentially exploitable service binares/config files.

.OUTPUTS

PowerUp.Service
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerUp.Service')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True)]
        [PSObject[]]
        $Services
    )

    PROCESS {

        ForEach( $Service in $Services ) {
            $ServiceName = $Service.Name
            $ServicePath = $Service.PathName
            
            if( $ServicePath -eq $null ) {
                Write-Warning "Skipping: $ServiceName [No Image Path]"
                continue
            }

            $count = 1
            $ServicePath | Get-ModifiablePath | ForEach-Object {
                $Service | Add-Member -MemberType NoteProperty -Name "ModifiableFile$count" -Value "`"$($_.ModifiablePath)`"" -Force
                $count += 1
            }

            if( $count -gt 1 ) { 
                $Service.PSObject.TypeNames.Insert(0, 'PowerUp.ModifiableService')
                $Service 
            }
        }
    }
}


function Show-ServicePermissions {
<#
.SYNOPSIS

Takes PowerUp.Service objects and transforms their access permissions in a human readable format.

Author: Tobias Neitzel (@qtc-de)
License: BSD 3-Clause  
Required Dependencies: 

.DESCRIPTION

This method takes PowerUp.Service objects and transforms them to PowerUp.ServicePermission objects.
PowerUp.ServicePermission objects allow easy and organized access to the permissions of a service.
Without any arguments, services where the current user has no access at all are not shown. Use the
-All switch to include all services.

.EXAMPLE

Get-ServiceReg | Show-ServicePermissions

PS C:\Users\IEUser> Get-ServiceReg | Show-ServicePermissions

Service                  Principal                        ObjectName                                                                                                    Permissions
-------                  ---------                        ----------                                                                                                    -----------
AJRouter                 NT AUTHORITY\INTERACTIVE         NT AUTHORITY\LocalService     QueryConfig, QueryStatus, EnumerateDependents, Interrogate, UserDefinedControl, ReadControl
AJRouter                 NT AUTHORITY\Authenticated Users NT AUTHORITY\LocalService                                                                              UserDefinedControl
ALG                      NT AUTHORITY\INTERACTIVE         NT AUTHORITY\LocalService     QueryConfig, QueryStatus, EnumerateDependents, Interrogate, UserDefinedControl, ReadControl
ALG                      NT AUTHORITY\Authenticated Users NT AUTHORITY\LocalService                                                                              UserDefinedControl
AppIDSvc                 NT AUTHORITY\INTERACTIVE         NT Authority\LocalService     QueryConfig, QueryStatus, EnumerateDependents, Interrogate, UserDefinedControl, ReadControl
[...]

Access permissions of the current user.

.EXAMPLE

Get-ServiceReg | Show-ServicePermissions | Where-Object { ($_.ObjectName -match 'SYSTEM') -and ($_.Permissions -match 'change') }

PS C:\Users\IEUser> Get-ServiceReg | Show-ServicePermissions | Where-Object { ($_.ObjectName -match 'SYSTEM') -and ($_.Permissions -match 'all') }

Service      Principal                ObjectName  Permissions
-------      ---------                ----------  -----------
UmRdpService NT AUTHORITY\INTERACTIVE localSystem   AllAccess
[...]

Show services where the current user has AllAccess.

.OUTPUTS

PowerUp.ServicePermission
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerUp.ServicePermission')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True)]
        [PSObject[]]
        $Services,

        [Switch]
        $All
    )

    BEGIN {
        $UserIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $CurrentUserSids = $UserIdentity.Groups | Select-Object -ExpandProperty Value
        $CurrentUserSids += $UserIdentity.User.Value
        $TranslatedIdentityReferences = @{}
    }

    PROCESS {

        ForEach( $Service in $Services ) {
            $Service | Select-Object -ExpandProperty Dacl | Where-Object { $_.AceType -match 'Allow' } | ForEach-Object {

                $Permissions = $_.AccessRights
                $Sid = $_.SecurityIdentifier   
                try {
                    $i = New-Object System.Security.Principal.SecurityIdentifier($Sid)
                    $Principal = $i.Translate([System.Security.Principal.NTAccount]).Value
                } catch {
                    $Principal = $Sid
                }
                if( ($CurrentUserSids -contains $Sid) -or $All ) {
                    $Out = New-Object PSObject
                    $Out | Add-Member Noteproperty 'Service' $Service.Name
                    $Out | Add-Member Noteproperty 'Principal' $Principal
                    $Out | Add-Member Noteproperty 'ObjectName' $Service.ObjectName
                    $Out | Add-Member Noteproperty 'Permissions' $Permissions
                    $Out.PSObject.TypeNames.Insert(0, 'PowerUp.ServicePermission')
                    $Out
                }
            }
        }
    }
}


function Test-ServiceDaclPermission {
<#
.SYNOPSIS

Expects a set of PowerUp.Service objects as input and returns PowerUp.Service objects where the current
user has modification permissions.

Author: Tobias Neitzel (@qtc-de)
License: BSD 3-Clause  
Required Dependencies:

.DESCRIPTION

This function is basically a copy of the plain Test-ServiceDaclPermission cmdlet of PowerUp.
However, PowerUp used this method to do both: Obtaining the DACL and checking for vulnerable
permissions. This is not flexible, as there are different methods obtaining the DACL of a service.
This version of the function assumes PowerUp.Service objects that get a DACL property assigned during
their creation.

.PARAMETER Services

An array of PowerUp.Service objects.

.PARAMETER Permissions

A manual set of permission to test again. One of:'QueryConfig', 'ChangeConfig', 'QueryStatus',
'EnumerateDependents', 'Start', 'Stop', 'PauseContinue', 'Interrogate', UserDefinedControl',
'Delete', 'ReadControl', 'WriteDac', 'WriteOwner', 'Synchronize', 'AccessSystemSecurity',
'GenericAll', 'GenericExecute', 'GenericWrite', 'GenericRead'.

.PARAMETER PermissionSet

A pre-defined permission set to test a specified service against. 'ChangeConfig' or 'Restart'.

.EXAMPLE

Get-ServiceApi | Test-ServiceDaclPermission | Show-ServicePermissions

Service      Principal                ObjectName                                                                                Permissions
-------      ---------                ----------                                                                                -----------
UmRdpService NT AUTHORITY\INTERACTIVE localSystem     QueryConfig, ChangeConfig, QueryStatus, EnumerateDependents, Interrogate, ReadControl

Return all service objects where the current user can modify the service configuration.

.OUTPUTS

PowerUp.Service
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerUp.Service')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True)]
        [PSObject[]]
        [ValidateNotNullOrEmpty()]
        $Services,

        [String[]]
        [ValidateSet('QueryConfig', 'ChangeConfig', 'QueryStatus', 'EnumerateDependents', 'Start', 'Stop', 'PauseContinue', 'Interrogate', 'UserDefinedControl', 'Delete', 'ReadControl', 'WriteDac', 'WriteOwner', 'Synchronize', 'AccessSystemSecurity', 'GenericAll', 'GenericExecute', 'GenericWrite', 'GenericRead')]
        $Permissions,

        [String]
        [ValidateSet('ChangeConfig', 'Restart')]
        $PermissionSet = 'ChangeConfig'
    )

    BEGIN {
        $AccessMask = @{
            'QueryConfig'           = [uint32]'0x00000001'
            'ChangeConfig'          = [uint32]'0x00000002'
            'QueryStatus'           = [uint32]'0x00000004'
            'EnumerateDependents'   = [uint32]'0x00000008'
            'Start'                 = [uint32]'0x00000010'
            'Stop'                  = [uint32]'0x00000020'
            'PauseContinue'         = [uint32]'0x00000040'
            'Interrogate'           = [uint32]'0x00000080'
            'UserDefinedControl'    = [uint32]'0x00000100'
            'Delete'                = [uint32]'0x00010000'
            'ReadControl'           = [uint32]'0x00020000'
            'WriteDac'              = [uint32]'0x00040000'
            'WriteOwner'            = [uint32]'0x00080000'
            'Synchronize'           = [uint32]'0x00100000'
            'AccessSystemSecurity'  = [uint32]'0x01000000'
            'GenericAll'            = [uint32]'0x10000000'
            'GenericExecute'        = [uint32]'0x20000000'
            'GenericWrite'          = [uint32]'0x40000000'
            'GenericRead'           = [uint32]'0x80000000'
        }

        $CheckAllPermissionsInSet = $False

        if ($PSBoundParameters['Permissions']) {
            $TargetPermission = 0
            foreach($permission in $Permissions) {
                $TargetPermission = $TargetPermission -bxor $AccessMask[$Permission]
            }
        }
        else {
            if ($PermissionSet -eq 'ChangeConfig') {
                $TargetPermission = 0x500c0002
            }
            elseif ($PermissionSet -eq 'Restart') {
                $TargetPermission = 0x30
                $CheckAllPermissionsInSet = $True # so we check all permissions && style
            }
        }

        $UserIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $CurrentUserSids = $UserIdentity.Groups | Select-Object -ExpandProperty Value
        $CurrentUserSids += $UserIdentity.User.Value
    }

    PROCESS {

        ForEach($TargetService in $Services) {

            if( $TargetService.Dacl -eq $null ) {
                if( $PSBoundParameters['Verbose'] ) {
                    Write-Warning "Skipping: $TargetService.Name [No DACL]"
                }
                continue
            }

            ForEach($ServiceDacl in $TargetService.Dacl) {

                if ($CurrentUserSids -contains $ServiceDacl.SecurityIdentifier) {

                    if ($CheckAllPermissionsInSet) {
                        if (($ServiceDacl.AccessMask -band $TargetPermission) -eq $TargetPermission) {
                            $TargetService
                        }
                    }
                    else {
                        if (($ServiceDacl.AceType -eq 'AccessAllowed') -and ($ServiceDacl.AccessMask -band $TargetPermission)) {
                            $TargetService
                        }
                    }
                }
            }
        }
    }
}

Add-Type @"
    [System.FlagsAttribute]
    public enum ServiceAccessRights : uint {
    QueryConfig             =   0x00000001,
    ChangeConfig            =   0x00000002,
    QueryStatus             =   0x00000004,
    EnumerateDependents     =   0x00000008,
    Start                   =   0x00000010,
    Stop                    =   0x00000020,
    PauseContinue           =   0x00000040,
    Interrogate             =   0x00000080,
    UserDefinedControl      =   0x00000100,
    Delete                  =   0x00010000,
    ReadControl             =   0x00020000,
    WriteDac                =   0x00040000,
    WriteOwner              =   0x00080000,
    Synchronize             =   0x00100000,
    AccessSystemSecurity    =   0x01000000,
    GenericAll              =   0x10000000,
    GenericExecute          =   0x20000000,
    GenericWrite            =   0x40000000,
    GenericRead             =   0x80000000,
    AllAccess               =   0x000F01FF
}
"@
