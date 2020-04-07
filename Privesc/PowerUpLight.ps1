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

Get-ChildItem C:\ProgramData\ -File -Recurse -ErrorAction SilentlyContinue | Get-ModifiablePath -Literal

Path                       Permissions                IdentityReference
----                       -----------                -----------------
C:\Vuln\blah.bat           {ReadAttributes, ReadCo... NT AUTHORITY\Authentic...
C:\Vuln\config.ini         {ReadAttributes, ReadCo... NT AUTHORITY\Authentic...
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
                    $Acl = Get-Acl -Path $CandidatePath
                    $Owner = $Acl.Owner;
                } catch [System.UnauthorizedAccessException] {
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
                $CandidatePath = "Microsoft.PowerShell.Core\Registry::$($TargetPath.replace(':',''))"
            }

            if (Test-Path -Path $CandidatePath -ErrorAction SilentlyContinue) {
                $CandidatePath = Resolve-Path -Path $CandidatePath | Select-Object -ExpandProperty Path
            } else {
                # if the path doesn't exist, check if the parent folder allows for modification
                $ParentPath = Split-Path -Path $CandidatePath -Parent  -ErrorAction SilentlyContinue
                if ($ParentPath -and (Test-Path -Path $ParentPath)) {
                    $CandidatePath = Resolve-Path -Path $ParentPath -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path
                } else {
                    continue
                }
            }

            $Acl = Get-Acl -Path $CandidatePath -ErrorAction SilentlyContinue
            $Owner = $Acl.Owner

            # handling forward slashes inside of registry keys is a pain. Test-Path will tell you that the path exists.
            # Get-Acl will throw an exception, but only if -ErrorAction is not Stop. If the -ErrorAction is Stop,
            # Get-Acl will throw no error and just return $null. Therefore, we cannot try/catch, but need instead to check
            # manually if the $Acl result is $null. If it is and the path contains a '/', we obtain the ACL in another way.
            if( $Acl -eq $null ) {
                if( $CandidatePath.contains('/') ) {
                    try {
                        $Split = $CandidatePath.split('\')
                        $hive = Get-Item ($Split[0,1] -join '\')
                        $CandidatePath = $hive.OpenSubKey($Split[2..$Split.Length] -join '\')
                        $Acl = $CandidatePath.GetAccessControl()
                        $Owner = $Acl.Owner
                    } catch {
                        continue
                    }
                } else {
                    continue
                }
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
