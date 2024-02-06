
#############################################################################################
# DISCLAIMER:																				#
#																							#
# THE SAMPLE SCRIPTS ARE NOT SUPPORTED UNDER ANY MICROSOFT STANDARD SUPPORT					#
# PROGRAM OR SERVICE. THE SAMPLE SCRIPTS ARE PROVIDED AS IS WITHOUT WARRANTY				#
# OF ANY KIND. MICROSOFT FURTHER DISCLAIMS ALL IMPLIED WARRANTIES INCLUDING, WITHOUT		#
# LIMITATION, ANY IMPLIED WARRANTIES OF MERCHANTABILITY OR OF FITNESS FOR A PARTICULAR		#
# PURPOSE. THE ENTIRE RISK ARISING OUT OF THE USE OR PERFORMANCE OF THE SAMPLE SCRIPTS		#
# AND DOCUMENTATION REMAINS WITH YOU. IN NO EVENT SHALL MICROSOFT, ITS AUTHORS, OR			#
# ANYONE ELSE INVOLVED IN THE CREATION, PRODUCTION, OR DELIVERY OF THE SCRIPTS BE LIABLE	#
# FOR ANY DAMAGES WHATSOEVER (INCLUDING, WITHOUT LIMITATION, DAMAGES FOR LOSS OF BUSINESS	#
# PROFITS, BUSINESS INTERRUPTION, LOSS OF BUSINESS INFORMATION, OR OTHER PECUNIARY LOSS)	#
# ARISING OUT OF THE USE OF OR INABILITY TO USE THE SAMPLE SCRIPTS OR DOCUMENTATION,		#
# EVEN IF MICROSOFT HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES						#
#############################################################################################

<#PSScriptInfo

.VERSION 1.10

.GUID f9cfe327-869f-410e-90e3-7286c94c31fd

.AUTHOR timmcmic@microsoft.com

.COMPANYNAME Microsoft CSS

.COPYRIGHT

.TAGS

.LICENSEURI

.PROJECTURI

.ICONURI

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS

.EXTERNALSCRIPTDEPENDENCIES

.RELEASENOTES


.PRIVATEDATA

#>

<# 

.DESCRIPTION 
 This script will allow an administrator to purge objects from the connetor space and perform full object sync. 

#> 
Param
(
    #Define paramters to locate object in Active Directory
    [Parameter(Mandatory = $false)]
    [string]$ADObjectGUID="",
    [Parameter(Mandatory = $false)]
    [string]$ADObjectMAIL="",
    [Parameter(Mandatory = $false)]
    [string]$ADObjectDN="",
    [Parameter(Mandatory = $false)]
    [string]$ADConnectorName="",
    #Define parameteres to locate object in Entra Connector space.
    [Parameter(Mandatory = $false)]
    [string]$EntraDN="",
    [Parameter(Mandatory = $false)]
    [boolean]$CalculateEntraDN=$true,
    #Define parameters for Active Directory Connections.
    [Parameter(Mandatory = $false)]
    [string]$globalCatalogServer="",
    [Parameter(Mandatory = $false)]
    [psCredential]$activeDirectoryCredential=$NULL,
    #Define general parameters for the script.
    [Parameter(Mandatory = $true)]
    [string]$logFolderPath=$NULL
)

#Define the script parameters.

[string]$entraConnectInstallPath = ""
[boolean]$useActiveDirectoryLookup = $FALSE
[string]$sourceAnchorAttribute = ""
[string]$ADConnectorPowershell = "Microsoft Azure AD Sync\Extensions\AADConnector.psm1"
[string]$ADSyncDiagnosticsPowershell = "Microsoft Azure AD Sync\Bin\ADSyncDiagnostics\ADSyncDiagnostics.psm1"
[string]$ADConnectorPowershellFullpath = ""
[string]$ADSyncDiagnosticsPowershellFullPath = ""
$adObject = $NULL
$adConnectorType = "AD"
$entraConnectorType = "Extensible2"
[string]$entraConnectorName = ""

$adObjectXML = "adObject"
$adCSObjectXML = "adCSObject"
$entraCSObjectXML = "entraCSObject"

$logFileName = (Get-Date -Format FileDateTime)

$adCSObject = $NULL
$entraCSObject = $NULL


Function new-LogFile
{
    [cmdletbinding()]

    Param
    (
        [Parameter(Mandatory = $true)]
        [string]$logFileName,
        [Parameter(Mandatory = $true)]
        [string]$logFolderPath
    )

    [string]$logFileSuffix=".log"
    [string]$fileName=$logFileName+$logFileSuffix

    # Get our log file path

    $logFolderPath = $logFolderPath+"\"+$logFileName+"\"
    
    #Since $logFile is defined in the calling function - this sets the log file name for the entire script
    
    $global:LogFile = Join-path $logFolderPath $fileName

    #Test the path to see if this exists if not create.

    [boolean]$pathExists = Test-Path -Path $logFolderPath

    if ($pathExists -eq $false)
    {
        try 
        {
            #Path did not exist - Creating

            New-Item -Path $logFolderPath -Type Directory
        }
        catch 
        {
            throw $_
        } 
    }
}
Function Out-LogFile
{
    [cmdletbinding()]

    Param
    (
        [Parameter(Mandatory = $true)]
        $String,
        [Parameter(Mandatory = $false)]
        [boolean]$isError=$FALSE
    )

    # Get the current date

    [string]$date = Get-Date -Format G

    # Build output string
    #In this case since I abuse the function to write data to screen and record it in log file
    #If the input is not a string type do not time it just throw it to the log.

    if ($string.gettype().name -eq "String")
    {
        [string]$logstring = ( "[" + $date + "] - " + $string)
    }
    else 
    {
        $logString = $String
    }

    # Write everything to our log file and the screen

    $logstring | Out-File -FilePath $global:LogFile -Append

    #Write to the screen the information passed to the log.

    if ($string.gettype().name -eq "String")
    {
        Write-Host $logString
    }
    else 
    {
        write-host $logString | select-object -expandProperty *
    }

    #If the output to the log is terminating exception - throw the same string.

    if ($isError -eq $TRUE)
    {
        #Ok - so here's the deal.
        #By default error action is continue.  IN all my function calls I use STOP for the most part.
        #In this case if we hit this error code - one of two things happen.
        #If the call is from another function that is not in a do while - the error is logged and we continue with exiting.
        #If the call is from a function in a do while - write-error rethrows the exception.  The exception is caught by the caller where a retry occurs.
        #This is how we end up logging an error then looping back around.

        write-error $logString

        #Now if we're not in a do while we end up here -> go ahead and create the status file this was not a retryable operation and is a hard failure.

        exit
    }
}

Function write-FunctionParameters
{
    [cmdletbinding()]

    Param
    (
        [Parameter(Mandatory = $true)]
        $keyArray,
        [Parameter(Mandatory = $true)]
        $parameterArray,
        [Parameter(Mandatory = $true)]
        $variableArray
    )

    #Define script paramters

    Out-LogFile -string "********************************************************************************"

    $parameteroutput = @()

    foreach ($paramName in $keyArray)
    {
        $bound = $parameterArray.ContainsKey($paramName)

        $parameterObject = New-Object PSObject -Property @{
            ParameterName = $paramName
            ParameterValue = if ($bound) { $parameterArray[$paramName] }
                                else { ($variableArray | where {$_.name -eq $paramName } ).value }
            Bound = $bound
            }

        $parameterOutput+=$parameterObject
    }

    out-logfile -string $parameterOutput

    Out-LogFile -string "********************************************************************************"
}

function validate-ActiveDirectoryServerInfo
{
    Param
    (
        [Parameter(Mandatory = $true)]
        $globalCatalogServer,
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        $activeDirectoryCredential
    )

    out-logfile -string "Entering validate-ActiveDirectoryServerInfo"

    out-logfile -string "Validating global catalog server..."

    if ($globalCatalogServer -eq "")
    {
        out-logfile -string "A global catlog server must be specified in order to continue." -isError:$true
    }

    out-logfile -string "Validaing credentials passed."

    if ($activeDirectoryCredential -eq $NULL)
    {
        out-logfile -string "A validate Active Directory credential with rights to read objects must be provided." -isError:$TRUE
    }
    else 
    {
        out-logfile -string "Active Directory credential provided."
    }

    out-logfile -string "Exiting validate-ActiveDirectoryServerInfo"
}

function validate-ActiveDirectoryTools
{
    out-logfile -string "Entering validate-ActiveDirectoryTools"

    $functionCommands = get-command -module "ActiveDirectory"

    if ($functionCommands.count -eq 0)
    {
        out-logfile -string "Remote server administration tools for Active Directory required to proceed." -isError:$TRUE
    }
    else 
    {
        out-logfile -string "Remote server administration tools for Active Directory present."
    }

    
    out-logfile -string "Exiting validate-ActiveDirectoryTools"
}

function validate-EntraConnectServer
{
    out-logfile -string "Entering validate-EntraConnectServer"

    $functionApplicationDisplayName = "Microsoft Azure AD Connect synchronization services"
    $functionInstalledPrograms = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*
    
    $functionEntraConnect = $functionInstalledPrograms | where {$_.displayName -eq $functionApplicationDisplayName}

    out-logfile -string $functionEntraConnect

    $functionPathReturn = $functionEntraConnect.installSource.replace("\Microsoft Azure Active Directory Connect\SetupFiles\","\")
    
    out-logfile -string "Exiting validate-EntraConnectServer"

    return $functionPathReturn
}

function query-SourceAnchor
{
    [string]$globalSourceAnchorValue = "Microsoft.SynchronizationOption.AnchorAttribute"
    out-logfile -string "Entering query-SourceAnchor"

    out-logfile -string "Obtain Entra Connect Global Settings"

    try {
        $functionGlobalSettings = Get-ADSyncGlobalSettings -errorAction STOP
    }
    catch {
        out-logfile -string $_ -isError:$TRUE
    }

    $functionSourceAnchor = $functionGlobalSettings.parameters | where {$_.name -eq $globalSourceAnchorValue}

    out-logfile -string $functionSourceAnchor

    $functionSourceAnchorValue = $functionSourceAnchor.value

    out-logfile -string $functionSourceAnchorValue
    
    out-logfile -string "Exiting query-SourceAnchor"

    return $functionSourceAnchorValue
}

function import-PowershellCommands
{
    Param
    (
        [Parameter(Mandatory = $true)]
        $powerShellModule
    )
    out-logfile -string "Entering import-PowershellCommands"

    try {
        Import-Module $powerShellModule -errorAction STOP
        out-logfile -string "Powershell module imported successfully."
    }
    catch {
        out-logfile -string "Error importing powershell module necessary for script execution."
        out-logfile -string $_ -isError:$TRUE
    }

    out-logfile -string "Exiting import-PowershellCommands"
}

function collect-ADObject
{
    Param
    (
        [Parameter(Mandatory = $true)]
        $ADObjectDN,
        [Parameter(Mandatory = $true)]
        $ADObjectGUID,
        [Parameter(Mandatory = $true)]
        $ADObjectMAIL,
        [Parameter(Mandatory = $true)]
        $globalCatalogServer,
        [Parameter(Mandatory = $true)]
        $activeDirectoryCredential
    )

    $functionADObject = $NULL

    out-logfile -string "Entering collect-ADObject"

    if ($ADObjectDN -ne "")
    {
        try
        {
            out-logfile -string "Finding AD Object by DN."
            $functionADObject=get-adobject -identity $ADObjectDN -Server $globalCatalogServer -credential $activeDirectoryCredential -Properties * -errorAction STOP
        }
        catch {
            out-logfile -string "ADObjectDN specified but object not found by DN."
            out-logfile -string $_ -isError:$TRUE
        }
    }
    elseif ($ADObjectGUID -ne "")
    {
        try
        {
            out-logfile -string "Finding AD Object by GUID"
            $functionADObject=Get-ADObject -filter "objectGUID -eq `"$ADObjectGUID`"" -Server $globalCatalogServer -credential $activeDirectoryCredential -Properties * -errorAction STOP
        }
        catch {
            out-logfile -string "ADObjectGUID specified but object not found by DN."
            out-logfile -string $_ -isError:$TRUE
        }
    }
    elseif ($ADObjectMail -ne "")
    {
        try
        {
            out-logfile -string "Finding AD Object by Mail."
            $functionADObject=Get-ADObject -filter "mail -eq `"$ADObjectMail`"" -Server $globalCatalogServer -credential $activeDirectoryCredential -Properties * -errorAction STOP
        }
        catch {
            out-logfile -string "ADObjectMAIL specified but object not found by DN."
            out-logfile -string $_ -isError:$TRUE
        }
    }

    out-logfile -string $functionADObject

    out-logfile -string "Exiting collect-ADObject"

    return $functionADObject
}

function calculate-EntraDN
{
    Param
    (
        [Parameter(Mandatory = $true)]
        $adObject,
        [Parameter(Mandatory = $true)]
        $sourceAnchorAttribute
    )

    $anchor0 = "objectGUID"
    $anchor1 = "ms-ds-ConsistencyGuid"
    $functionGUID = $NULL
    $functionBase64String=$NULL
    $functionDN = $NULL

    out-logfile -string "Enter calculate-EntraDN"

    if (($sourceAnchorAttribute -eq $anchor0) -or ($sourceAnchorAttribute -eq $anchor1))
    {
        out-logfile -string "Source anchor is objectGUID or ms-ds-ConsistencyGUID"
        out-logfile -string "Determine if object has ms-ds-ConsistencyGUID"

        if ($adObject.'ms-ds-ConsistencyGUID' -ne $NULL)
        {
            out-logfile -string "MS-DS-ConsistencyGUID in use."
            out-logfile -string $adObject.'ms-ds-consistencyguid'

            $functionGuid = [GUID]$adObject.'ms-ds-ConsistencyGUID'
        }
        else
        {
            out-logfile -string "ObjectGUID in Use."
            out-logfile -string $adObject.objectGUID

            $functionGuid = [GUID]$adObject.objectGUID
        }

        out-logfile -string $functionGUID.Guid

        $functionBase64String = [System.Convert]::ToBase64String($functionGuid.ToByteArray())

        out-logfile -string $functionBase64String

        $functionDN = ConvertTo-ADSyncAadDistinguishedName -sourceAnchor $functionBase64String

        out-logfile -string $functionDN
    }
    else 
    {
        out-logfile -string "Source anchor attribute is a custom attribute."

        $functionBase64String = $adObject.$sourceAnchorAttribute

        out-logfile -string $functionBase64String

        $functionDN = ConvertTo-ADSyncAadDistinguishedName -sourceAnchor $functionBase64String

        out-logfile -string $functionDN
    }

    out-logfile -string "Exit calculate-EntraDN"

    return $functionDN
}

function get-Connector
{
    Param
    (
        [Parameter(Mandatory = $true)]
        $connectorType
    )
    out-logfile -string "Enter get-Connector"

    $functionConnectors = $NULL
    [string]$functionConnectorName

    try {
        $functionConnectors = Get-ADSyncConnector -errorAction STOP | where {$_.connectorTypeName -eq $connectorType}
    }
    catch {
        out-logfile -string "Unable to obtain the Entra Connect connectors."
        out-logfile -string $_
    }
    
    out-logfile -string $functionConnectors

    if ($functionConnectors.count -gt 1)
    {
        out-logfile -string "More than one Active Directory connector exists.  Please specify -ADConnectorName with the name from Synchornization Manager -> Connectors"
    }
    else 
    {
        $functionConnectorName = $functionConnectors.name
    }

    out-logfile -string "Exit get-Connector"

    return $functionConnectorName
}

Function Out-XMLFile
    {
    [cmdletbinding()]

    Param
    (
        [Parameter(Mandatory = $true)]
        $itemToExport,
        [Parameter(Mandatory = $true)]
        [string]$itemNameToExport
    )

    Out-LogFile -string "********************************************************************************"
    Out-LogFile -string "BEGIN OUT-XMLFILE"
    Out-LogFile -string "********************************************************************************"

    #Declare function variables.

    $fileName = $itemNameToExport+".xml"

    #Update the log folder path to include the static folder.

    $logFolderPath = $logFolderPath+"\"+$logFileName+"\"
    
    # Get our log file path and combine it with the filename

    $LogFile = Join-path $logFolderPath $fileName

    #Write our variables to the log.

    out-logfile -string ("XML File Name = "+$fileName)
    out-logfile -string ("Log Folder Path = "+$logFolderPath)
    out-logfile -string ("Log File = "+$LogFile)

    # Write everything to our log file and the screen

    try 
    {
        $itemToExport | export-CLIXML -path $LogFile
    }
    catch 
    {
        throw $_
    }

    Out-LogFile -string "END OUT-XMLFILE"
    Out-LogFile -string "********************************************************************************"
}

function get-CSObject
{
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]$dn,
        [Parameter(Mandatory = $true)]
        [string]$connectorName
    )
    out-logfile -string "Enter get-CSObject"

    $functionCSObject=$NULL

    try {
        $functionCSObject = Get-ADSyncCSObject -DistinguishedName $dn -ConnectorName $connectorName.trim()
    }
    catch {
        out-logfile -string "Uanble to locate CS Object by DN."
        out-logfile -string $_ -isError:$true
    }
    
    out-logfile -string $functionCSObject

    out-logfile -string "Exit get-CSObject"

    return $functionCSObject
}
Function  start-sleepProgress
{
    [cmdletbinding()]

    Param
    (
        [Parameter(Mandatory = $true)]
        [string]$sleepString,
        [Parameter(Mandatory = $true)]
        [int]$sleepSeconds,
        [Parameter(Mandatory = $false)]
        [int]$sleepParentID=0,
        [Parameter(Mandatory = $false)]
        [int]$sleepID=0
    )

    #Output all parameters bound or unbound and their associated values.

    write-functionParameters -keyArray $MyInvocation.MyCommand.Parameters.Keys -parameterArray $PSBoundParameters -variableArray (Get-Variable -Scope Local -ErrorAction Ignore)

    Out-LogFile -string "********************************************************************************"
    Out-LogFile -string "BEGIN  start-sleepProgess"
    Out-LogFile -string "********************************************************************************"

    if(($sleepId -eq 0)-and ($sleepParentID -eq 0))
    {
        For ($i=$sleepSeconds; $i -gt 0; $i--) 
        {  
            Write-Progress -Activity $sleepString -SecondsRemaining $i
            Start-Sleep 1
        }

        write-progress -activity $sleepString -Completed
    }
    else 
    {
        For ($i=$sleepSeconds; $i -gt 0; $i--) 
        {  
            Write-Progress -Activity $sleepString -SecondsRemaining $i -Id $sleepID -ParentId $sleepParentID
            Start-Sleep 1
        }

        Write-Progress -Activity $sleepString -Id $sleepID -ParentId $sleepParentID -Completed
    }

    Out-LogFile -string "END start-sleepProgess"
    Out-LogFile -string "********************************************************************************"
}

Function suspend-EntraSync
{
    $retry = $TRUE
    out-logfile -string "Enter suspend-EntraSync"

    do
    {
        try {
            Set-ADSyncScheduler -SyncCycleEnabled:$FALSE -errorAction STOP
            out-logfile -string "Sync cycle suspended successfully."
            $retry=$FALSE
        }
        catch {
            out-logfile -string $_
            start-sleepProgress -sleepString "Unable to set scheduled to false - sleeping" -sleepSeconds 15
        }
    }until ($retry -eq $FALSE)

    out-logfile -string "End suspend-EntraSync"
}

Function delete-CSObject
{
    [cmdletbinding()]

    Param
    (
        [Parameter(Mandatory = $true)]
        $csObject
    )

    out-logfile -string "Enter delete-CSObject"

    try {
        Remove-ADSyncCSObject -CsObject $csObject -Force -errorAction STOP
    }
    catch {
        out-logfile -string "Error deleting CS Object."
        out-logfile -string $_ -isError:$true
    }

    out-logfile -string "End delete-CSObject"
}

Function start-EntraSync
{
    [cmdletbinding()]

    Param
    (
        [Parameter(Mandatory = $true)]
        $policyType
    )

    $retry = $true
    $delta = "Delta"
    $single = "Single"

    out-logfile -string "Enter start-EntraSync"

    if ($policyType -eq $delta)
    {
        do
        {
            try {
                start-adSyncSyncCycle -policyType Delta -errorAction STOP
                out-logfile -string "Delta sync triggered successfully."
                $retry=$FALSE
            }
            catch {
                out-logfile -string $_
                start-sleepProgress -sleepString "Unable to perform delta sync - sleeping" -sleepSeconds 15
            }
        }until ($retry -eq $FALSE)
    }

    out-logfile -string "End start-EntraSync"
}

#Create the log file.

new-logfile -logFileName $logFileName -logFolderPath $logFolderPath

#Start logging

out-logfile -string "*********************************************************************************"
out-logfile -string "Start reset-EntraConnectObject"
out-logfile -string "*********************************************************************************"

#Capture paramters for review.

out-logfile -string "Script paramters:"
write-functionParameters -keyArray $MyInvocation.MyCommand.Parameters.Keys -parameterArray $PSBoundParameters -variableArray (Get-Variable -Scope Local -ErrorAction Ignore)

#If an Active Directory DN and entra DN were provided - there's no need to calculate valies.

if (($entraDN -ne "") -and ($ADObjectDN -ne ""))
{
    out-logfile -string "Both an EntraDN and AD DN were specified - no calculations necessary."
    $CalculateEntraDN = $false
    $useActiveDirectoryLookup = $false
    out-logfile -string ("Calculate EntraDN: "+$CalculateEntraDN)
    out-logfile -string ("Use Active Directory Lookup: "+$useActiveDirectoryLookup)
}
elseif (($ADObjectDN -ne "") -or ($ADObjectGUID -ne "") -or ($ADObjectMail -ne ""))
{
    out-logfile -string "Active Directory Information Provided."

    if (($entraDN -eq "") -and ($CalculateEntraDN -eq $TRUE))
    {
       out-logfile -string "No entra ID provided."
       out-logfile -string "Calculate EntraDN is TRUE."
       out-logfile -string "Allow directory lookup to calculate entraDN." 

       $useActiveDirectoryLookup = $TRUE

       out-logfile -string ("Use Active Directory Lookup: "+$useActiveDirectoryLookup)
    }
    elseif (($entraDN -ne "") -and ($CalculateEntraDN -eq $TRUE))
    {
        out-logfile -string "Entra DN provided with AD Information - calculate EntraDN not necessary."
        $CalculateEntraDN=$false

        if ($adObjectDN -ne "")
        {
            out-logfile -string "AD Object DN specified - AD looksups no required."
            $useActiveDirectoryLookup = $false
        }
        else 
        {
            out-logfile -string "AD Object Mail or GUID specified - lookup required."
            $useActiveDirectoryLookup = $true
        }
    }
    elseif (($entraDN -eq "") -and ($CalculateEntraDN -eq $FALSE))
    {
        out-logfile -string "An EntraDN was not specified and calculate false - assume AD connector space only purge."

        if ($adObjectDN -ne "")
        {
            out-logfile -string "AD Object DN specified - AD looksups no required."
            $useActiveDirectoryLookup = $false
        }
        else 
        {
            out-logfile -string "AD Object Mail or GUID specified - lookup required."
            $useActiveDirectoryLookup = $true
        }
    }
}
elseif (($ADObjectDN -eq "") -or ($ADObjectGUID -eq "") -or ($ADObjectMail -eq ""))
{
    out-logfile -string "No AD information provided - test for Entra Connector space remove only."

    if ($EntraDN -ne "")
    {
        out-logfile -string "EntraDN specified only."
        $CalculateEntraDN=$false
    }
    else 
    {
        out-logfile -string "No AD or EntraDN information provided - no work to do." -isError:$true
    }
}

#Determine the AD Connect installation path.

out-logfile -string "Determine the Entra Connect installation root path - required for further script importation."

$entraConnectInstallPath=validate-EntraConnectServer

out-logfile -string $entraConnectInstallPath

out-logfile -string "Construct powershell modules to import path."

$ADConnectorPowershellFullpath = $entraConnectInstallPath+$ADConnectorPowershell
out-logfile -string $ADConnectorPowershellFullpath
$ADSyncDiagnosticsPowershellFullPath = $entraConnectInstallPath+$ADSyncDiagnosticsPowershell
out-logfile -string $ADSyncDiagnosticsPowershellFullPath

out-logfile -string "Importing powershell commands necessary for script execution."

import-PowershellCommands -powerShellModule $ADConnectorPowershellFullpath
import-PowershellCommands -powerShellModule $ADSyncDiagnosticsPowershellFullPath

#The following is performed only if the distinguished name is not provided forcing active directory lookup.

#If use active directory is true perform pre-req checks.

if ($useActiveDirectoryLookup -eq $TRUE)
{
    out-logfile -string "Lookup attribute provided - requires Active Directory connectivity.
    "
    #Validate the Active Directory Tools are installed

    validate-ActiveDirectoryTools

    #Validate the Active Directory Server information.

    validate-ActiveDirectoryServerInfo -globalCatalogServer $globalCatalogServer -activeDirectoryCredential $activeDirectoryCredential

    #Obtain the active directory object for futher work.

    $adObject = collect-ADObject -ADObjectDN $ADObjectDN -adobjectguid $adobjectGUID -adObjectMail $ADObjectMAIL -globalCatalogServer $globalCatalogServer -activeDirectoryCredential $activeDirectoryCredential

    out-logfile -string $adObject

    Out-XMLFile -itemToExport $adobject -itemNameToExport $adObjectXML
}

#At this time we can calculate the entraDN if necessary.

if ($CalculateEntraDN -eq $TRUE)
{
    out-logfile -string "Determine the source anchor."

    $sourceAnchorAttribute = query-SourceAnchor

    out-logfile -string "Calculate the Entra Connector Space DN"

    $entraDN = calculate-EntraDN -adObject $adObject -sourceAnchorAttribute $sourceAnchorAttribute

    out-logfile -string $EntraDN
}

out-logfile -string "Determine if Active Directory connector name specified - if so use otherwise determine - if more than 1 fail."

if ($adConnectorName -eq "")
{
    out-logfile -string "No AD Connector specified - determine if more than one or automatic selection."

    $adConnectorName = get-Connector -connectorType $adConnectorType

    out-logfile -string $adConnectorName
}

out-logfile -string "Determine the entra connector name."

$entraConnectorName = get-Connector -connectorType $entraConnectorType

out-logfile -string $entraConnectorName

out-logfile -string "Capture the CS objects"

if ($adobject -ne $NULL)
{
    out-logfile -string "An active directory object was specified."

    $adCSObject = get-CSObject -dn $adobject.distinguishedName -connectorName $ADConnectorName

    Out-LogFile -string $adCSObject

    out-xmlFile -itemToExport $adCSObject -itemNameToExport $adCSObjectXML
}
elseif ($adObjectDN -ne "") 
{
    out-logfile -string "An active directory object DN was specified."

    $adCSObject = get-CSObject -dn $ADObjectDN -connectorName $ADConnectorName

    Out-LogFile -string $adCSObject

    out-xmlFile -itemToExport $adCSObject -itemNameToExport $adCSObjectXML
}
else 
{
    out-logfile -string "No Active Directory CS object information obtained."
}

if ($EntraDN -ne "")
{
    out-logfile -string "An entra DN was specified or calculated."

    out-logfile -string $entraConnectorName.getType()

    $entraCSObject = get-CSObject -dn $EntraDN -connectorName $entraConnectorName

    out-logfile -string $entraCSObject

    out-xmlFile -itemToExport $entraCSObject -itemNameToExport $entraCSObjectXML
}

out-logfile -string "Suspend Entra Connect synchornization while object removal and sync is in progress."

suspend-EntraSync

out-logfile -string "Suspend Entra Connect synchronization successful - proceed with connector space object deletion."

if ($adCSObject -ne $NULL)
{
    delete-CSObject -csObject $adCSObject
}

if ($entraCSObject -ne $NULL)
{
    delete-CSObject -csObject $entraCSObject
}

out-logfile -string "If the object was an entra connetor space only move detal sync required - otherwise single object is fine."

if (($adCSObject -eq $NULL) -and ($entraCSObject -ne $NULL))
{
    start-EntraSync -policyType "Delta"
}