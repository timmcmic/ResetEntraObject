
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

.VERSION 1.3

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
    [string]$objectGUID="",
    [Parameter(Mandatory = $false)]
    [string]$objectMAIL="",
    #Define parameters for Active Directory Connections.
    [Parameter(Mandatory = $false)]
    [string]$globalCatalogServer="",
    [Parameter(Mandatory = $false)]
    [psCredential]$activeDirectoryCredential=$NULL,
    #Define general parameters for the script.
    [Parameter(Mandatory = $true)]
    [string]$logFolderPath=$NULL
)

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

    #First entry in split array is the prefix of the group - use that for log file name.
    #The SMTP address may contain letters that are not permitted in a file name - for example ?.
    #Using regex and a pattern to replace invalid file name characters with a -

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

#Create the log file.

new-logfile -logFileName (Get-Date -Format FileDateTime) -logFolderPath $logFolderPath

#Start logging

out-logfile -string "*********************************************************************************"
out-logfile -string "Start reset-EntraConnectObject"
out-logfile -string "*********************************************************************************"

#Capture paramters for review.

out-logfile -string "Script paramters:"
write-functionParameters -keyArray $MyInvocation.MyCommand.Parameters.Keys -parameterArray $PSBoundParameters -variableArray (Get-Variable -Scope Local -ErrorAction Ignore)

