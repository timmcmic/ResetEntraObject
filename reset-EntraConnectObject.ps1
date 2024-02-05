
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

.VERSION 1.1

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

new-logfile -logFileName (get-random) -logFolderPath $logFolderPath