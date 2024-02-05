
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
    [psCredential]$activeDirectoryCredential=$NULL
)

write-host "Test"