#------------------------------------------------------------
# Based on Azure AD Sign-Ins "DownloadScripts.ps1" from Microsoft
#
# Function Get-AccessToken taken from https://blogs.technet.microsoft.com/cloudlojik/2018/06/29/connecting-to-microsoft-graph-with-a-native-app-using-powershell/
# (Paul Kotylo)
#
#
# 20191208
# Stephan Wälde
#
# tested with version 2.0.2.77 of the AzureADPreview PowerShell module
# tested with version 2.0.2.76 of the AzureAD Powershell module
#------------------------------------------------------------


# Replace with own Tenant ID and Account ID
$tenantId = "xxxxxxxx-86f1-41af-91ab-xxxxxxxxxxxx"
$accountId = "xxxxxxxx-44b4-4489-8e99-xxxxxxxxxxxx"





# The filter expression in this URL gets the Sign-In records of the specified Account ID
# The records will be returned by the Graph API after Account ID's logon without any additional permissions
$url = "https://graph.microsoft.com/beta/auditLogs/signIns?api-version=beta&`$filter=(userId%20eq%20%27$accountId%27)&`$orderby=createdDateTime%20desc"



# from https://blogs.technet.microsoft.com/cloudlojik/2018/06/29/connecting-to-microsoft-graph-with-a-native-app-using-powershell/
# using PowerShell as clientID
Function Get-AccessToken ($TenantName, $ClientID, $redirectUri, $resourceAppIdURI, $CredPrompt){
    Write-Host "Checking for AzureAD module..."
    if (!$CredPrompt){$CredPrompt = 'Auto'}

    $AadModule = Get-Module -Name "AzureAD" -ListAvailable
    if ($AadModule -eq $null) {$AadModule = Get-Module -Name "AzureADPreview" -ListAvailable}
    if ($AadModule -eq $null) {write-host "AzureAD Powershell module is not installed. The module can be installed by running 'Install-Module AzureAD' or 'Install-Module AzureADPreview' from an elevated PowerShell prompt. Stopping." -f Yellow;exit}
    if ($AadModule.count -gt 1) {
        $Latest_Version = ($AadModule | select version | Sort-Object)[-1]
        $aadModule      = $AadModule | ? { $_.version -eq $Latest_Version.version }
        $adal           = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
        $adalforms      = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"
        }
    else {
        $adal           = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
        $adalforms      = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"
        }
    [System.Reflection.Assembly]::LoadFrom($adal) | Out-Null
    [System.Reflection.Assembly]::LoadFrom($adalforms) | Out-Null
    $authority          = "https://login.microsoftonline.com/$TenantName"
    $authContext        = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority
    $platformParameters = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters"    -ArgumentList $CredPrompt
    $authResult         = $authContext.AcquireTokenAsync($resourceAppIdURI, $clientId, $redirectUri, $platformParameters).Result
    return $authResult
    }






# First, let's authenticate
$clientId = "1b730954-1685-4b74-9bfd-dac224a7b894" # PowerShell
$redirectUri = "urn:ietf:wg:oauth:2.0:oob"
$MSGraphURI = "https://graph.microsoft.com"
$CredPrompt = "Always"

$AccessToken = Get-AccessToken -TenantName $tenantId -ClientID $clientId -redirectUri $redirectUri -resourceAppIdURI $MSGraphURI -CredPrompt $CredPrompt






# Next, let's get the Sign-in data
$now = get-date -Format "yyyyMMddhhmm"
$outputFile = "$now-AzureADSignIns-$tenantId.csv"

$headers = @{
        'Content-Type'  = 'application\json'
        'Authorization' = $AccessToken.CreateAuthorizationHeader()
        }


# anything below is taken from the "DownloadScripts.ps1" from Microsoft
Function Expand-Collections {
    [cmdletbinding()]
    Param (
        [parameter(ValueFromPipeline)]
        [psobject]$MSGraphObject
    )
    Begin {
        $IsSchemaObtained = $False
    }
    Process {
        If (!$IsSchemaObtained) {
            $OutputOrder = $MSGraphObject.psobject.properties.name
            $IsSchemaObtained = $True
        }

        $MSGraphObject | ForEach-Object {
            $singleGraphObject = $_
            $ExpandedObject = New-Object -TypeName PSObject

            $OutputOrder | ForEach-Object {
                Add-Member -InputObject $ExpandedObject -MemberType NoteProperty -Name $_ -Value $(($singleGraphObject.$($_) | Out-String).Trim())
            }
            $ExpandedObject
        }
    }
    End {}
}
        
Write-Output "--------------------------------------------------------------"
Write-Output "Downloading from $url"
Write-Output "Output file: $outputFile"
Write-Output "--------------------------------------------------------------"

$count=0
$retryCount = 0
$oneSuccessfulFetch = $False

Do {
    Write-Output "Fetching data using Url: $url"

    Try {
        $myReport = (Invoke-WebRequest -UseBasicParsing -Headers $headers -Uri $url)
        $convertedReport = ($myReport.Content | ConvertFrom-Json).value
        $convertedReport | Expand-Collections | ConvertTo-Csv -NoTypeInformation | Add-Content $outputFile
        $url = ($myReport.Content | ConvertFrom-Json).'@odata.nextLink'
        $count = $count+$convertedReport.Count
        Write-Output "Total Fetched: $count"
        $oneSuccessfulFetch = $True
        $retryCount = 0
    }
    Catch [System.Net.WebException] {
        $statusCode = [int]$_.Exception.Response.StatusCode
        Write-Output $statusCode
        Write-Output $_.Exception.Message
        if($statusCode -eq 401 -and $oneSuccessfulFetch)
        {
            # Token might have expired! Renew token and try again
            $authResult = $authContext.AcquireToken($MSGraphURI, $clientId, $redirectUri, "Auto")
            $token = $authResult.AccessToken
            $headers = Get-Headers($token)
            $oneSuccessfulFetch = $False
        }
        elseif($statusCode -eq 429 -or $statusCode -eq 504 -or $statusCode -eq 503)
        {
            # throttled request or a temporary issue, wait for a few seconds and retry
            Start-Sleep -5
        }
        elseif($statusCode -eq 403 -or $statusCode -eq 400 -or $statusCode -eq 401)
        {
            Write-Output "Please check the permissions of the user"
            break;
        }
        else {
            if ($retryCount -lt 5) {
                Write-Output "Retrying..."
                $retryCount++
            }
            else {
                Write-Output "Download request failed. Please try again in the future."
                break
            }
        }
     }
    Catch {
        $exType = $_.Exception.GetType().FullName
        $exMsg = $_.Exception.Message

        Write-Output "Exception: $_.Exception"
        Write-Output "Error Message: $exType"
        Write-Output "Error Message: $exMsg"

         if ($retryCount -lt 5) {
            Write-Output "Retrying..."
            $retryCount++
        }
        else {
            Write-Output "Download request failed. Please try again in the future."
            break
        }
    }

    Write-Output "--------------------------------------------------------------"
} while($url -ne $null)
	