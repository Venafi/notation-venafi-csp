<#
    .SYNOPSIS
    Downloads and installs Venafi CodeSign Protect plugin for notation (notary v2) on the local machine.

    .DESCRIPTION
    Retrieves the Venafi CodeSign Protect plugin for the latest or a specified version, and
    downloads and installs the plugin to the local machine.

    .NOTES
    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
    =====================================================================

#>
[CmdletBinding(DefaultParameterSetName = 'Default')]
param(
    # The URL to download notation-venafi-csp from. 
    [Parameter(Mandatory = $false)]
    [string]
    $PluginDownloadUrl = $env:pluginDownloadUrl,

    # Specifies a target version of notation-venafi-csp to install. By default, the latest
    # stable version is installed. 
    [Parameter(Mandatory = $false)]
    [string]
    $PluginVersion = $env:pluginVersion
)

#region Functions

$PluginName = "notation-venafi-csp"
$GitHubURL = "https://github.com/venafi/notation-venafi-csp"


function Get-Downloader {
    <#
    .SYNOPSIS
    Gets a System.Net.WebClient that respects relevant proxies to be used for
    downloading data.

    .DESCRIPTION
    Retrieves a WebClient object that is pre-configured according to specified
    environment variables for any proxy and authentication for the proxy.
    Proxy information may be omitted if the target URL is considered to be
    bypassed by the proxy (originates from the local network.)

    .PARAMETER Url
    Target URL that the WebClient will be querying. This URL is not queried by
    the function, it is only a reference to determine if a proxy is needed.

    .EXAMPLE
    Get-Downloader -Url $fileUrl

    Verifies whether any proxy configuration is needed, and/or whether $fileUrl
    is a URL that would need to bypass the proxy, and then outputs the
    already-configured WebClient object.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]
        $Url,

        [Parameter(Mandatory = $false)]
        [string]
        $ProxyUrl,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        $ProxyCredential
    )

    $downloader = New-Object System.Net.WebClient

    $defaultCreds = [System.Net.CredentialCache]::DefaultCredentials
    if ($defaultCreds) {
        $downloader.Credentials = $defaultCreds
    }

    if ($ProxyUrl) {
        # Use explicitly set proxy.
        Write-Host "Using explicit proxy server '$ProxyUrl'."
        $proxy = New-Object System.Net.WebProxy -ArgumentList $ProxyUrl, <# bypassOnLocal: #> $true

        $proxy.Credentials = if ($ProxyCredential) {
            $ProxyCredential.GetNetworkCredential()
        } elseif ($defaultCreds) {
            $defaultCreds
        } else {
            Write-Warning "Default credentials were null, and no explicitly set proxy credentials were found. Attempting backup method."
            (Get-Credential).GetNetworkCredential()
        }

        if (-not $proxy.IsBypassed($Url)) {
            $downloader.Proxy = $proxy
        }
    } else {
        Write-Host "Not using proxy."
    }

    $downloader
}

function Request-String {
    <#
    .SYNOPSIS
    Downloads content from a remote server as a string.

    .DESCRIPTION
    Downloads target string content from a URL and outputs the resulting string.
    Any existing proxy that may be in use will be utilised.

    .PARAMETER Url
    URL to download string data from.

    .PARAMETER ProxyConfiguration
    A hashtable containing proxy parameters (ProxyUrl and ProxyCredential)

    .EXAMPLE
    Request-String https://github.com/venafi/notation-venafi-csp/install/install.ps1

    Retrieves the contents of the string data at the targeted URL and outputs
    it to the pipeline.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Url,

        [Parameter(Mandatory = $false)]
        [hashtable]
        $ProxyConfiguration
    )

    (Get-Downloader $url @ProxyConfiguration).DownloadString($url)
}

function Request-File {
    <#
    .SYNOPSIS
    Downloads a file from a given URL.

    .DESCRIPTION
    Downloads a target file from a URL to the specified local path.
    Any existing proxy that may be in use will be utilised.

    .PARAMETER Url
    URL of the file to download from the remote host.

    .PARAMETER File
    Local path for the file to be downloaded to.

    .PARAMETER ProxyConfiguration
    A hashtable containing proxy parameters (ProxyUrl and ProxyCredential)

    .EXAMPLE
    Request-File -Url https://github.com/venafi/notation-venafi-csp/install/install.ps1 -File $targetFile

    Downloads the install.ps1 script to the path specified in $targetFile.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]
        $Url,

        [Parameter(Mandatory = $false)]
        [string]
        $File,

        [Parameter(Mandatory = $false)]
        [hashtable]
        $ProxyConfiguration
    )

    Write-Host "Downloading $url to $file"
    (Get-Downloader $url @ProxyConfiguration).DownloadFile($url, $file)
}

function Set-PSConsoleWriter {
    <#
    .SYNOPSIS
    Workaround for a bug in output stream handling PS v2 or v3.

    .DESCRIPTION
    PowerShell v2/3 caches the output stream. Then it throws errors due to the
    FileStream not being what is expected. Fixes "The OS handle's position is
    not what FileStream expected. Do not use a handle simultaneously in one
    FileStream and in Win32 code or another FileStream." error.

    .EXAMPLE
    Set-PSConsoleWriter

    .NOTES
    General notes
    #>

    [CmdletBinding()]
    param()
    if ($PSVersionTable.PSVersion.Major -gt 3) {
        return
    }

    try {
        # http://www.leeholmes.com/blog/2008/07/30/workaround-the-os-handles-position-is-not-what-filestream-expected/ plus comments
        $bindingFlags = [Reflection.BindingFlags] "Instance,NonPublic,GetField"
        $objectRef = $host.GetType().GetField("externalHostRef", $bindingFlags).GetValue($host)

        $bindingFlags = [Reflection.BindingFlags] "Instance,NonPublic,GetProperty"
        $consoleHost = $objectRef.GetType().GetProperty("Value", $bindingFlags).GetValue($objectRef, @())
        [void] $consoleHost.GetType().GetProperty("IsStandardOutputRedirected", $bindingFlags).GetValue($consoleHost, @())

        $bindingFlags = [Reflection.BindingFlags] "Instance,NonPublic,GetField"
        $field = $consoleHost.GetType().GetField("standardOutputWriter", $bindingFlags)
        $field.SetValue($consoleHost, [Console]::Out)

        [void] $consoleHost.GetType().GetProperty("IsStandardErrorRedirected", $bindingFlags).GetValue($consoleHost, @())
        $field2 = $consoleHost.GetType().GetField("standardErrorWriter", $bindingFlags)
        $field2.SetValue($consoleHost, [Console]::Error)
    } catch {
        Write-Warning "Unable to apply redirection fix."
    }
}

function Test-PluginInstalled {
    [CmdletBinding()]
    param()

    $checkPath =  "$env:APPDATA\notation\plugins\venafi-csp"

   
    if (-not (Test-Path $checkPath)) {
        # Install folder doesn't exist
        $false
    }
    elseif (-not (Get-ChildItem -Path $checkPath)) {
        # Install folder exists but is empty
        $false
    }
    else {
        # Install folder exists and is not empty
        Write-Warning "Files from a previous installation of $PluginName were found at '$($CheckPath)'."
        $true
    }
}

#endregion Functions

#region Pre-check

# Ensure we have all our streams setup correctly, needed for older PSVersions.
Set-PSConsoleWriter

if (Test-PluginInstalled) {
    $message = @(
        "An existing $PluginName installation was detected. Installation will not continue."
        "For security reasons, this script will not overwrite existing installations."
        ""
    ) -join [Environment]::NewLine

    Write-Warning $message

    return
}

#endregion Pre-check

#region Setup

$proxyConfig = if ($IgnoreProxy -or -not $ProxyUrl) {
    @{}
} else {
    $config = @{
        ProxyUrl = $ProxyUrl
    }

    if ($ProxyCredential) {
        $config['ProxyCredential'] = $ProxyCredential
    } 

    $config
}

# Attempt to set highest encryption available for SecurityProtocol.
# PowerShell will not set this by default (until maybe .NET 4.6.x). This
# will typically produce a message for PowerShell v2 (just an info
# message though)
try {
    # Set TLS 1.2 (3072).
    # Use integers because the enumeration value for TLS 1.2 won't exist
    # in .NET 4.0, even though they are addressable if .NET 4.5+ is
    # installed (.NET 4.5 is an in-place upgrade).
    Write-Host "Forcing web requests to allow TLS v1.2"
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
}
catch {
    $errorMessage = @(
        'Unable to set PowerShell to use TLS 1.2.'
    ) -join [Environment]::NewLine
    Write-Warning $errorMessage
}

if ($PluginDownloadUrl) {
    if ($PluginVersion) {
        Write-Warning "Ignoring -PluginVersion parameter ($PluginVersion) because -PluginDownloadUrl is set."
    }

    Write-Host "Downloading Notation plugin for Venafi CodeSign Protect from: $PluginDownloadUrl"
} elseif ($PluginVersion) {
    Write-Host "Downloading specific version of $PluginName plugin: $PluginVersion"
    $PluginDownloadUrl = "$GitHubURL/releases/download/$PluginVersion/$PluginName-windows-amd64.exe"
} else {
    Write-Host "Getting latest version of the $PluginName package for download."
    $url = "$GitHubURL/releases/latest"
    $request = [System.Net.WebRequest]::Create($url)
    $response = $request.GetResponse()
    $responseURI = $response.ResponseUri.OriginalString
    $version = $responseURI.split('/')[-1]
    $PluginDownloadUrl = "$GitHubURL/releases/download/$version/$PluginName-windows-amd64.exe"
}

if (-not $env:TEMP) {
    $env:TEMP = Join-Path $env:SystemDrive -ChildPath 'temp'
}

$pluginTempDir = Join-Path $env:TEMP -ChildPath $PluginName
$tempDir = Join-Path $pluginTempDir -ChildPath "$PluginName-install"

if (-not (Test-Path $tempDir -PathType Container)) {
    $null = New-Item -Path $tempDir -ItemType Directory
}

#endregion Setup

#region Download & Extract notation-venafi-csp

# If we are passed a valid local path, we do not need to download it.
if (Test-Path $PluginDownloadUrl) {
    $file = $PluginDownloadUrl

    Write-Host "Using $PluginName from $PluginDownloadUrl."
} else {
    $file = Join-Path $tempDir "$PluginName.exe"

    Write-Host "Getting $PluginName from $PluginDownloadUrl."
    Request-File -Url $PluginDownloadUrl -File $file -ProxyConfiguration $proxyConfig
}

#endregion Download & Extract notation-venafi-csp

#region Install notation-venafi-csp

Write-Host "Installing $PluginName on the local machine"
$pluginInstallPath = "$env:APPDATA\notation\plugins\venafi-csp"

# Create plugin folder structure
New-Item -Path $pluginInstallPath -ItemType Directory

Copy-Item -Path $file -Destination $pluginInstallPath -Force -ErrorAction SilentlyContinue

#endregion Install notation-venafi-csp