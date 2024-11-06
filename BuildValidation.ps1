function Get-RemoteRegistryValue {
    param (
        [string]$vmName,           # Remote computer name
        [string]$registryPath,     # Registry path
        [string]$registryValue     # Registry value name
    )
    Write-Host "Checking path $registryPath and $registryValue"

    # Invoke-Command to get the registry value from a remote computer
    $result = Invoke-Command -ComputerName $vmName -ScriptBlock {
        param ($remoteRegistryPath, $remoteRegistryValue)

        try {
            $regValue = Get-ItemProperty -Path $remoteRegistryPath -Name $remoteRegistryValue -ErrorAction Stop
            return @(
                @{
                    Status = "PASS"
                    Value  = $regValue.$remoteRegistryValue
                }
            )
        }
        catch {
            return @(
                @{
                    Status = "FAIL"
                    Value  = "Not Found"
                }
            )
        }
    } -ArgumentList $registryPath, $registryValue -ErrorAction SilentlyContinue

    return $result
}

# Function to check if a specific Windows feature is installed on a remote machine
function Check-WindowsFeature {
    param (
        [string]$vmName,           # Remote computer name
        [string]$featureName       # Windows feature name to check
    )

    $result = Invoke-Command -ComputerName $vmName -ScriptBlock {
        param (
            [string]$remoteFeatureName
        )

        try {
            $feature = Get-WindowsFeature -Name $remoteFeatureName
            if ($feature.Installed) {
                return @{
                    Status = "PASS"
                    Value  = "$remoteFeatureName is Installed"
                }
            }
            else {
                return @{
                    Status = "FAIL"
                    Value  = "$remoteFeatureName is Not Installed"
                }
            }
        }
        catch {
            return @{
                Status = "FAIL"
                Value  = "Error: Unable to retrieve feature status"
            }
        }
    } -ArgumentList $featureName -ErrorAction SilentlyContinue

    return $result
}

# Get Remote Volume
function Get-RemoteVolumeName {
    param (
        [string]$vmName,         # The name of the remote VM
        [char]$driveLetter       # The drive letter to check (e.g., C)
    )

    $volumeName = Invoke-Command -ComputerName $vmName -ScriptBlock {
        param ($remoteDriveLetter)

        try {
            $drive = Get-Volume -DriveLetter $remoteDriveLetter

            if ($drive -and $drive.FileSystemLabel) {
                return @{
                    Status = "PASS"
                    Value = $drive.FileSystemLabel
                }
            }
            else {
                Status = "FAIL"
                Value = "Drive $remoteDriveLetter does not exist on $vmName."
            }
        }
        catch {
            return @{
                Status = "FAIL"
                Value = "Failed to retrieve ${remoteDriveLetter}: drive information: $_"
            }
        }
    } -ArgumentList $driveLetter -ErrorAction Stop -ErrorVariable remoteError

    return $volumeName
}


function Get-RemotePrintSpoolerStatus {
    param (
        [string]$vmName
    )

    $result = Invoke-Command -ComputerName $vmName -ScriptBlock {

        try {
            $printSpoolerStatus = (Get-WmiObject -Class Win32_Service -Filter "Name='Spooler'").StartMode
            if ($printSpoolerStatus -eq "Disabled"){
                return @(
                    @{
                        Status = "PASS"
                        Value  = $printSpoolerStatus
                    }
                )
            }
            else {
                throw "Could not retrieve print spooler status."
            }
        }
        catch {
            return @(
                @{
                    Status = "FAIL"
                    Value  = "Failed to retrieve print spooler status: $_"
                }
            )
        }
    } -ErrorAction SilentlyContinue

    return $result
}

function Get-TcpAutoTuningLevelStatus {
    param (
        [string]$vmName
    )

    $result = Invoke-Command -ComputerName $vmName -ScriptBlock {

        try {
            $tcpGlobalSettings = netsh interface tcp show global
            $autoTuningLevel = $tcpGlobalSettings | Select-String -Pattern 'Receive Window Auto-Tuning Level' | ForEach-Object {
                $_.Line -replace '^.*Receive Window Auto-Tuning Level\s*:\s*', ''
            }
            $autoTuningLevel = $autoTuningLevel.Trim()

            if ($autoTuningLevel -eq "disabled"){
                return @(
                    @{
                        Status = "PASS"
                        Value  = $autoTuningLevel
                    }
                )
            }
            else {
                return @{
                    Status = "FAIL"
                    Value  = "Auto Tuning Level set to: $autoTuningLevel"
                }
            }
        }
        catch {
            return @(
                @{
                    Status = "FAIL"
                    Value  = "Failed to retrieve TCP Auto Tuning Level: $_"
                }
            )
        }
    } -ErrorAction SilentlyContinue

    return $result
}

function Get-TcpEcnCapabilityStatus {
    param (
        [string]$vmName
    )

    $result = Invoke-Command -ComputerName $vmName -ScriptBlock {

        try {
            $tcpGlobalSettings = netsh interface tcp show global
            $tcpEcnCapability = $tcpGlobalSettings | Select-String -Pattern 'ECN Capability' | ForEach-Object {
                $_.Line -replace '^.*ECN Capability\s*:\s*', ''
            }
            $tcpEcnCapability = $tcpEcnCapability.Trim()

            if ($tcpEcnCapability -eq "disabled"){
                return @(
                    @{
                        Status = "PASS"
                        Value  = $tcpEcnCapability
                    }
                )
            }
            else {
                return @{
                    Status = "FAIL"
                    Value  = "ECN Capability set to: $tcpEcnCapability"
                }
            }
        }
        catch {
            return @(
                @{
                    Status = "FAIL"
                    Value  = "Failed to retrieve ECN Capability: $_"
                }
            )
        }
    } -ErrorAction SilentlyContinue

    return $result
}

function Get-TcpRscStatus {
    param (
        [string]$vmName
    )

    $result = Invoke-Command -ComputerName $vmName -ScriptBlock {

        try {
            $tcpGlobalSettings = netsh interface tcp show global
            $tcpRscStatus = $tcpGlobalSettings | Select-String -Pattern 'Receive Segment Coalescing State' | ForEach-Object {
                $_.Line -replace '^.*Receive Segment Coalescing State\s*:\s*', ''
            }
            $tcpRscStatus = $tcpRscStatus.Trim()

            if ($tcpRscStatus -eq "disabled"){
                return @(
                    @{
                        Status = "PASS"
                        Value  = $tcpRscStatus
                    }
                )
            }
            else {
                Write-Host "FAIL"
                return @{
                    Status = "FAIL"
                    Value  = "ECN Capability set to: $tcpRscStatus"
                }
            }
        }
        catch {
            return @(
                @{
                    Status = "FAIL"
                    Value  = "Failed to retrieve ECN Capability: $_"
                }
            )
        }
    } -ErrorAction SilentlyContinue

    return $result
}

function Get-NetAdapterAdvancedProperty {
    param (
        [string]$vmName,
        [string]$propertyName
    )

    Write-Host "$propertyName"
    $result = Invoke-Command -ComputerName $vmName -ScriptBlock {
        param($localPropertyName)

        try {
            $advancedPropertyValue = (Get-NetAdapterAdvancedProperty -Name * | Where-Object { $_.DisplayName -eq $localPropertyName }).DisplayValue

            Write-Host "$advancedPropertyValue"
            return @{
                Status = "PASS"
                Value = $advancedPropertyValue
                }
        }
        catch {

            return @{
                Status = "FAIL"
                Value = "Could not retrienve Net Adapter Advanced Property $propertyName"
                }
        }

    } -ArgumentList $propertyName -ErrorAction SilentlyContinue

    return $result
}

function Get-NetAdapterBindingProperty {
    param (
        [string]$vmName,
        [string]$propertyName
    )

    Write-Host "$propertyName"
    $result = Invoke-Command -ComputerName $vmName -ScriptBlock {
        param($localPropertyName)

        try {
            $bindingPropertyValue = (Get-NetAdapterBinding -Name * | Where-Object { $_.DisplayName -eq $localPropertyName }).Enabled

            Write-Host $bindingPropertyValue

            return @(
                @{
                Status = "PASS"
                Value = $bindingPropertyValue
                }
            )
        }
        catch {
            return @(
                @{
                Status = "FAIL"
                Value = "Could not retrieve Net Adapter Binding Property $localPropertyName"
                }
            )
        }

    } -ArgumentList $propertyName -ErrorAction SilentlyContinue

    return $result
}

function Get-RemoteAdMachineGroupStatus {
    param (
        [string]$vmName,
        [string]$adMachineGroupName
    )

    Write-Host "Checking if VM $vmName is a member of group $adMachineGroupName"

    try {
        $computer = Get-ADComputer -Identity $vmName -Properties MemberOf

        if ($computer.MemberOf -contains (Get-ADGroup -Identity $adMachineGroupName).DistinguishedName) {
            Write-Host "VM $vmName is a member of group $adMachineGroupName"
            return @{
                Status = "PASS"
                Value  = $adMachineGroupName
            }
        } else {
            Write-Host "VM $vmName is NOT a member of group $adMachineGroupName"
            return @{
                Status = "FAIL"
                Value  = "Could not find $vmName in Machine Group $adMachineGroupName"
            }
        }
    }
    catch {
        Write-Host "Error during AD group membership check: $_"
        return @{
            Status = "FAIL"
            Value  = "Error occurred: $_"
        }
    }
}

function Get-AccessToken {
    param (
        [string]$baseApiUrl
    )

    Write-Host "Obtaining API access token"
    Write-Host "Base URL set to $baseApiUrl"

    $tokenFilePath = "C:\vRA\api_token.txt"
    if (Test-Path $tokenFilePath) {
        Write-Host "Loading API token from file"
        try {
            $api_token = Get-Content -Path $tokenFilePath -Raw
            $api_token = $api_token.Trim()
        }
        catch {
            Write-Host "Error reading API token from file: $_"
            return
        }
    } else {
        Write-Host "Token file not found at path: $tokenFilePath"
        return
    }

    # Bypass SSL certificate validation
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

    $headers = @{
        'Content-Type' = 'application/json'
        'Accept' = 'application/json'
    }
    
    $body = @{
        refreshToken = $api_token
    } | ConvertTo-Json

    try {
        $response = Invoke-RestMethod -Method Post -Uri "$baseApiUrl/iaas/api/login" -Headers $headers -Body $body
        $accessToken = $response.token
        Write-Host "Access Token: $accessToken"
        return $accessToken
    }
    catch {
        Write-Host "Error getting access token: $_"
    }
}


function Get-UserInputData {
    param (
        [string]$vmName,
        [string]$accessToken
    )

    $headers = @{
        'accept' = 'application/json'
        'Authorization' = "Bearer $accessToken"
    }

    $uri = "$baseApiUrl/deployment/api/deployments?page=0&size=100&search=$vmName&deleted=false&%24top=100&%24skip=0"
    try {
        $userInputData = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers

        $userInputData |ConvertTo-Json

        return $userInputData
    }
    catch {
        Write-Host "Error getting user input: $_"
    }

}

function Get-RemoteDriveSize {
    param (
        [string]$vmName,
        [string]$driveLetter
    )

    try {
        # Use ${} to properly reference the variable within the string
        $drive = Get-CimInstance -ComputerName $vmName -ClassName Win32_LogicalDisk -Filter "DeviceID = '${driveLetter}:'"

        if ($drive) {
            # If the drive exists, return the size in GB
            $sizeGB = [math]::round($drive.Size / 1GB, 2)
            return "Drive $driveLetter exists on $vmName with a size of $sizeGB GB."
        } else {
            return "Drive $driveLetter does not exist on $vmName."
        }
    } catch {
        return "Error connecting to $vmName or retrieving drive information: $_"
    }
}

# Function to add a single row to HTML table data
function Add-ReportTableData {
    param (
        [string]$color,           # Color for the status text
        [string]$status,
        [string]$title,
        [string]$desc,
        [string]$expected,
        [string]$value
    )

    # Ensure $htmlTableData is global so it accumulates data correctly
    $script:htmlTableData += @"
            <tr>
                <td><span style='color:$color;'>$status</span></td>
                <td>$title</td>
                <td>$desc</td>
                <td>$expected</td>
                <td>$value</td>  
            </tr>
"@

    # No need to return the value as it's accumulating globally
}

#######################################################################################################
########################################### START OF PROGRAM ##########################################
#######################################################################################################

$defaultServer = "POCBFAUTOQA2"

$vmName = Read-Host -Prompt "Enter the name of the VM to QA (default: $defaultServer): "

if ([string]::IsNullOrEmpty($vmName)) {
    $vmName = $defaultServer
}

#$vmName = "POCBFAUTOQA2"
Write-Host "Running validation for $vmName"

Write-Host "Setting base URL for API calls"
$baseApiUrl = '<YourARIAAutomationServerHere>'
Write-Host "Base URL for API calls set to: $baseApiUrl"

# Define the path where the HTML file will be saved
$outputFilePath = "C:\vra"

# Create directory if it doesn't exist
if (-not (Test-Path "$outputFilePath")) {
    Try {
        New-Item -Path "$outputFilePath" -ItemType Directory -Force
        Write-Host "Report output directory created at $outputFilePath"
    }
    Catch {
        Write-Host "Error: Failed to create report output directory at $outputFilePath. Error details: $_" -ForegroundColor Red
    }
} else {
    Write-Host "Output directory already exists at $outputFilePath"
}


$outputFileName = "VMValidation_$vmName.html"

$outputFile = $outputFilePath + "/" + $outputFileName
$date = Get-Date

# Initialize $htmlTableData as an empty string before adding rows
$htmlTableData = ""

$htmlHeader = @"
<html>
<head>
    <style>
        table { border-collapse: collapse; width: 75%; }
        table, th, td { border: 1px solid black; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .pass { color: green; }
        .fail { color: red; }
    </style>
</head>
<body>
    <h1>Validation of VM: $vmName</h1>
    <h2>Validation run on: $date</h2>
    <table>
        <tr>
            <th>Status</th>
            <th>Title</th>
            <th>Description</th>
            <th>Expected Value</th>
            <th>Value</th>
        </tr>
"@

$htmlFooter = @"
</table>
    </body>
    </html>
"@

#######################################################################################################
############################## START CONFIGIURATION CHECKS ############################################
#######################################################################################################

#################################### Service Now Integration ##########################################

Write-Host "Checking Service Now Integration"

# Set variables for Service Now module import
$serviceNowSerialNumberTitle = "Service Now Serial Number Check"
$serviceNowSerialNumberPath = "HKLM:\Software\MCD"
$serviceNowSerialNumberPathValue = "SerialNumber"
$serviceNowSerialNumberDesc = "The value auto-generated during deployment that is used in ServiceNow to identify this VM"
$serviceNowSerialNumberExpected = "A random serial number generated by Service Now."

# Retrieve Service Now module registry values
Write-Host "Getting Service Now $serviceNowSerialNumberPathValue"
$serviceNowSerialNumberResult = Get-RemoteRegistryValue -vmName $vmName -registryPath $serviceNowSerialNumberPath -registryValue $serviceNowSerialNumberPathValue
Write-Host "Service Now Serial Number result status $($serviceNowSerialNumberResult.Status)"
Write-Host "Service Now Serial Number $($serviceNowSerialNumberResult.Value)"
$serviceNowSerialNumberColor = if ($serviceNowSerialNumberResult.Status -eq "PASS") { "green" } else { "red" }
# Add row to the HTML table data
Add-ReportTableData -color $serviceNowSerialNumberColor -status $($serviceNowSerialNumberResult.Status) -title $serviceNowSerialNumberTitle -desc $serviceNowSerialNumberDesc -expected $serviceNowSerialNumberExpected -value $($serviceNowSerialNumberResult.Value)

# Set variables for Service Now module import
$serviceNowSystemModelTitle = "Service Now System Model Check"
$serviceNowSystemModelPath = "HKLM:\Software\MCD"
$serviceNowSystemModelValue = "SystemModel"
$serviceNowSystemModelDesc = "The field that returns the validation that this is a VMware virtual machine"
$serviceNowSystemModelExpected = "VMware Virtual Platform."

# Retrieve Service Now module registry values
Write-Host "Getting Service Now $serviceNowSystemModelValue"
$serviceNowSystemModelResult = Get-RemoteRegistryValue -vmName $vmName -registryPath $serviceNowSystemModelPath -registryValue $serviceNowSystemModelValue
Write-Host "Service Now System Model result status $($serviceNowSystemModelResult.Status)"
Write-Host "Service Now System Model $($serviceNowSystemModelResult.Value)"
$serviceNowSystemModelColor = if ($serviceNowSystemModelResult.Status -eq "PASS") { "green" } else { "red" }
# Add row to the HTML table data
Add-ReportTableData -color $serviceNowSystemModelColor -status $($serviceNowSystemModelResult.Status) -title $serviceNowSystemModelTitle -desc $serviceNowSystemModelDesc -expected $serviceNowSystemModelExpected -value $($serviceNowSystemModelResult.Value)

################################# Check Local Machine Execution Policy #####################################

# Set varibales for Local Machine Execution Policy
$localMachineExecutionPolicyTitle = "Local Machine Execution Policy"
$localMachineExecutionPolicyPath = "HKLM:\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell"
$localMachineExecutionPolicyValue = "ExecutionPolicy"
$localMachineExecutionPolicyDesc = "The local machine execution policy for PowerShell."
$localMachineExecutionPolicyExpected = "Remote Signed"

# Retrieve Local Machine Execution Policy
Write-Host "Getting $localMachineExecutionPolicyValue"
$localMachineExecutionPolicyResult = Get-RemoteRegistryValue -vmName $vmName -registryPath $localMachineExecutionPolicyPath -registryValue $localMachineExecutionPolicyValue
Write-Host "Local Machine Execution Policy result status $($localMachineExecutionPolicyResult.Status)"
Write-Host "Local Machine Execution Policy $($localMachineExecutionPolicyResult.Value)"

# Check if ExecutionPolicy is 'RemoteSigned'
if ($localMachineExecutionPolicyResult.Value -eq 'RemoteSigned') {
    $localMachineExecutionPolicyResult.Status = "PASS"
} else {
    $localMachineExecutionPolicyResult.Status = "FAIL"
}
$localMachineExecutionPolicyColor = if ($localMachineExecutionPolicyResult.Status -eq "PASS") { "green" } else { "red" }
# Add row to the HTML table data
Add-ReportTableData -color $localMachineExecutionPolicyColor -status $($localMachineExecutionPolicyResult.Status) -title $localMachineExecutionPolicyTitle -desc $localMachineExecutionPolicyDesc -expected $localMachineExecutionPolicyExpected -value $($localMachineExecutionPolicyResult.Value)

#######################################################################################################
######################################## Windows Feature Check ########################################
#######################################################################################################

# Check if SNMP-Service feature is installed
$featureName = "SNMP-Service"
Write-Host "Checking for Windows Feature $featureName"
$snmpFeatureResult = Check-WindowsFeature -vmName $vmName -featureName $featureName
$snmpFeatureTitle = "SNMP Service"
$snmpFeatureDesc = "Checks if Windows Feature $featureName is installed"
$snmpFeatureExpected = "Installed"
Write-Host "Windows Feature result status $($snmpFeatureResult.Status)"
Write-Host "Windows Feature $($snmpFeatureResult.Value)"
$snmpFeatureColor = if ($snmpFeatureResult.Status -eq "PASS") { "green" } else { "red" }
# Add row to the HTML table data
Add-ReportTableData -color $snmpFeatureColor -status $($snmpFeatureResult.Status) -title $snmpFeatureTitle -desc $snmpFeatureDesc -expected $snmpFeatureExpected -value $($snmpFeatureResult.Value)


# Check if RSAT-SNMP feature is installed
$featureName = "RSAT-SNMP"
Write-Host "Checking for Windows Feature $featureName"
$rsatSnmpFeatureResult = Check-WindowsFeature -vmName $vmName -featureName $featureName
$rsatSnmpFeatureTitle = "RSAT-SNMP Service"
$rsatSnmpFeatureDesc = "Checks if Windows Feature $featureName is installed"
$rsatSnmpFeatureExpected = "Installed"
Write-Host "Windows Feature result status $($rsatSnmpFeatureResult.Status)"
Write-Host "Windows Feature $($rsatSnmpFeatureResult.Value)"
$rsatSnmpFeatureColor = if ($rsatSnmpFeatureResult.Status -eq "PASS") { "green" } else { "red" }
# Add row to the HTML table data
Add-ReportTableData -color $rsatSnmpFeatureColor -status $($rsatSnmpFeatureResult.Status) -title $rsatSnmpFeatureTitle -desc $rsatSnmpFeatureDesc -expected $rsatSnmpFeatureExpected -value $($rsatSnmpFeatureResult.Value)

# Check if RSAT-ADDS-Tools feature is installed
$featureName = "RSAT-ADDS-Tools"
Write-Host "Checking for Windows Feature $featureName"
$rsatAddsToolsResult = Check-WindowsFeature -vmName $vmName -featureName $featureName
$rsatAddsToolsTitle = "RSAT-ADDS-Tools"
$rsatAddsToolsDesc = "Checks if RSAT-ADDS-Tools feature installed"
$rsatAddsToolsExpected = "Installed"
Write-Host "Windows Feature result status $($rsatAddsToolsResult.Status)"
Write-Host "Windows Feature $($rsatAddsToolsResult.Value)"
$rsatAddsToolsColor = if ($rsatAddsToolsResult.Status -eq "PASS") { "green" } else { "red" }
# Add row to the HTML table data
Add-ReportTableData -color $rsatAddsToolsColor -status $($rsatAddsToolsResult.Status) -title $rsatAddsToolsTitle -desc $rsatAddsToolsDesc -expected $rsatAddsToolsExpected -value $($rsatAddsToolsResult.Value)

# Check SNMP settings in regsitry
$enableAuthenticationTrapsTitle = "SNMP Traps"
$enableAuthenticationTrapsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters"
$enableAuthenticationTrapsValue = "EnableAuthenticationTraps"
$enableAuthenticationTrapsDesc = "SNMP registry setting for authentication traps"
$enableAuthenticationTrapsExpected = "1"
$enableAuthenticationTrapsResult = Get-RemoteRegistryValue -vmName $vmName -registryPath $enableAuthenticationTrapsPath -registryValue $enableAuthenticationTrapsValue
$enableAuthenticationTrapsColor = if ($enableAuthenticationTrapsResult.Status -eq "PASS") { "green" } else { "red" }

if ($enableAuthenticationTrapsResult.Value -eq '1') {
    $enableAuthenticationTrapsResult.Status = "PASS"
} else {
    $enableAuthenticationTrapsResult.Status = "FAIL"
}
# Add row to the HTML table data
Add-ReportTableData -color $enableAuthenticationTrapsColor -status $($enableAuthenticationTrapsResult.Status) -title $enableAuthenticationTrapsTitle -desc $enableAuthenticationTrapsDesc -expected $enableAuthenticationTrapsExpected -value $($enableAuthenticationTrapsResult.Value)

$nameResolutionRetriesTitle = "SNMP Name Resolution Retries"
$nameResolutionRetriesPath = "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters"
$nameResolutionRetriesValue = "NameResolutionRetries"
$nameResolutionRetriesDesc = "SNMP registry setting for Name Resolution Retries"
$nameResolutionRetriesExpected = "16"
$nameResolutionRetriesResult = Get-RemoteRegistryValue -vmName $vmName -registryPath $nameResolutionRetriesPath -registryValue $nameResolutionRetriesValue
$nameResolutionRetriesColor = if ($nameResolutionRetriesResult.Status -eq "PASS") { "green" } else { "red" }
if ($nameResolutionRetriesResult.Value -eq '16') {
    $nameResolutionRetriesResult.Status = "PASS"
} else {
    $nameResolutionRetriesResult.Status = "FAIL"
}
# Add row to the HTML table data
Add-ReportTableData -color $nameResolutionRetriesColor -status $($nameResolutionRetriesResult.Status) -title $nameResolutionRetriesTitle -desc $nameResolutionRetriesDesc -expected $nameResolutionRetriesExpected -value $($nameResolutionRetriesResult.Value)

$sysContactTitle = "RFC1156 Agent Contact Info"
$sysContactPath = "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\RFC1156Agent"
$sysContactValue = "sysContact"
$sysContactDesc = "RFC1156 Agent Contact Info"
$sysContactExpected = "ISIS Server Group"
$sysContactResult = Get-RemoteRegistryValue -vmName $vmName -registryPath $sysContactPath -registryValue $sysContactValue
$sysContactColor = if ($nameResolutionRetriesResult.Status -eq "PASS") { "green" } else { "red" }
if ($sysContactResult.Value -eq 'ISIS Server Group') {
    $sysContactResult.Status = "PASS"
} else {
    $sysContactResult.Status = "FAIL"
}
# Add row to the HTML table data
Add-ReportTableData -color $sysContactColor -status $($sysContactResult.Status) -title $sysContactTitle -desc $sysContactDesc -expected $sysContactExpected -value $($sysContactResult.Value)

$sysLocationTitle = "RFC1156 Agent System Location"
$sysLocationPath = "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\RFC1156Agent"
$sysLocationValue = "sysLocation"
$sysLocationDesc = "RFC1156 Agent System Location"
$sysLocationExpected = "Site Server Room"
$sysLocationResult = Get-RemoteRegistryValue -vmName $vmName -registryPath $sysLocationPath -registryValue $sysLocationValue
$sysLocationColor = if ($sysLocationResult.Status -eq "PASS") { "green" } else { "red" }
if ($sysLocationResult.Value -eq 'Site Server Room') {
    $sysLocationResult.Status = "PASS"
} else {
    $sysLocationResult.Status = "FAIL"
}
# Add row to the HTML table data
Add-ReportTableData -color $sysLocationColor -status $($sysLocationResult.Status) -title $sysLocationTitle -desc $sysLocationDesc -expected $sysLocationExpected -value $($sysLocationResult.Value)

$trapConfig1Title = "SNMP Trap 1"
$trapConfig1Path = "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\TrapConfiguration\control"
$trapConfig1Value = "1"
$trapConfig1Desc = "SNMP Trap 1 Configuration"
$trapConfig1Expected = "10.51.32.222 OR 10.35.5.222"
$trapConfig1Result = Get-RemoteRegistryValue -vmName $vmName -registryPath $trapConfig1Path -registryValue $trapConfig1Value
$trapConfig1Color = if ($trapConfig1Result.Status -eq "PASS") { "green" } else { "red" }
if ($trapConfig1Result.Value -eq '10.51.32.222' -or $trapConfig1Result.Value -eq '10.35.5.222') {
    $trapConfig1Result.Status = "PASS"
} else {
    $trapConfig1Result.Status = "FAIL"
}
# Add row to the HTML table data
Add-ReportTableData -color $trapConfig1Color -status $($trapConfig1Result.Status) -title $trapConfig1Title -desc $trapConfig1Desc -expected $trapConfig1Expected -value $($trapConfig1Result.Value)

$trapConfig2Title = "SNMP Trap 2"
$trapConfig2Path = "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\TrapConfiguration\control"
$trapConfig2Value = "2"
$trapConfig2Desc = "SNMP Trap 2 Configuration"
$trapConfig2Expected = "10.51.32.222 OR 10.35.5.222"
$trapConfig2Result = Get-RemoteRegistryValue -vmName $vmName -registryPath $trapConfig2Path -registryValue $trapConfig2Value
$trapConfig2Color = if ($trapConfig2Result.Status -eq "PASS") { "green" } else { "red" }
if ($trapConfig2Result.Value -eq '10.51.32.222' -or $trapConfig2Result.Value -eq '10.35.5.222') {
    $trapConfig2Result.Status = "PASS"
} else {
    $trapConfig2Result.Status = "FAIL"
}
# Add row to the HTML table data
Add-ReportTableData -color $trapConfig2Color -status $($trapConfig2Result.Status) -title $trapConfig2Title -desc $trapConfig2Desc -expected $trapConfig2Expected -value $($trapConfig2Result.Value)

# SNMP Permitted Managers
$permittedManagers1Title = "SNMP Permitted Managers"
$permittedManagers1Path = "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers"
$permittedManagers1Value = "1"
$permittedManagers1Desc = "SNMP Permitted Managers 1"
$permittedManagers1Expected = "10.35.5.222 OR 10.35.32.25 OR 10.51.4.92 OR 10.51.32.222"
$permittedManagers1Result = Get-RemoteRegistryValue -vmName $vmName -registryPath $permittedManagers1Path -registryValue $permittedManagers1Value
$permittedManagers1Color = if ($permittedManagers1Result.Status -eq "PASS") { "green" } else { "red" }
if ($permittedManagers1Result.Value -eq '10.35.5.222' -or $permittedManagers1Result.Value -eq '10.35.32.25' -or $permittedManagers1Result.Value -eq '10.51.4.92' -or $permittedManagers1Result.Value -eq '10.51.32.222') {
    $permittedManagers1Result.Status = "PASS"
} else {
    $permittedManagers1Result.Status = "FAIL"
}
# Add row to the HTML table data
Add-ReportTableData -color $permittedManagers1Color -status $($permittedManagers1Result.Status) -title $permittedManagers1Title -desc $permittedManagers1Desc -expected $permittedManagers1Expected -value $($permittedManagers1Result.Value)

# SNMP Permitted Managers
$permittedManagers2Title = "SNMP Permitted Managers"
$permittedManagers2Path = "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers"
$permittedManagers2Value = "2"
$permittedManagers2Desc = "SNMP Permitted Managers 2"
$permittedManagers2Expected = "10.35.5.222 OR 10.35.32.25 OR 10.51.4.92 OR 10.51.32.222"
$permittedManagers2Result = Get-RemoteRegistryValue -vmName $vmName -registryPath $permittedManagers2Path -registryValue $permittedManagers2Value
$permittedManagers2Color = if ($permittedManagers2Result.Status -eq "PASS") { "green" } else { "red" }
if ($permittedManagers2Result.Value -eq '10.35.5.222' -or $permittedManagers2Result.Value -eq '10.35.32.25' -or $permittedManagers2Result.Value -eq '10.51.4.92' -or $permittedManagers2Result.Value -eq '10.51.32.222') {
    $permittedManagers2Result.Status = "PASS"
} else {
    $permittedManagers2Result.Status = "FAIL"
}
# Add row to the HTML table data
Add-ReportTableData -color $permittedManagers2Color -status $($permittedManagers2Result.Status) -title $permittedManagers2Title -desc $permittedManagers2Desc -expected $permittedManagers2Expected -value $($permittedManagers2Result.Value)

# SNMP Permitted Managers
$permittedManagers3Title = "SNMP Permitted Managers"
$permittedManagers3Path = "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers"
$permittedManagers3Value = "3"
$permittedManagers3Desc = "SNMP Permitted Managers 3"
$permittedManagers3Expected = "10.35.5.222 OR 10.35.32.25 OR 10.51.4.92 OR 10.51.32.222"
$permittedManagers3Result = Get-RemoteRegistryValue -vmName $vmName -registryPath $permittedManagers3Path -registryValue $permittedManagers3Value
$permittedManagers3Color = if ($permittedManagers3Result.Status -eq "PASS") { "green" } else { "red" }
if ($permittedManagers3Result.Value -eq '10.35.5.222' -or $permittedManagers3Result.Value -eq '10.35.32.25' -or $permittedManagers3Result.Value -eq '10.51.4.92' -or $permittedManagers3Result.Value -eq '10.51.32.222') {
    $permittedManagers3Result.Status = "PASS"
} else {
    $permittedManagers3Result.Status = "FAIL"
}
# Add row to the HTML table data
Add-ReportTableData -color $permittedManagers3Color -status $($permittedManagers3Result.Status) -title $permittedManagers3Title -desc $permittedManagers3Desc -expected $permittedManagers3Expected -value $($permittedManagers3Result.Value)

# SNMP Permitted Managers
$permittedManagers4Title = "SNMP Permitted Managers"
$permittedManagers4Path = "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers"
$permittedManagers4Value = "4"
$permittedManagers4Desc = "SNMP Permitted Managers 4"
$permittedManagers4Expected = "10.35.5.222 OR 10.35.32.25 OR 10.51.4.92 OR 10.51.32.222"
$permittedManagers4Result = Get-RemoteRegistryValue -vmName $vmName -registryPath $permittedManagers4Path -registryValue $permittedManagers4Value
$permittedManagers4Color = if ($permittedManagers4Result.Status -eq "PASS") { "green" } else { "red" }
if ($permittedManagers4Result.Value -eq '10.35.5.222' -or $permittedManagers4Result.Value -eq '10.35.32.25' -or $permittedManagers4Result.Value -eq '10.51.4.92' -or $permittedManagers4Result.Value -eq '10.51.32.222') {
    $permittedManagers4Result.Status = "PASS"
} else {
    $permittedManagers4Result.Status = "FAIL"
}
# Add row to the HTML table data
Add-ReportTableData -color $permittedManagers4Color -status $($permittedManagers4Result.Status) -title $permittedManagers4Title -desc $permittedManagers4Desc -expected $permittedManagers4Expected -value $($permittedManagers4Result.Value)

# Check to see if we renamed the root volume
$rootVolumeNameTitle = "C: Drive Renamed"
$rootVolumeNameResult = Get-RemoteVolumeName -vmName $vmName -driveLetter "C"
$rootVolumeNameDesc = "Check that the C: drive got renamed to the hostname"
$rootVolumeNameExpected = "$vmName"
if ($rootVolumeNameResult.Value -eq $vmName) {
    $rootVolumeNameResult.Status = "PASS"
} else {
    $rootVolumeName.Status = "FAIL"
}
$rootVolumeNameColor = if ($rootVolumeNameResult.Status -eq "PASS") { "green" } else { "red" }
# Add row to the HTML table data
Add-ReportTableData -color $rootVolumeNameColor -status $($rootVolumeNameResult.Status) -title $rootVolumeNameTitle -desc $rootVolumeNameDesc -expected $rootVolumeNameExpected -value $($rootVolumeNameResult.Value)

# Check Print Spooler Status
$printSpoolerStatusTitle = "Print Spooler Status"
$printSpoolerStatusResult = Get-RemotePrintSpoolerStatus -vmName $vmName
$printSpoolerStatusDesc = "Check to make sure the spooler service is Disabled"
$printSpoolerStatusExpected = "Disabled"
if ($printSpoolerStatusResult.Value -eq "Disabled") {
    $printSpoolerStatusResult.Status = "PASS"
} else {
    $printSpoolerStatusResult.Status = "FAIL"
}
$printSpoolerStatusColor = if ($printSpoolerStatusResult.Status -eq "PASS") { "green" } else { "red" }
# Add row to the HTML table data
Add-ReportTableData -color $printSpoolerStatusColor -status $($printSpoolerStatusResult.Status) -title $printSpoolerStatusTitle -desc $printSpoolerStatusDesc -expected $printSpoolerStatusExpected -value $($printSpoolerStatusResult.Value)

#######################################################################################################
################################### Net Adapter / TCP Specific Checks #################################
#######################################################################################################

$tcpip6paramsTitle = "TCP IP 6 Disabled Components"
$tcpip6paramsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
$tcpip6paramsValue = "DisabledComponents"
$tcpip6paramsDesc = "TCP IP 6 Disabled Components reg value set to 255 (0xFF)"
$tcpip6paramsExpected = "255 (0xFF)"
$tcpip6paramsResult = Get-RemoteRegistryValue -vmName $vmName -registryPath $tcpip6paramsPath -registryValue $tcpip6paramsValue

if ($tcpip6paramsResult.Value -eq '255') {
    $tcpip6paramsResult.Status = "PASS"
} else {
    $tcpip6paramsResult.Status = "FAIL"
}
$tcpip6paramsColor = if ($tcpip6paramsResult.Status -eq "PASS") { "green" } else { "red" }
# Add row to the HTML table data
Add-ReportTableData -color $tcpip6paramsColor -status $($tcpip6paramsResult.Status) -title $tcpip6paramsTitle -desc $tcpip6paramsDesc -expected $tcpip6paramsExpected -value $($tcpip6paramsResult.Value)


$tcpAutoTuningLevelStatusTitle = "TCP Auto Tuning Level"
$tcpAutoTuningLevelStatusExpected = 'disabled'
$tcpAutoTuningLevelStatusResult = Get-TcpAutoTuningLevelStatus -vmName $vmName
$tcpAutoTuningLevelStatusDesc = "Checks to make sure the Recieve Window Auto-Tuning Level Param is disabled."
if ($tcpAutoTuningLevelStatusResult.Value -eq "disabled") {
    $tcpAutoTuningLevelStatusResult.Status = "PASS"
} else {
    $tcpAutoTuningLevelStatusResult.Status = "FAIL"
}
$tcpAutoTuningLevelStatusColor = if ($tcpAutoTuningLevelStatusResult.Status -eq "PASS") { "green" } else { "red" }
# Add row to the HTML table data
Add-ReportTableData -color $tcpAutoTuningLevelStatusColor -status $($tcpAutoTuningLevelStatusResult.Status) -title $tcpAutoTuningLevelStatusTitle -desc $tcpAutoTuningLevelStatusDesc -expected $tcpAutoTuningLevelStatusExpected -value $($tcpAutoTuningLevelStatusResult.Value)


$tcpEcnCapabilityStatusTitle = "TCP ECN Capability"
$tcpEcnCapabilityStatusExpected = 'disabled'
$tcpEcnCapabilityStatusResult = Get-TcpEcnCapabilityStatus -vmName $vmName
$tcpEcnCapabilityStatusDesc = "Checks to ensure that Explicit Congestion Notification (ECN) capability is disabled."
if ($tcpEcnCapabilityStatusResult.Value -eq "disabled") {
    $tcpEcnCapabilityStatusResult.Status = "PASS"
} else {
    $tcpEcnCapabilityStatusResult.Status = "FAIL"
}
$tcpEcnCapabilityStatusColor = if ($tcpEcnCapabilityStatusResult.Status -eq "PASS") { "green" } else { "red" }
# Add row to the HTML table data
Add-ReportTableData -color $tcpEcnCapabilityStatusColor -status $($tcpEcnCapabilityStatusResult.Status) -title $tcpEcnCapabilityStatusTitle -desc $tcpEcnCapabilityStatusDesc -expected $tcpEcnCapabilityStatusExpected -value $($tcpEcnCapabilityStatusResult.Value)

$tcpRscStatusTitle = "TCP RSC (Receive Segment Coalescing) Status"
$tcpRscStatusExpected = 'disabled'
$tcpRscStatusResult = Get-TcpRscStatus -vmName $vmName
$tcpRscStatusDesc = "Checks to ensure that Receive Segment Coalescing (RSC) is disabled."
if ($tcpRscStatusResult.Value -eq "disabled") {
    $tcpRscStatusResult.Status = "PASS"
} else {
    $tcpRscStatusResult.Status = "FAIL"
}
$tcpRscStatusColor = if ($tcpRscStatusResult.Status -eq "PASS") { "green" } else { "red" }
# Add row to the HTML table data
Add-ReportTableData -color $tcpRscStatusColor -status $($tcpRscStatusResult.Status) -title $tcpRscStatusTitle -desc $tcpRscStatusDesc -expected $tcpRscStatusExpected -value $($tcpRscStatusResult.Value)

$smbServerNameHardeningTitle = "SMB Server Name Hardening Policy Check"
$smbServerNameHardeningExpected = "0"
$smbServerNameHardeningPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
$smbServerNameHardeningValue = "SmbServerNameHardeningLevel"
$smbServerNameHardeningDesc = "Checks if the SMB Server Name Hardening Policy is disabled. The expected registry value is 1, which corresponds to the 'Enabled' state."

# Retrieve registry values
$smbServerNameHardeningResult = Get-RemoteRegistryValue -vmName $vmName -registryPath $smbServerNameHardeningPath -registryValue $smbServerNameHardeningValue
if ($smbServerNameHardeningResult.Value -eq '1') {
    $smbServerNameHardeningResult.Status = "PASS"
} else {
    $smbServerNameHardeningResult.Status = "FAIL"
}
$smbServerNameHardeningColor = if ($smbServerNameHardeningResult.Status -eq "PASS") { "green" } else { "red" }

# Add row to the HTML table data
Add-ReportTableData -color $smbServerNameHardeningColor -status $($smbServerNameHardeningResult.Status) -title $smbServerNameHardeningTitle -desc $smbServerNameHardeningDesc -expected $smbServerNameHardeningExpected -value $($smbServerNameHardeningResult.Value)

$netAdapterIp4ChecksumOffloadTitle = "Net Adapter Advanced Property"
$netAdapterIp4ChecksumOffloadResult = Get-NetAdapterAdvancedProperty -vmName $vmName -propertyName "IPv4 Checksum Offload"
$netAdapterIp4ChecksumOffloadDesc = "Checks to make sure IPv4 Checksum Offload is disabled."
$netAdapterIp4ChecksumOffloadExpected = "Disabled"
$netAdapterIp4ChecksumOffloadColor = if ($netAdapterIp4ChecksumOffloadResult.Status -eq "PASS") { "green" } else { "red" }
if ($netAdapterIp4ChecksumOffloadResult.Value -eq 'Disabled') {
    $netAdapterIp4ChecksumOffloadResult.Status = "PASS"
} else {
    $netAdapterIp4ChecksumOffloadResult.Status = "FAIL"
}
# Add row to the HTML table data
Add-ReportTableData -color $netAdapterIp4ChecksumOffloadColor -status $($netAdapterIp4ChecksumOffloadResult.Status) -title $netAdapterIp4ChecksumOffloadTitle -desc $netAdapterIp4ChecksumOffloadDesc -expected $netAdapterIp4ChecksumOffloadExpected -value $($netAdapterIp4ChecksumOffloadResult.Value)

# netAdapterIP4LargeSendOffload
$netAdapterIP4LargeSendOffloadTitle = "Net Adapter Advanced Property - IPv4 Large Send Offload"
$netAdapterIP4LargeSendOffloadResult = Get-NetAdapterAdvancedProperty -vmName $vmName -propertyName "Large Send Offload V2 (IPv4)"
$netAdapterIP4LargeSendOffloadDesc = "Checks to ensure IPv4 Large Send Offload is disabled."
$netAdapterIP4LargeSendOffloadExpected = "Disabled"
$netAdapterIP4LargeSendOffloadColor = if ($netAdapterIP4LargeSendOffloadResult.Status -eq "PASS") { "green" } else { "red" }
if ($netAdapterIP4LargeSendOffloadResult.Value -eq 'Disabled') {
    $netAdapterIP4LargeSendOffloadResult.Status = "PASS"
} else {
    $netAdapterIP4LargeSendOffloadResult.Status = "FAIL"
}
Add-ReportTableData -color $netAdapterIP4LargeSendOffloadColor -status $($netAdapterIP4LargeSendOffloadResult.Status) -title $netAdapterIP4LargeSendOffloadTitle -desc $netAdapterIP4LargeSendOffloadDesc -expected $netAdapterIP4LargeSendOffloadExpected -value $($netAdapterIP4LargeSendOffloadResult.Value)

# netAdapterIP6LargeSendOffload
$netAdapterIP6LargeSendOffloadTitle = "Net Adapter Advanced Property - IPv6 Large Send Offload"
$netAdapterIP6LargeSendOffloadResult = Get-NetAdapterAdvancedProperty -vmName $vmName -propertyName "Large Send Offload V2 (IPv6)"
$netAdapterIP6LargeSendOffloadDesc = "Checks to ensure IPv6 Large Send Offload is disabled."
$netAdapterIP6LargeSendOffloadExpected = "Disabled"
$netAdapterIP6LargeSendOffloadColor = if ($netAdapterIP6LargeSendOffloadResult.Status -eq "PASS") { "green" } else { "red" }
if ($netAdapterIP6LargeSendOffloadResult.Value -eq 'Disabled') {
    $netAdapterIP6LargeSendOffloadResult.Status = "PASS"
} else {
    $netAdapterIP6LargeSendOffloadResult.Status = "FAIL"
}
Add-ReportTableData -color $netAdapterIP6LargeSendOffloadColor -status $($netAdapterIP6LargeSendOffloadResult.Status) -title $netAdapterIP6LargeSendOffloadTitle -desc $netAdapterIP6LargeSendOffloadDesc -expected $netAdapterIP6LargeSendOffloadExpected -value $($netAdapterIP6LargeSendOffloadResult.Value)

# netAdapterTCPChecksumIPv4
$netAdapterTCPChecksumIPv4Title = "Net Adapter Advanced Property - TCP Checksum Offload IPv4"
$netAdapterTCPChecksumIPv4Result = Get-NetAdapterAdvancedProperty -vmName $vmName -propertyName "TCP Checksum Offload (IPv4)"
$netAdapterTCPChecksumIPv4Desc = "Checks to ensure TCP Checksum Offload for IPv4 is disabled."
$netAdapterTCPChecksumIPv4Expected = "Disabled"
$netAdapterTCPChecksumIPv4Color = if ($netAdapterTCPChecksumIPv4Result.Status -eq "PASS") { "green" } else { "red" }
if ($netAdapterTCPChecksumIPv4Result.Value -eq 'Disabled') {
    $netAdapterTCPChecksumIPv4Result.Status = "PASS"
} else {
    $netAdapterTCPChecksumIPv4Result.Status = "FAIL"
}
Add-ReportTableData -color $netAdapterTCPChecksumIPv4Color -status $($netAdapterTCPChecksumIPv4Result.Status) -title $netAdapterTCPChecksumIPv4Title -desc $netAdapterTCPChecksumIPv4Desc -expected $netAdapterTCPChecksumIPv4Expected -value $($netAdapterTCPChecksumIPv4Result.Value)

# netAdapterTCPChecksumIPv6
$netAdapterTCPChecksumIPv6Title = "Net Adapter Advanced Property - TCP Checksum Offload IPv6"
$netAdapterTCPChecksumIPv6Result = Get-NetAdapterAdvancedProperty -vmName $vmName -propertyName "TCP Checksum Offload (IPv6)"
$netAdapterTCPChecksumIPv6Desc = "Checks to ensure TCP Checksum Offload for IPv6 is disabled."
$netAdapterTCPChecksumIPv6Expected = "Disabled"
$netAdapterTCPChecksumIPv6Color = if ($netAdapterTCPChecksumIPv6Result.Status -eq "PASS") { "green" } else { "red" }
if ($netAdapterTCPChecksumIPv6Result.Value -eq 'Disabled') {
    $netAdapterTCPChecksumIPv6Result.Status = "PASS"
} else {
    $netAdapterTCPChecksumIPv6Result.Status = "FAIL"
}
Add-ReportTableData -color $netAdapterTCPChecksumIPv6Color -status $($netAdapterTCPChecksumIPv6Result.Status) -title $netAdapterTCPChecksumIPv6Title -desc $netAdapterTCPChecksumIPv6Desc -expected $netAdapterTCPChecksumIPv6Expected -value $($netAdapterTCPChecksumIPv6Result.Value)

# netAdapterUDPChecksumIPv4
$netAdapterUDPChecksumIPv4Title = "Net Adapter Advanced Property - UDP Checksum Offload IPv4"
$netAdapterUDPChecksumIPv4Result = Get-NetAdapterAdvancedProperty -vmName $vmName -propertyName "UDP Checksum Offload (IPv4)"
$netAdapterUDPChecksumIPv4Desc = "Checks to ensure UDP Checksum Offload for IPv4 is disabled."
$netAdapterUDPChecksumIPv4Expected = "Disabled"
$netAdapterUDPChecksumIPv4Color = if ($netAdapterUDPChecksumIPv4Result.Status -eq "PASS") { "green" } else { "red" }
if ($netAdapterUDPChecksumIPv4Result.Value -eq 'Disabled') {
    $netAdapterUDPChecksumIPv4Result.Status = "PASS"
} else {
    $netAdapterUDPChecksumIPv4Result.Status = "FAIL"
}
Add-ReportTableData -color $netAdapterUDPChecksumIPv4Color -status $($netAdapterUDPChecksumIPv4Result.Status) -title $netAdapterUDPChecksumIPv4Title -desc $netAdapterUDPChecksumIPv4Desc -expected $netAdapterUDPChecksumIPv4Expected -value $($netAdapterUDPChecksumIPv4Result.Value)

# netAdapterUDPChecksumIPv6
$netAdapterUDPChecksumIPv6Title = "Net Adapter Advanced Property - UDP Checksum Offload IPv6"
$netAdapterUDPChecksumIPv6Result = Get-NetAdapterAdvancedProperty -vmName $vmName -propertyName "UDP Checksum Offload (IPv6)"
$netAdapterUDPChecksumIPv6Desc = "Checks to ensure UDP Checksum Offload for IPv6 is disabled."
$netAdapterUDPChecksumIPv6Expected = "Disabled"
$netAdapterUDPChecksumIPv6Color = if ($netAdapterUDPChecksumIPv6Result.Status -eq "PASS") { "green" } else { "red" }
if ($netAdapterUDPChecksumIPv6Result.Value -eq 'Disabled') {
    $netAdapterUDPChecksumIPv6Result.Status = "PASS"
} else {
    $netAdapterUDPChecksumIPv6Result.Status = "FAIL"
}
Add-ReportTableData -color $netAdapterUDPChecksumIPv6Color -status $($netAdapterUDPChecksumIPv6Result.Status) -title $netAdapterUDPChecksumIPv6Title -desc $netAdapterUDPChecksumIPv6Desc -expected $netAdapterUDPChecksumIPv6Expected -value $($netAdapterUDPChecksumIPv6Result.Value)

# netAdapterIPv4TSOOffload
$netAdapterIPv4TSOOffloadTitle = "Net Adapter Advanced Property - IPv4 TSO Offload"
$netAdapterIPv4TSOOffloadResult = Get-NetAdapterAdvancedProperty -vmName $vmName -propertyName "IPv4 TSO Offload"
$netAdapterIPv4TSOOffloadDesc = "Checks to ensure IPv4 TCP Segment Offload (TSO) is disabled."
$netAdapterIPv4TSOOffloadExpected = "Disabled"
$netAdapterIPv4TSOOffloadColor = if ($netAdapterIPv4TSOOffloadResult.Status -eq "PASS") { "green" } else { "red" }
if ($netAdapterIPv4TSOOffloadResult.Value -eq 'Disabled') {
    $netAdapterIPv4TSOOffloadResult.Status = "PASS"
} else {
    $netAdapterIPv4TSOOffloadResult.Status = "FAIL"
}
Add-ReportTableData -color $netAdapterIPv4TSOOffloadColor -status $($netAdapterIPv4TSOOffloadResult.Status) -title $netAdapterIPv4TSOOffloadTitle -desc $netAdapterIPv4TSOOffloadDesc -expected $netAdapterIPv4TSOOffloadExpected -value $($netAdapterIPv4TSOOffloadResult.Value)

# netAdapterOffloadIPOptions
$netAdapterOffloadIPOptionsTitle = "Net Adapter Advanced Property - Offload IP Options"
$netAdapterOffloadIPOptionsResult = Get-NetAdapterAdvancedProperty -vmName $vmName -propertyName "Offload IP Options"
$netAdapterOffloadIPOptionsDesc = "Checks to ensure IP options offloading is disabled."
$netAdapterOffloadIPOptionsExpected = "Disabled"
$netAdapterOffloadIPOptionsColor = if ($netAdapterOffloadIPOptionsResult.Status -eq "PASS") { "green" } else { "red" }
if ($netAdapterOffloadIPOptionsResult.Value -eq 'Disabled') {
    $netAdapterOffloadIPOptionsResult.Status = "PASS"
} else {
    $netAdapterOffloadIPOptionsResult.Status = "FAIL"
}
Add-ReportTableData -color $netAdapterOffloadIPOptionsColor -status $($netAdapterOffloadIPOptionsResult.Status) -title $netAdapterOffloadIPOptionsTitle -desc $netAdapterOffloadIPOptionsDesc -expected $netAdapterOffloadIPOptionsExpected -value $($netAdapterOffloadIPOptionsResult.Value)

# netAdapterOffloadTCPOptions
$netAdapterOffloadTCPOptionsTitle = "Net Adapter Advanced Property - Offload TCP Options"
$netAdapterOffloadTCPOptionsResult = Get-NetAdapterAdvancedProperty -vmName $vmName -propertyName "Offload TCP Options"
$netAdapterOffloadTCPOptionsDesc = "Checks to ensure TCP options offloading is disabled."
$netAdapterOffloadTCPOptionsExpected = "Disabled"
$netAdapterOffloadTCPOptionsColor = if ($netAdapterOffloadTCPOptionsResult.Status -eq "PASS") { "green" } else { "red" }
if ($netAdapterOffloadTCPOptionsResult.Value -eq 'Disabled') {
    $netAdapterOffloadTCPOptionsResult.Status = "PASS"
} else {
    $netAdapterOffloadTCPOptionsResult.Status = "FAIL"
}
Add-ReportTableData -color $netAdapterOffloadTCPOptionsColor -status $($netAdapterOffloadTCPOptionsResult.Status) -title $netAdapterOffloadTCPOptionsTitle -desc $netAdapterOffloadTCPOptionsDesc -expected $netAdapterOffloadTCPOptionsExpected -value $($netAdapterOffloadTCPOptionsResult.Value)

# netAdapterOffloadTaggedTraffic
$netAdapterOffloadTaggedTrafficTitle = "Net Adapter Advanced Property - Offload Tagged Traffic"
$netAdapterOffloadTaggedTrafficResult = Get-NetAdapterAdvancedProperty -vmName $vmName -propertyName "Offload Tagged Traffic"
$netAdapterOffloadTaggedTrafficDesc = "Checks to ensure tagged traffic offloading is disabled."
$netAdapterOffloadTaggedTrafficExpected = "Disabled"
$netAdapterOffloadTaggedTrafficColor = if ($netAdapterOffloadTaggedTrafficResult.Status -eq "PASS") { "green" } else { "red" }
if ($netAdapterOffloadTaggedTrafficResult.Value -eq 'Disabled') {
    $netAdapterOffloadTaggedTrafficResult.Status = "PASS"
} else {
    $netAdapterOffloadTaggedTrafficResult.Status = "FAIL"
}
Add-ReportTableData -color $netAdapterOffloadTaggedTrafficColor -status $($netAdapterOffloadTaggedTrafficResult.Status) -title $netAdapterOffloadTaggedTrafficTitle -desc $netAdapterOffloadTaggedTrafficDesc -expected $netAdapterOffloadTaggedTrafficExpected -value $($netAdapterOffloadTaggedTrafficResult.Value)

# netAdapterReceiveSideScaling
$netAdapterReceiveSideScalingTitle = "Net Adapter Advanced Property - Receive Side Scaling"
$netAdapterReceiveSideScalingResult = Get-NetAdapterAdvancedProperty -vmName $vmName -propertyName "Receive Side Scaling"
$netAdapterReceiveSideScalingDesc = "Checks to ensure Receive Side Scaling (RSS) is disabled."
$netAdapterReceiveSideScalingExpected = "Disabled"
$netAdapterReceiveSideScalingColor = if ($netAdapterReceiveSideScalingResult.Status -eq "PASS") { "green" } else { "red" }
if ($netAdapterReceiveSideScalingResult.Value -eq 'Disabled') {
    $netAdapterReceiveSideScalingResult.Status = "PASS"
} else {
    $netAdapterReceiveSideScalingResult.Status = "FAIL"
}
Add-ReportTableData -color $netAdapterReceiveSideScalingColor -status $($netAdapterReceiveSideScalingResult.Status) -title $netAdapterReceiveSideScalingTitle -desc $netAdapterReceiveSideScalingDesc -expected $netAdapterReceiveSideScalingExpected -value $($netAdapterReceiveSideScalingResult.Value)

# netAdapterRecvSegmentCoalescingIPv4
$netAdapterRecvSegmentCoalescingIPv4Title = "Net Adapter Advanced Property - Receive Segment Coalescing IPv4"
$netAdapterRecvSegmentCoalescingIPv4Result = Get-NetAdapterAdvancedProperty -vmName $vmName -propertyName "Recv Segment Coalescing (IPv4)"
$netAdapterRecvSegmentCoalescingIPv4Desc = "Checks to ensure Receive Segment Coalescing (IPv4) is disabled."
$netAdapterRecvSegmentCoalescingIPv4Expected = "Disabled"
$netAdapterRecvSegmentCoalescingIPv4Color = if ($netAdapterRecvSegmentCoalescingIPv4Result.Status -eq "PASS") { "green" } else { "red" }
if ($netAdapterRecvSegmentCoalescingIPv4Result.Value -eq 'Disabled') {
    $netAdapterRecvSegmentCoalescingIPv4Result.Status = "PASS"
} else {
    $netAdapterRecvSegmentCoalescingIPv4Result.Status = "FAIL"
}
Add-ReportTableData -color $netAdapterRecvSegmentCoalescingIPv4Color -status $($netAdapterRecvSegmentCoalescingIPv4Result.Status) -title $netAdapterRecvSegmentCoalescingIPv4Title -desc $netAdapterRecvSegmentCoalescingIPv4Desc -expected $netAdapterRecvSegmentCoalescingIPv4Expected -value $($netAdapterRecvSegmentCoalescingIPv4Result.Value)

# netAdapterRecvSegmentCoalescingIPv6
$netAdapterRecvSegmentCoalescingIPv6Title = "Net Adapter Advanced Property - Receive Segment Coalescing IPv6"
$netAdapterRecvSegmentCoalescingIPv6Result = Get-NetAdapterAdvancedProperty -vmName $vmName -propertyName "Recv Segment Coalescing (IPv6)"
$netAdapterRecvSegmentCoalescingIPv6Desc = "Checks to ensure Receive Segment Coalescing (IPv6) is disabled."
$netAdapterRecvSegmentCoalescingIPv6Expected = "Disabled"
$netAdapterRecvSegmentCoalescingIPv6Color = if ($netAdapterRecvSegmentCoalescingIPv6Result.Status -eq "PASS") { "green" } else { "red" }
if ($netAdapterRecvSegmentCoalescingIPv6Result.Value -eq 'Disabled') {
    $netAdapterRecvSegmentCoalescingIPv6Result.Status = "PASS"
} else {
    $netAdapterRecvSegmentCoalescingIPv6Result.Status = "FAIL"
}
Add-ReportTableData -color $netAdapterRecvSegmentCoalescingIPv6Color -status $($netAdapterRecvSegmentCoalescingIPv6Result.Status) -title $netAdapterRecvSegmentCoalescingIPv6Title -desc $netAdapterRecvSegmentCoalescingIPv6Desc -expected $netAdapterRecvSegmentCoalescingIPv6Expected -value $($netAdapterRecvSegmentCoalescingIPv6Result.Value)

# QoS Packet Scheduler Binding
$qosPacketSchedulerBindingTitle = "QoS Packet Scheduler Binding Check"
$qosPacketSchedulerBindingExpected = "False"
$qosPacketSchedulerBindingResult = Get-NetAdapterBindingProperty -vmName $vmName -propertyName "QoS Packet Scheduler"
$qosPacketSchedulerBindingDesc = "Checks to ensure that the QoS Packet Scheduler is disabled (set to False)."
if ($qosPacketSchedulerBindingResult.Value -eq $false) {
    $qosPacketSchedulerBindingResult.Status = "PASS"
} else {
    $qosPacketSchedulerBindingResult.Status = "FAIL"
}
$qosPacketSchedulerBindingColor = if ($qosPacketSchedulerBindingResult.Status -eq "PASS") { "green" } else { "red" }
Add-ReportTableData -color $qosPacketSchedulerBindingColor -status $($qosPacketSchedulerBindingResult.Status) -title $qosPacketSchedulerBindingTitle -desc $qosPacketSchedulerBindingDesc -expected $qosPacketSchedulerBindingExpected -value $($qosPacketSchedulerBindingResult.Value)

# Link-Layer Topology Discovery Mapper I/O Driver Binding
$linkLayerMapperBindingTitle = "Link-Layer Topology Discovery Mapper Binding Check"
$linkLayerMapperBindingExpected = "False"
$linkLayerMapperBindingResult = Get-NetAdapterBindingProperty -vmName $vmName -propertyName "Link-Layer Topology Discovery Mapper I/O Driver"
$linkLayerMapperBindingDesc = "Checks to ensure that the Link-Layer Topology Discovery Mapper I/O Driver is disabled (set to False)."
if ($linkLayerMapperBindingResult.Value -eq $false) {
    $linkLayerMapperBindingResult.Status = "PASS"
} else {
    $linkLayerMapperBindingResult.Status = "FAIL"
}
$linkLayerMapperBindingColor = if ($linkLayerMapperBindingResult.Status -eq "PASS") { "green" } else { "red" }
Add-ReportTableData -color $linkLayerMapperBindingColor -status $($linkLayerMapperBindingResult.Status) -title $linkLayerMapperBindingTitle -desc $linkLayerMapperBindingDesc -expected $linkLayerMapperBindingExpected -value $($linkLayerMapperBindingResult.Value)

# Link-Layer Topology Discovery Responder Binding
$linkLayerResponderBindingTitle = "Link-Layer Topology Discovery Responder Binding Check"
$linkLayerResponderBindingExpected = "False"
$linkLayerResponderBindingResult = Get-NetAdapterBindingProperty -vmName $vmName -propertyName "Link-Layer Topology Discovery Responder"
$linkLayerResponderBindingDesc = "Checks to ensure that the Link-Layer Topology Discovery Responder is disabled (set to False)."
if ($linkLayerResponderBindingResult.Value -eq $false) {
    $linkLayerResponderBindingResult.Status = "PASS"
} else {
    $linkLayerResponderBindingResult.Status = "FAIL"
}
$linkLayerResponderBindingColor = if ($linkLayerResponderBindingResult.Status -eq "PASS") { "green" } else { "red" }
Add-ReportTableData -color $linkLayerResponderBindingColor -status $($linkLayerResponderBindingResult.Status) -title $linkLayerResponderBindingTitle -desc $linkLayerResponderBindingDesc -expected $linkLayerResponderBindingExpected -value $($linkLayerResponderBindingResult.Value)

#######################################################################################################
#####################################  Check some system settings #####################################
#######################################################################################################

################################ Check to make sure UAC is not disabled ###############################

# Set varibales for Local Machine UAC Check
$localMachineUacCheckTitle = "UAC Enabled Check"
$localMachineUacCheckPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$localMachineUacCheckValue = "EnableLUA"
$localMachineUacCheckDesc = "Ensure that UAC is enabled on this machine."
$localMachineUacCheckExpected = "1"

# Retrieve Local Machine Execution Policy
Write-Host "Getting $localMachineUacCheckValue"
$localMachineUacCheckResult = Get-RemoteRegistryValue -vmName $vmName -registryPath $localMachineUacCheckPath -registryValue $localMachineUacCheckValue
Write-Host "Local Machine UAC result status $($localMachineUacCheckResult.Status)"
Write-Host "Local Machine UAC value: $($localMachineUacCheckResult.Value)"

# Check if ExecutionPolicy is 'RemoteSigned'
if ($localMachineUacCheckResult.Value -eq '1') {
    $localMachineUacCheckResult.Status = "PASS"
} else {
    $localMachineUacCheckResult.Status = "FAIL"
}
$localMachineUacCheckColor = if ($localMachineUacCheckResult.Status -eq "PASS") { "green" } else { "red" }
# Add row to the HTML table data
Add-ReportTableData -color $localMachineUacCheckColor -status $($localMachineUacCheckResult.Status) -title $localMachineUacCheckTitle -desc $localMachineUacCheckDesc -expected $localMachineUacCheckExpected -value $($localMachineUacCheckResult.Value)





#######################################################################################################
#####################################  AD Group Membership Checks #####################################
#######################################################################################################

# A_SCCM_SUS_GPO_Servers Check
$A_SCCM_SUS_GPO_ServersTitle = "A_SCCM_SUS_GPO_Servers Group Membership Check"
$A_SCCM_SUS_GPO_ServersExpected = "A_SCCM_SUS_GPO_Servers"
$A_SCCM_SUS_GPO_ServersResult = Get-RemoteAdMachineGroupStatus -vmName $vmName -adMachineGroupName "A_SCCM_SUS_GPO_Servers"
$A_SCCM_SUS_GPO_ServersDesc = "Checks to ensure that the server is a member of A_SCCM_SUS_GPO_Servers."
if ($A_SCCM_SUS_GPO_ServersResult.Value -eq "A_SCCM_SUS_GPO_Servers") {
    $A_SCCM_SUS_GPO_ServersResult.Status = "PASS"
} else {
    $A_SCCM_SUS_GPO_ServersResult.Status = "FAIL"
}
$A_SCCM_SUS_GPO_ServersColor = if ($A_SCCM_SUS_GPO_ServersResult.Status -eq "PASS") { "green" } else { "red" }

# Add row to the HTML table data
Add-ReportTableData -color $A_SCCM_SUS_GPO_ServersColor -status $($A_SCCM_SUS_GPO_ServersResult.Status) -title $A_SCCM_SUS_GPO_ServersTitle -desc $A_SCCM_SUS_GPO_ServersDesc -expected $A_SCCM_SUS_GPO_ServersExpected -value $($A_SCCM_SUS_GPO_ServersResult.Value)

# A_Computer_Server_vRA_PROD Check
$A_Computer_Server_vRAPRODTitle = "A_Computer_Server_vRA_PROD Group Membership Check"
$A_Computer_Server_vRAPRODExpected = "A_Computer_Server_vRA_PROD"
$A_Computer_Server_vRA_PRODResult = Get-RemoteAdMachineGroupStatus -vmName $vmName -adMachineGroupName "A_Computer_Server_vRA_PROD"
$A_Computer_Server_vRAPRODDesc = "Checks to ensure that the server is a member of A_Computer_Server_vRA_PROD."
if ($A_Computer_Server_vRA_PRODResult.Value -eq "A_Computer_Server_vRA_PROD") {
    $A_Computer_Server_vRA_PRODResult.Status = "PASS"
} else {
    $A_Computer_Server_vRA_PRODResult.Status = "FAIL"
}
$A_Computer_Server_vRAPRODColor = if ($A_Computer_Server_vRA_PRODResult.Status -eq "PASS") { "green" } else { "red" }

# Add row to the HTML table data
Add-ReportTableData -color $A_Computer_Server_vRAPRODColor -status $($A_Computer_Server_vRA_PRODResult.Status) -title $A_Computer_Server_vRAPRODTitle -desc $A_Computer_Server_vRAPRODDesc -expected $A_Computer_Server_vRAPRODExpected -value $($A_Computer_Server_vRA_PRODResult.Value)

# A_SCCM_ClientInstall_WMP Check
$A_SCCM_ClientInstall_WMPTitle = "A_SCCM_ClientInstall_WMP Group Membership Check"
$A_SCCM_ClientInstall_WMPExpected = "A_SCCM_ClientInstall_WMP"
$A_SCCM_ClientInstall_WMPResult = Get-RemoteAdMachineGroupStatus -vmName $vmName -adMachineGroupName "A_SCCM_ClientInstall_WMP"
$A_SCCM_ClientInstall_WMPDesc = "Checks to ensure that the server is a member of A_SCCM_ClientInstall_WMP."
if ($A_SCCM_ClientInstall_WMPResult.Value -eq "A_SCCM_ClientInstall_WMP") {
    $A_SCCM_ClientInstall_WMPResult.Status = "PASS"
} else {
    $A_SCCM_ClientInstall_WMPResult.Status = "FAIL"
}
$A_SCCM_ClientInstall_WMPColor = if ($A_SCCM_ClientInstall_WMPResult.Status -eq "PASS") { "green" } else { "red" }

# Add row to the HTML table data
Add-ReportTableData -color $A_SCCM_ClientInstall_WMPColor -status $($A_SCCM_ClientInstall_WMPResult.Status) -title $A_SCCM_ClientInstall_WMPTitle -desc $A_SCCM_ClientInstall_WMPDesc -expected $A_SCCM_ClientInstall_WMPExpected -value $($A_SCCM_ClientInstall_WMPResult.Value)


#######################################################################################################
######################################### Start User Data Compare #####################################
#######################################################################################################

# Get access token for session
Write-Host "Getting access token"
$accessToken = Get-AccessToken -baseApiUrl $baseApiUrl

if ($accessToken) {

    $userInputData = Get-UserInputData -vmName $vmName -accessToken $accessToken

    #######################################################################################################
    # Get user input elements returned in the array
    #######################################################################################################
    $deploymentDetails = $userInputData.content[0]

    $inputs = $deploymentDetails.inputs

    $userInputMachineName = $($inputs.MachineName)
    $userInputFlavor = $($inputs.Flavor)
    $userInputImage = $($inputs.Image)
    $userInputGDrive = $($inputs.GDrive)
    $userInputHDrive = $($inputs.HDrive)
    $userInputLDrive = $($inputs.LDrive)
    $userInputMDrive = $($inputs.MDrive)
    $userInputTDrive = $($inputs.TDrive)
    $userInputYDrive = $($inputs.YDrive)
    $userInputPatchDay = $($inputs.PatchDay)
    $userInputNetwork = $($inputs.Network)
    $userInputTermServer = $($inputs.TermServer)
    $userInputIIS = $($inputs.IIS)

    Write-Host "Server Name selected by user: $userInputMachineName"
    Write-Host "Flavor: $userInputFlavor"
    Write-Host "Image: $userInputImage"
    Write-Host "Network: $userInputNetwork"
    Write-Host "Patch Day: $userInputPatchDay"
    Write-Host "G Drive request: $userInputGDrive"
    Write-Host "H Drive request: $userInputHDrive"
    Write-Host "L Drive request: $userInputLDrive"
    Write-Host "M Drive request: $userInputMDrive"
    Write-Host "T Drive request: $userInputTDrive"
    Write-Host "Y Drive request: $userInputYDrive"
    Write-Host "Term Server: $userInputtermServer"
    Write-Host "IIS: $userInputIIS"

    #################################################################################
    ################################## Patch Group Check ############################
    #################################################################################
    $ADGroupMembershipTitle = "Patch Group Check"
    $ADGroupMembershipExpected = "$userInputPatchDay"
    $ADGroupMembershipResult = Get-RemoteAdMachineGroupStatus -vmName $vmName -adMachineGroupName $userInputPatchDay
    $ADGroupMembershipDesc = "Checks to make sure the server is in the requested Patch Group."
    if ($userInputPatchDay -eq $ADGroupMembershipResult.Value) {
        $ADGroupMembershipResult.Status = "PASS"
    } else {
        $ADGroupMembershipResult.Status = "FAIL"
    }
    $ADGroupMembershipColor = if ($ADGroupMembershipResult.Status -eq "PASS") { "green" } else { "red" }
    Add-ReportTableData -color $ADGroupMembershipColor -status $($ADGroupMembershipResult.Status) -title $ADGroupMembershipTitle -desc $ADGroupMembershipDesc -expected $ADGroupMembershipExpected -value $($ADGroupMembershipResult.Value)

    #################################################################################
    ################################## DISK DRIVE CHECK #############################
    #################################################################################

    # Define the array of drive letters available
    $driveLetters = @("G", "H", "L", "M", "T", "Y")

    # Loop through each drive letter
    foreach ($driveLetter in $driveLetters) {
        $driveSizeMessage = Get-RemoteDriveSize -vmName $vmName -driveLetter $driveLetter
        if ($driveSizeMessage -match "(\d+(\.\d+)?)\s*GB") {
            $driveSize = [double]$matches[1]  # Convert the extracted size to a number
            $roundedDriveSize = [math]::Round($driveSize, 0)
            New-Variable -Name "${driveLetter}DriveSize" -Value $roundedDriveSize
        }
        else {
            Write-Host "Drive $driveLetter size could not be determined."
        }
    }

    Write-Host "G Drive actual size: $GDriveSize GB"
    Write-Host "H Drive actual size: $HDriveSize GB"
    Write-Host "L Drive actual size: $LDriveSize GB"
    Write-Host "M Drive actual size: $MDriveSize GB"
    Write-Host "T Drive actual size: $TDriveSize GB"
    Write-Host "Y Drive actual size: $YDriveSize GB"

    
    #################################################################################
    # Drive Size Check
    #################################################################################

    $GDriveTitle = "G Drive"
    $GDriveDesc = "Drive size check"
    if ($userInputGDrive -gt 0) {
        if ($GDriveSize -eq $userInputGDrive) {
            $GDriveStatus = "PASS"
        } else {
            $GDriveStatus = "FAIL"
        }

        $GDriveColor = if ($GDriveStatus -eq "PASS") { "green" } else { "red" }
        Add-ReportTableData -color $GDriveColor -status $($GDriveStatus) -title $GDriveTitle -desc $GDriveDesc -expected $userInputGDrive -value $GDriveSize

    } else {
        $GDriveStatus = "Not requested"
        $GDriveSize = "n/a"
        $GDriveColor = "green"
        Add-ReportTableData -color $GDriveColor -status $($GDriveStatus) -title $GDriveTitle -desc $GDriveDesc -expected "n/a" -value $GDriveSize
    }

    $HDriveTitle = "H Drive"
    $HDriveDesc = "Drive size check"
    if ($userInputHDrive -gt 0) {
        if ($HDriveSize -eq $userInputHDrive) {
            $HDriveStatus = "PASS"
        } else {
            $HDriveStatus = "FAIL"
        }

        $HDriveColor = if ($HDriveStatus -eq "PASS") { "green" } else { "red" }
        # Add row to the HTML table data
        Add-ReportTableData -color $HDriveColor -status $($HDriveStatus) -title $HDriveTitle -desc $HDriveDesc -expected $userInputHDrive -value $HDriveSize

    } else {
        $HDriveStatus = "Not requested"
        $HDriveSize = "n/a"
        $HDriveColor = "green"
        Add-ReportTableData -color $HDriveColor -status $($HDriveStatus) -title $HDriveTitle -desc $HDriveDesc -expected "n/a" -value $HDriveSize

    }

    $LDriveTitle = "L Drive"
    $LDriveDesc = "Drive size check"
    if ($userInputLDrive -gt 0) {
        if ($LDriveSize -eq $userInputLDrive) {
            $LDriveStatus = "PASS"
        } else {
            $LDriveStatus = "FAIL"
        }

        $LDriveColor = if ($LDriveStatus -eq "PASS") { "green" } else { "red" }
        Add-ReportTableData -color $LDriveColor -status $($LDriveStatus) -title $LDriveTitle -desc $LDriveDesc -expected $userInputLDrive -value $LDriveSize

    } else {
        $LDriveStatus = "Not requested"
        $LDriveSize = "n/a"
        $LDriveColor = "green"
        Add-ReportTableData -color $LDriveColor -status $($LDriveStatus) -title $LDriveTitle -desc $LDriveDesc -expected "n/a" -value $LDriveSize
    }

    $MDriveTitle = "M Drive"
    $MDriveDesc = "Drive size check"
    if ($userInputMDrive -gt 0) {
        if ($MDriveSize -eq $userInputMDrive) {
            $MDriveStatus = "PASS"
        } else {
            $MDriveStatus = "FAIL"
        }

        $MDriveColor = if ($MDriveStatus -eq "PASS") { "green" } else { "red" }
        Add-ReportTableData -color $MDriveColor -status $($MDriveStatus) -title $MDriveTitle -desc $MDriveDesc -expected $userInputMDrive -value $MDriveSize

    } else {
        $MDriveStatus = "Not requested"
        $MDriveSize = "n/a"
        $MDriveColor = "green"
        Add-ReportTableData -color $MDriveColor -status $($MDriveStatus) -title $MDriveTitle -desc $MDriveDesc -expected "n/a" -value $MDriveSize
    }

    $TDriveTitle = "T Drive"
    $TDriveDesc = "Drive size check"
    if ($userInputTDrive -gt 0) {
        if ($TDriveSize -eq $userInputTDrive) {
            $TDriveStatus = "PASS"
        } else {
            $TDriveStatus = "FAIL"
        }

        $TDriveColor = if ($TDriveStatus -eq "PASS") { "green" } else { "red" }
        Add-ReportTableData -color $TDriveColor -status $($TDriveStatus) -title $TDriveTitle -desc $TDriveDesc -expected $userInputTDrive -value $TDriveSize

    } else {
        $TDriveStatus = "Not requested"
        $TDriveSize = "n/a"
        $TDriveColor = "green"
        Add-ReportTableData -color $TDriveColor -status $($TDriveStatus) -title $TDriveTitle -desc $TDriveDesc -expected "n/a" -value $TDriveSize
    }

    $YDriveTitle = "Y Drive"
    $YDriveDesc = "Drive size check"
    if ($userInputYDrive -gt 0) {
        if ($YDriveSize -eq $userInputYDrive) {
            $YDriveStatus = "PASS"
        } else {
            $YDriveStatus = "FAIL"
        }

        $YDriveColor = if ($YDriveStatus -eq "PASS") { "green" } else { "red" }
        Add-ReportTableData -color $YDriveColor -status $($YDriveStatus) -title $YDriveTitle -desc $YDriveDesc -expected $userInputYDrive -value $YDriveSize

    } else {
        $YDriveStatus = "Not requested"
        $YDriveSize = "n/a"
        $YDriveColor = "green"
        Add-ReportTableData -color $YDriveColor -status $($YDriveStatus) -title $YDriveTitle -desc $YDriveDesc -expected "n/a" -value $YDriveSize
    }

    #################################################################################
    # Drive Label Check
    #################################################################################

    if ($userInputGDrive -gt 0) {
        $GVolumeNameTitle = "G: Drive Label"
        $GVolumeNameResult = Get-RemoteVolumeName -vmName $vmName -driveLetter "G"
        $GVolumeNameDesc = "G: drive got renamed to APPS"
        $GVolumeNameExpected = "APPS"
        if ($GVolumeNameResult.Value -eq "APPS") {
            $GVolumeNameResult.Status = "PASS"
        } else {
            $GVolumeNameResult.Status = "FAIL"
        }
        $GVolumeNameColor = if ($GVolumeNameResult.Status -eq "PASS") { "green" } else { "red" }
        # Add row to the HTML table data
        Add-ReportTableData -color $GVolumeNameColor -status $($GVolumeNameResult.Status) -title $GVolumeNameTitle -desc $GVolumeNameDesc -expected $GVolumeNameExpected -value $($GVolumeNameResult.Value)

    } else {
        $GDriveStatus = "Not requested"
        $GDriveSize = "n/a"
        $GDriveColor = "green"
        $GVolumeNameDesc = "G: drive got renamed to APPS"
        Add-ReportTableData -color $GDriveColor -status "Not Requested" -title $GDriveTitle -desc $GVolumeNameDesc -expected "n/a" -value "n/a"
    }


    if ($userInputHDrive -gt 0) {

        $HVolumeNameTitle = "H: Drive Label"
        $HVolumeNameResult = Get-RemoteVolumeName -vmName $vmName -driveLetter "H"
        $HVolumeNameDesc = "H: drive got renamed to DATA"
        $HVolumeNameExpected = "DATA"
        if ($HVolumeNameResult.Value -eq "DATA") {
            $HVolumeNameResult.Status = "PASS"
        } else {
            $HVolumeNameResult.Status = "FAIL"
        }
        $HVolumeNameColor = if ($HVolumeNameResult.Status -eq "PASS") { "green" } else { "red" }
        # Add row to the HTML table data
        Add-ReportTableData -color $HVolumeNameColor -status $($HVolumeNameResult.Status) -title $HVolumeNameTitle -desc $HVolumeNameDesc -expected $HVolumeNameExpected -value $($HVolumeNameResult.Value)

    } else {
        $HDriveStatus = "Not requested"
        $HDriveSize = "n/a"
        $HDriveColor = "green"
        $HVolumeNameDesc = "H: drive got renamed to DATA"
        Add-ReportTableData -color $HDriveColor -status "Not Requested" -title $HDriveTitle -desc $HVolumeNameDesc -expected "n/a" -value $HDriveSize
    }

    if ($userInputLDrive -gt 0) {

        $LVolumeNameTitle = "L: Drive Label"
        $LVolumeNameResult = Get-RemoteVolumeName -vmName $vmName -driveLetter "L"
        $LVolumeNameDesc = "L: drive got renamed to LOGS"
        $LVolumeNameExpected = "LOGS"
        if ($LVolumeNameResult.Value -eq "LOGS") {
            $LVolumeNameResult.Status = "PASS"
        } else {
            $LVolumeNameResult.Status = "FAIL"
        }
        $LVolumeNameColor = if ($LVolumeNameResult.Status -eq "PASS") { "green" } else { "red" }
        # Add row to the HTML table data
        Add-ReportTableData -color $LVolumeNameColor -status $($LVolumeNameResult.Status) -title $LVolumeNameTitle -desc $LVolumeNameDesc -expected $LVolumeNameExpected -value $($LVolumeNameResult.Value)

    } else {
        $LDriveStatus = "Not requested"
        $LDriveSize = "n/a"
        $LDriveColor = "green"
        $LVolumeNameDesc = "L: drive got renamed to LOGS"
        Add-ReportTableData -color $LDriveColor -status "Not Requested" -title $LDriveTitle -desc $LVolumeNameDesc -expected "n/a" -value $LDriveSize
    }

    if ($userInputMDrive -gt 0) {

        $MVolumeNameTitle = "M: Drive Label"
        $MVolumeNameResult = Get-RemoteVolumeName -vmName $vmName -driveLetter "M"
        $MVolumeNameDesc = "M: drive got renamed to SQLBU"
        $MVolumeNameExpected = "SQLBU"
        if ($MVolumeNameResult.Value -eq "SQLBU") {
            $MVolumeNameResult.Status = "PASS"
        } else {
            $MVolumeNameResult.Status = "FAIL"
        }
        $MVolumeNameColor = if ($MVolumeNameResult.Status -eq "PASS") { "green" } else { "red" }
        # Add row to the HTML table data
        Add-ReportTableData -color $MVolumeNameColor -status $($MVolumeNameResult.Status) -title $MVolumeNameTitle -desc $MVolumeNameDesc -expected $MVolumeNameExpected -value $($MVolumeNameResult.Value)

    } else {
        $MDriveStatus = "Not requested"
        $MDriveSize = "n/a"
        $MDriveColor = "green"
        $MVolumeNameDesc = "M: drive got renamed to SQLBU"
        Add-ReportTableData -color $MDriveColor -status "Not Requested" -title $MDriveTitle -desc $MVolumeNameDesc -expected "n/a" -value $MDriveSize
    }

    if ($userInputTDrive -gt 0) {

        $TVolumeNameTitle = "T: Drive Label"
        $TVolumeNameResult = Get-RemoteVolumeName -vmName $vmName -driveLetter "T"
        $TVolumeNameDesc = "T: drive got renamed to TEMP"
        $TVolumeNameExpected = "TEMP"
        if ($TVolumeNameResult.Value -eq "TEMP") {
            $TVolumeNameResult.Status = "PASS"
        } else {
            $TVolumeNameResult.Status = "FAIL"
        }
        $TVolumeNameColor = if ($TVolumeNameResult.Status -eq "PASS") { "green" } else { "red" }
        # Add row to the HTML table data
        Add-ReportTableData -color $TVolumeNameColor -status $($TVolumeNameResult.Status) -title $TVolumeNameTitle -desc $TVolumeNameDesc -expected $TVolumeNameExpected -value $($TVolumeNameResult.Value)

    } else {
        $TDriveStatus = "Not requested"
        $TDriveSize = "n/a"
        $TDriveColor = "green"
        $TVolumeNameDesc = "T: drive got renamed to TEMP"
        Add-ReportTableData -color $TDriveColor -status "Not Requested" -title $TDriveTitle -desc $TVolumeNameDesc -expected "n/a" -value $TDriveSize
    }

    if ($userInputYDrive -gt 0) {

        $YVolumeNameTitle = "Y: Drive Label"
        $YVolumeNameResult = Get-RemoteVolumeName -vmName $vmName -driveLetter "Y"
        $YVolumeNameDesc = "Y: drive got renamed to ANALYST"
        $YVolumeNameExpected = "ANALYST"
        if ($YVolumeNameResult.Value -eq "ANALYST") {
            $YVolumeNameResult.Status = "PASS"
        } else {
            $YVolumeNameResult.Status = "FAIL"
        }
        $YVolumeNameColor = if ($YVolumeNameResult.Status -eq "PASS") { "green" } else { "red" }
        # Add row to the HTML table data
        Add-ReportTableData -color $YVolumeNameColor -status $($YVolumeNameResult.Status) -title $YVolumeNameTitle -desc $YVolumeNameDesc -expected $YVolumeNameExpected -value $($YVolumeNameResult.Value)

    } else {
        $YDriveStatus = "Not requested"
        $YDriveSize = "n/a"
        $YDriveColor = "green"
        $YVolumeNameDesc = "Y: drive got renamed to ANALYST"
        Add-ReportTableData -color $YDriveColor -status "Not Requested" -title $YDriveTitle -desc $YVolumeNameDesc -expected "n/a" -value $YDriveSize
    }
} else {

    Write-Host "Cannot get user requested data."
    Write-Host "Server was not built using vRA."
}

#######################################################################################################
############################################## Save the Report ########################################
#######################################################################################################

$htmlBody = $htmlHeader + $htmlTableData + $htmlFooter

# Write the HTML content to the file
$htmlBody | Out-File -FilePath $outputFile -Encoding UTF8