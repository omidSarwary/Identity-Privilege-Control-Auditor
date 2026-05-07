<#
.SYNOPSIS
    NordSec Identity & Privilege Control Auditor - Windows Identity Audit Sensor.

.DESCRIPTION
    Read-only Windows collection helper that exports local identities, local
    administrator membership, Event Viewer evidence, and policy state for the
    later analysis pipeline. The script does not modify system state.

.VERSION
    1.0.0
#>

[CmdletBinding()]
param(
    [ValidateSet("Production", "Test")]
    [string]$Mode = "Production",

    [string]$LogHours = "24",

    [string]$MaxEvents = "1000"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:DefaultLogHours = 24
$script:DefaultMaxEvents = 1000
$script:MaxLogHours = 720
$script:MaxMaxEvents = 10000
$script:ResolvedLogHours = $script:DefaultLogHours
$script:ResolvedMaxEvents = $script:DefaultMaxEvents
$script:ResolvedStartTime = $null

$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptRoot
$DataDir = Join-Path $ProjectRoot 'data'
$CollectedDir = Join-Path $DataDir 'collected'
$LogsDir = Join-Path $ProjectRoot 'logs'
$TestsMockDataDir = Join-Path $ProjectRoot 'tests\mockdata'

$IdentityCsvPath = Join-Path $CollectedDir 'windows_identity.csv'
$EventsCsvPath = Join-Path $CollectedDir 'windows_events.csv'
$PolicyCsvPath = Join-Path $CollectedDir 'windows_policy.csv'
$AuditLogPath = Join-Path $LogsDir 'windows_audit.log'
$AnomaliesLogPath = Join-Path $LogsDir 'anomalies.log'

$script:AuditRecords = @()
$script:IdentityRecords = @()
$script:EventRecords = @()
$script:PolicyRecords = @()
$script:LocalAdminMembers = @()

function Write-Log {
    <#
    .SYNOPSIS
        Write a timestamped log message.

    .DESCRIPTION
        Writes a structured log entry to the Windows audit log and, for warning
        and error levels, also to the anomalies log. This keeps operational
        messages and policy-relevant issues easy to trace during analysis.
    #>
    param(
        [ValidateSet('INFO', 'WARNING', 'ERROR')]
        [string]$Level,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    $timestamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
    $entry = '{0} [{1}] {2}' -f $timestamp, $Level, $Message
    Add-Content -Path $AuditLogPath -Value $entry -Encoding UTF8
    $script:AuditRecords += $entry

    if ($Level -ne 'INFO') {
        Add-Content -Path $AnomaliesLogPath -Value $entry -Encoding UTF8
    }
}

function Resolve-PositiveIntValue {
    <#
    .SYNOPSIS
        Normalize a numeric option and keep it within safe bounds.

    .DESCRIPTION
        Converts a raw string value into a positive integer, falls back to a
        documented default when parsing fails, and clamps values that exceed
        the configured safety limit. This keeps collection bounded without
        crashing when the user supplies unexpected input.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$RawValue,

        [Parameter(Mandatory = $true)]
        [int]$DefaultValue,

        [Parameter(Mandatory = $true)]
        [int]$UpperBound,

        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    if ([string]::IsNullOrWhiteSpace($RawValue)) {
        return $DefaultValue
    }

    $parsedValue = 0
    if (-not [int]::TryParse($RawValue, [ref]$parsedValue) -or $parsedValue -le 0) {
        Write-Log -Level 'WARNING' -Message "$Label '$RawValue' is invalid; using default $DefaultValue."
        return $DefaultValue
    }

    if ($parsedValue -gt $UpperBound) {
        Write-Log -Level 'WARNING' -Message "$Label '$RawValue' exceeds the maximum $UpperBound; clamping to $UpperBound."
        return $UpperBound
    }

    return $parsedValue
}

function Initialize-CollectionWindow {
    <#
    .SYNOPSIS
        Resolve and log the bounded Security log collection window.

    .DESCRIPTION
        Applies the safe log lookback hours and maximum event limit before the
        Security log is queried. The resolved values are recorded in the audit
        log so the run can be traced later.
    #>
    $script:ResolvedLogHours = Resolve-PositiveIntValue -RawValue $LogHours -DefaultValue $script:DefaultLogHours -UpperBound $script:MaxLogHours -Label 'Windows log hours'
    $script:ResolvedMaxEvents = Resolve-PositiveIntValue -RawValue $MaxEvents -DefaultValue $script:DefaultMaxEvents -UpperBound $script:MaxMaxEvents -Label 'Windows max events'
    $script:ResolvedStartTime = (Get-Date).AddHours(-1 * $script:ResolvedLogHours)
    Write-Log -Level 'INFO' -Message ("Windows Security collection window resolved: LogHours={0}, MaxEvents={1}, StartTime={2}" -f $script:ResolvedLogHours, $script:ResolvedMaxEvents, $script:ResolvedStartTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
}

function Initialize-Paths {
    <#
    .SYNOPSIS
        Create the output directories used by the sensor.

    .DESCRIPTION
        Ensures the collector and log directories exist before any export is
        attempted. This prevents partially written output and keeps the sensor
        read-only apart from its own approved output locations.
    #>
    if (-not (Test-Path -LiteralPath $CollectedDir)) {
        New-Item -ItemType Directory -Path $CollectedDir -Force | Out-Null
    }

    if (-not (Test-Path -LiteralPath $LogsDir)) {
        New-Item -ItemType Directory -Path $LogsDir -Force | Out-Null
    }

    if (-not (Test-Path -LiteralPath $AuditLogPath)) {
        New-Item -ItemType File -Path $AuditLogPath -Force | Out-Null
    }

    if (-not (Test-Path -LiteralPath $AnomaliesLogPath)) {
        New-Item -ItemType File -Path $AnomaliesLogPath -Force | Out-Null
    }

    Write-Log -Level 'INFO' -Message 'Initialized output paths.'
}

function Test-ExecutionContext {
    <#
    .SYNOPSIS
        Verify that the current execution context is safe for collection.

    .DESCRIPTION
        Checks whether the script is running in production or test mode and
        logs a clear status message. The function does not change policy or
        elevate privileges; it only records whether the chosen mode is valid.
    #>
    if ($Mode -notin @('Production', 'Test')) {
        Write-Log -Level 'ERROR' -Message "Invalid mode selected: $Mode"
        throw 'Invalid mode'
    }

    Write-Log -Level 'INFO' -Message "Execution context accepted for mode: $Mode"
}

function Get-LocalIdentityData {
    <#
    .SYNOPSIS
        Collect local Windows user identity records.

    .DESCRIPTION
        Returns objects containing the local username, enabled state,
        administrator indicator, last logon, and source label. In test mode the
        function reads approved mock data; in production it uses Get-LocalUser
        when available and falls back to a controlled, empty result if the
        cmdlet is missing.
    #>
    if ($Mode -eq 'Test') {
        $testPath = Join-Path $TestsMockDataDir 'windows_identity.csv'
        Write-Log -Level 'INFO' -Message "Loading test identity data from $testPath"
        return Import-Csv -LiteralPath $testPath
    }

    if (-not (Get-Command Get-LocalUser -ErrorAction SilentlyContinue)) {
        Write-Log -Level 'WARNING' -Message 'Get-LocalUser is not available on this host.'
        return @()
    }

    $localUsers = Get-LocalUser -ErrorAction Stop
    $adminMembers = @()
    try {
        $adminMembers = Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop
    }
    catch {
        Write-Log -Level 'WARNING' -Message 'The local Administrators group could not be read.'
    }

    $adminNames = @($adminMembers | ForEach-Object { $_.Name })

    return $localUsers | ForEach-Object {
        [pscustomobject]@{
            ComputerName      = $env:COMPUTERNAME
            CollectionTime    = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
            Username          = $_.Name
            Enabled           = [bool]$_.Enabled
            IsLocalAdmin      = [bool]($adminNames -contains $_.Name)
            LastLogon         = if ($_.LastLogon) { $_.LastLogon.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } else { '' }
            Source            = 'local_user'
        }
    }
}

function Get-EventDataValue {
    <#
    .SYNOPSIS
        Read a named field from a Windows event record.

    .DESCRIPTION
        Converts the event to XML and extracts the requested event-data field.
        This avoids brittle positional parsing while still keeping the event
        collection bounded and read-only.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [object]$EventRecord,

        [Parameter(Mandatory = $true)]
        [string]$FieldName
    )

    try {
        [xml]$xmlEvent = $EventRecord.ToXml()
        foreach ($dataNode in $xmlEvent.Event.EventData.Data) {
            if ($dataNode.Name -eq $FieldName) {
                return [string]$dataNode.'#text'
            }
        }
    }
    catch {
        return ''
    }

    return ''
}

function Get-LocalAdminMembers {
    <#
    .SYNOPSIS
        Collect members of the local Administrators group.

    .DESCRIPTION
        Returns the current members as a list of names so the analysis pipeline
        can compare them against approved Windows admin baselines.
    #>
    if ($Mode -eq 'Test') {
        $testPath = Join-Path $TestsMockDataDir 'windows_identity.csv'
        $rows = Import-Csv -LiteralPath $testPath
        return @($rows | Where-Object { $_.IsLocalAdmin -eq 'True' } | Select-Object -ExpandProperty Username)
    }

    try {
        return @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop | Select-Object -ExpandProperty Name)
    }
    catch {
        Write-Log -Level 'WARNING' -Message 'The local Administrators group could not be read.'
        return @()
    }
}

function Get-WindowsSecurityEvents {
    <#
    .SYNOPSIS
        Collect Windows security-related Event Viewer records.

    .DESCRIPTION
        Uses Get-WinEvent when possible and handles permission failures with a
        controlled warning. In test mode the function returns approved mock
        event rows so the sensor does not touch real logs.
    #>
    if ($Mode -eq 'Test') {
        $testPath = Join-Path $TestsMockDataDir 'windows_events.csv'
        Write-Log -Level 'INFO' -Message "Loading test event data from $testPath"
        return Import-Csv -LiteralPath $testPath
    }

    $filter = @{
        LogName   = 'Security'
        Id        = 4624, 4625
        StartTime = $script:ResolvedStartTime
    }

    try {
        $rawEvents = Get-WinEvent -FilterHashtable $filter -MaxEvents $script:ResolvedMaxEvents -ErrorAction Stop
        $events = @(
            $rawEvents | ForEach-Object {
                [pscustomobject]@{
                    ComputerName    = $env:COMPUTERNAME
                    TimeCreated     = $_.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
                    EventId         = $_.Id
                    TargetUserName  = (Get-EventDataValue -EventRecord $_ -FieldName 'TargetUserName')
                    IpAddress       = (Get-EventDataValue -EventRecord $_ -FieldName 'IpAddress')
                    EventType       = if ($_.Id -eq 4625) { 'failed_login' } elseif ($_.Id -eq 4624) { 'successful_login' } else { 'security_event' }
                }
            }
        )
        Write-Log -Level 'INFO' -Message ("Collected {0} Windows Security events from Event IDs 4624 and 4625." -f $events.Count)
        return $events
    }
    catch {
        Write-Log -Level 'WARNING' -Message 'The Security event log could not be read.'
        return @()
    }
}

function Get-WindowsPolicyState {
    <#
    .SYNOPSIS
        Collect Windows policy state relevant to the risk model.

    .DESCRIPTION
        Returns firewall profile status, audit policy availability, and the
        PowerShell execution policy. Only policy-relevant values are recorded
        so the sensor remains tightly aligned to the project design.
    #>
    if ($Mode -eq 'Test') {
        $testPath = Join-Path $TestsMockDataDir 'windows_policy.csv'
        Write-Log -Level 'INFO' -Message "Loading test policy data from $testPath"
        return Import-Csv -LiteralPath $testPath
    }

    $policyRows = @()

    try {
        $firewallProfiles = Get-NetFirewallProfile -ErrorAction Stop
        foreach ($profile in $firewallProfiles) {
            $policyRows += [pscustomobject]@{
                ComputerName = $env:COMPUTERNAME
                CheckName    = 'firewall_enabled'
                Status       = [bool]$profile.Enabled
                Value        = if ($profile.Enabled) { 'Enabled' } else { 'Disabled' }
                RiskHint     = if ($profile.Enabled) { 'Expected' } else { 'Policy deviation' }
            }
        }
    }
    catch {
        Write-Log -Level 'WARNING' -Message 'Windows Firewall profiles could not be read.'
    }

    try {
        $executionPolicy = Get-ExecutionPolicy -Scope LocalMachine
        $policyRows += [pscustomobject]@{
            ComputerName = $env:COMPUTERNAME
            CheckName    = 'execution_policy'
            Status       = $executionPolicy -in @('RemoteSigned', 'AllSigned', 'Unrestricted')
            Value        = $executionPolicy
            RiskHint     = if ($executionPolicy -in @('RemoteSigned', 'AllSigned')) { 'Expected' } else { 'Policy deviation' }
        }
    }
    catch {
        Write-Log -Level 'WARNING' -Message 'The PowerShell execution policy could not be read.'
    }

    try {
        $auditPolicyOutput = & auditpol.exe /get /category:* 2>$null
        if ($auditPolicyOutput) {
            $policyRows += [pscustomobject]@{
                ComputerName = $env:COMPUTERNAME
                CheckName    = 'audit_policy_enabled'
                Status       = $true
                Value        = 'Available'
                RiskHint     = 'Expected'
            }
        }
        else {
            $policyRows += [pscustomobject]@{
                ComputerName = $env:COMPUTERNAME
                CheckName    = 'audit_policy_enabled'
                Status       = $false
                Value        = 'Unavailable'
                RiskHint     = 'Policy deviation'
            }
        }
    }
    catch {
        Write-Log -Level 'WARNING' -Message 'Audit policy could not be read.'
    }

    return $policyRows
}

function Export-IdentityCsv {
    <#
    .SYNOPSIS
        Export Windows identity records to CSV.

    .DESCRIPTION
        Writes the identity objects to the approved output location with clean
        headers so the downstream parser can validate them without ambiguity.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$InputObject
    )

    $InputObject | Export-Csv -LiteralPath $IdentityCsvPath -NoTypeInformation -Encoding UTF8
}

function Export-EventsCsv {
    <#
    .SYNOPSIS
        Export Windows event records to CSV.

    .DESCRIPTION
        Writes the security events collected by the sensor to the approved
        output location using the schema expected by the analysis pipeline.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$InputObject
    )

    $InputObject | Export-Csv -LiteralPath $EventsCsvPath -NoTypeInformation -Encoding UTF8
}

function Export-PolicyCsv {
    <#
    .SYNOPSIS
        Export Windows policy records to CSV.

    .DESCRIPTION
        Writes firewall, audit, and execution policy rows to the approved
        output location so the policy parser can compare them against baselines.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$InputObject
    )

    $InputObject | Export-Csv -LiteralPath $PolicyCsvPath -NoTypeInformation -Encoding UTF8
}

function Invoke-WindowsAudit {
    <#
    .SYNOPSIS
        Run the Windows identity audit sensor.

    .DESCRIPTION
        Orchestrates path initialization, execution context validation, data
        collection, and export. The function only writes approved output files
        and never performs remediation.
    #>
    Test-ExecutionContext
    Initialize-Paths
    Initialize-CollectionWindow
    Write-Log -Level 'INFO' -Message "Starting Windows identity audit sensor in $Mode mode."

    $script:LocalAdminMembers = Get-LocalAdminMembers
    $script:IdentityRecords = @(Get-LocalIdentityData)
    $script:EventRecords = @(Get-WindowsSecurityEvents)
    $script:PolicyRecords = @(Get-WindowsPolicyState)

    Export-IdentityCsv -InputObject $script:IdentityRecords
    Export-EventsCsv -InputObject $script:EventRecords
    Export-PolicyCsv -InputObject $script:PolicyRecords

    Write-Log -Level 'INFO' -Message 'Windows audit export completed successfully.'
}

Invoke-WindowsAudit
