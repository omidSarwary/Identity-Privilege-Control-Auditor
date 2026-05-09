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
$script:IdentityHeaders = @('ComputerName', 'CollectionTime', 'Username', 'Enabled', 'IsLocalAdmin', 'LastLogon', 'Source')
$script:EventHeaders = @('ComputerName', 'TimeCreated', 'EventId', 'TargetUserName', 'IpAddress', 'EventType')
$script:PolicyHeaders = @('ComputerName', 'CheckName', 'Status', 'Value', 'RiskHint')

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

function Write-RecordsCsv {
    <#
    .SYNOPSIS
        Write a collection to CSV with a stable schema.

    .DESCRIPTION
        Handles empty collections by creating a header-only file so the sensor
        can still complete safely when no rows are returned in the selected
        time window.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$InputObject,

        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string[]]$Headers
    )

    $writeStarted = Get-Date
    try {
        if (-not $InputObject -or $InputObject.Count -eq 0) {
            Set-Content -Path $Path -Value ($Headers -join ',') -Encoding UTF8
        }
        else {
            $InputObject | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8
        }
    }
    catch {
        Write-Log -Level 'ERROR' -Message ("CSV export failed for {0}: {1}" -f $Path, $_.Exception.Message)
        throw
    }

    if (-not (Test-Path -LiteralPath $Path)) {
        $message = "CSV export did not create expected file: $Path"
        Write-Log -Level 'ERROR' -Message $message
        throw $message
    }

    $writtenFile = Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($writtenFile.LastWriteTime -lt $writeStarted.AddSeconds(-2)) {
        $message = "CSV export did not update expected file in this run: $Path"
        Write-Log -Level 'ERROR' -Message $message
        throw $message
    }

    Write-Log -Level 'INFO' -Message ("CSV export completed: {0}" -f $Path)
}

function ConvertTo-LocalAdminUserName {
    <#
    .SYNOPSIS
        Normalize an administrator group member into a local username.

    .DESCRIPTION
        Accepts names returned by Get-LocalGroupMember, ADSI, or net.exe. SID
        values are logged and skipped because the current CSV schema stores
        usernames, not unresolved security identifiers.
    #>
    param(
        [string]$RawName,

        [string]$Source
    )

    if ([string]::IsNullOrWhiteSpace($RawName)) {
        return $null
    }

    $candidate = $RawName.Trim()
    if ($candidate -match '^S-\d-\d+(-\d+)+$') {
        Write-Log -Level 'WARNING' -Message ("Unresolved administrator SID skipped from {0}: {1}" -f $Source, $candidate)
        return $null
    }

    if ($candidate -like 'WinNT://*') {
        $candidate = ($candidate -split '/')[-1]
    }

    if ($candidate -like '*\*') {
        $candidate = ($candidate -split '\\')[-1]
    }

    if ([string]::IsNullOrWhiteSpace($candidate)) {
        return $null
    }

    return $candidate.Trim()
}

function Add-AdminMemberCandidate {
    <#
    .SYNOPSIS
        Add one normalized administrator name to a lookup table.

    .DESCRIPTION
        Keeps administrator membership de-duplicated case-insensitively so
        different fallback methods can be combined safely.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Lookup,

        [string]$RawName,

        [string]$Source
    )

    $name = ConvertTo-LocalAdminUserName -RawName $RawName -Source $Source
    if ($null -eq $name) {
        return
    }

    $key = $name.ToLowerInvariant()
    if (-not $Lookup.ContainsKey($key)) {
        $Lookup[$key] = $name
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

    Write-Log -Level 'INFO' -Message 'Windows identity collection started.'
    if (-not (Get-Command Get-LocalUser -ErrorAction SilentlyContinue)) {
        Write-Log -Level 'WARNING' -Message 'Get-LocalUser is not available on this host.'
        return @()
    }

    try {
        $localUsers = Get-LocalUser -ErrorAction Stop
    }
    catch {
        $message = $_.Exception.Message
        Write-Log -Level 'WARNING' -Message "Local Windows users could not be read. Administrator rights may be required. $message"
        return @()
    }

    $adminLookup = @{}
    foreach ($adminName in @($script:LocalAdminMembers)) {
        if (-not [string]::IsNullOrWhiteSpace($adminName)) {
            $adminLookup[$adminName.ToLowerInvariant()] = $true
        }
    }

    $records = @($localUsers | ForEach-Object {
        $username = [string]$_.Name
        [pscustomobject]@{
            ComputerName      = $env:COMPUTERNAME
            CollectionTime    = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
            Username          = $username
            Enabled           = [bool]$_.Enabled
            IsLocalAdmin      = [bool]$adminLookup.ContainsKey($username.ToLowerInvariant())
            LastLogon         = if ($_.LastLogon) { $_.LastLogon.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } else { '' }
            Source            = 'local_user'
        }
    })

    Write-Log -Level 'INFO' -Message ("Windows identity collection completed: {0} user(s)." -f $records.Count)
    return $records
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

    Write-Log -Level 'INFO' -Message 'Windows local administrator collection started.'
    $memberLookup = @{}

    try {
        $members = @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop)
        foreach ($member in $members) {
            Add-AdminMemberCandidate -Lookup $memberLookup -RawName ([string]$member.Name) -Source 'Get-LocalGroupMember'
        }
        Write-Log -Level 'INFO' -Message ("Windows local administrator collection completed with Get-LocalGroupMember: {0} member(s)." -f $memberLookup.Count)
    }
    catch {
        $message = $_.Exception.Message
        Write-Log -Level 'WARNING' -Message "Get-LocalGroupMember could not read the local Administrators group. Falling back to ADSI and net localgroup. $message"

        try {
            $adsiGroup = [ADSI]("WinNT://{0}/Administrators,group" -f $env:COMPUTERNAME)
            $adsiMembers = @($adsiGroup.psbase.Invoke('Members'))
            foreach ($member in $adsiMembers) {
                $name = $null
                try {
                    $name = [string]$member.GetType().InvokeMember('Name', 'GetProperty', $null, $member, $null)
                }
                catch {
                    try {
                        $name = [string]$member.GetType().InvokeMember('ADsPath', 'GetProperty', $null, $member, $null)
                    }
                    catch {
                        Write-Log -Level 'WARNING' -Message ("ADSI administrator member could not be resolved: {0}" -f $_.Exception.Message)
                    }
                }
                Add-AdminMemberCandidate -Lookup $memberLookup -RawName $name -Source 'ADSI'
            }
            Write-Log -Level 'INFO' -Message ("ADSI administrator fallback returned {0} normalized member(s)." -f $memberLookup.Count)
        }
        catch {
            Write-Log -Level 'WARNING' -Message ("ADSI administrator fallback failed: {0}" -f $_.Exception.Message)
        }

        try {
            $netOutput = & net.exe localgroup Administrators 2>&1
            $insideMembers = $false
            foreach ($line in @($netOutput)) {
                $text = [string]$line
                if ($text -match '^-{3,}$') {
                    $insideMembers = -not $insideMembers
                    continue
                }
                if (-not $insideMembers) {
                    continue
                }
                if ($text -match 'The command completed successfully|Kommandot slutfördes') {
                    break
                }
                Add-AdminMemberCandidate -Lookup $memberLookup -RawName $text -Source 'net localgroup'
            }
            Write-Log -Level 'INFO' -Message ("net localgroup administrator fallback returned {0} normalized member(s)." -f $memberLookup.Count)
        }
        catch {
            Write-Log -Level 'WARNING' -Message ("net localgroup administrator fallback failed: {0}" -f $_.Exception.Message)
        }
    }

    $resolvedMembers = @($memberLookup.Values | Sort-Object)
    if ($resolvedMembers.Count -eq 0) {
        Write-Log -Level 'WARNING' -Message 'No local administrator members could be resolved from any collection method.'
    }
    else {
        Write-Log -Level 'INFO' -Message ("Windows local administrator collection completed: {0} resolved member(s)." -f $resolvedMembers.Count)
    }
    return $resolvedMembers
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

    Write-Log -Level 'INFO' -Message ("Windows Security event collection started. LogHours={0}, MaxEvents={1}, StartTime={2}, EventIds=4624,4625" -f $script:ResolvedLogHours, $script:ResolvedMaxEvents, $script:ResolvedStartTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
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
        if ($events.Count -eq 0) {
            Write-Log -Level 'INFO' -Message 'No Windows Security events matched the selected time window and event IDs.'
        }
        else {
            Write-Log -Level 'INFO' -Message ("Collected {0} Windows Security events from Event IDs 4624 and 4625." -f $events.Count)
        }
        return $events
    }
    catch {
        $message = $_.Exception.Message
        if ($message -match 'Access is denied|permission denied') {
            Write-Log -Level 'WARNING' -Message "The Security event log could not be read. Administrator rights may be required. $message"
        }
        else {
            Write-Log -Level 'WARNING' -Message "The Security event log could not be read. $message"
        }
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

    Write-Log -Level 'INFO' -Message 'Windows policy collection started.'
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
        $message = $_.Exception.Message
        Write-Log -Level 'WARNING' -Message "Windows Firewall profiles could not be read. Administrator rights may be required. $message"
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
        $message = $_.Exception.Message
        Write-Log -Level 'WARNING' -Message "The PowerShell execution policy could not be read. $message"
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
        $message = $_.Exception.Message
        Write-Log -Level 'WARNING' -Message "Audit policy could not be read. Administrator rights may be required. $message"
    }

    Write-Log -Level 'INFO' -Message ("Windows policy collection completed: {0} row(s)." -f $policyRows.Count)
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
        [AllowEmptyCollection()]
        [object[]]$InputObject
    )

    Write-RecordsCsv -InputObject $InputObject -Path $IdentityCsvPath -Headers $script:IdentityHeaders
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
        [AllowEmptyCollection()]
        [object[]]$InputObject
    )

    Write-RecordsCsv -InputObject $InputObject -Path $EventsCsvPath -Headers $script:EventHeaders
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
        [AllowEmptyCollection()]
        [object[]]$InputObject
    )

    Write-RecordsCsv -InputObject $InputObject -Path $PolicyCsvPath -Headers $script:PolicyHeaders
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
    Write-Log -Level 'INFO' -Message ("Windows collection summary: identity={0}, events={1}, policy={2}" -f $script:IdentityRecords.Count, $script:EventRecords.Count, $script:PolicyRecords.Count)

    Export-IdentityCsv -InputObject $script:IdentityRecords
    Export-EventsCsv -InputObject $script:EventRecords
    Export-PolicyCsv -InputObject $script:PolicyRecords

    Write-Log -Level 'INFO' -Message 'Windows audit export completed successfully.'
}

Invoke-WindowsAudit
