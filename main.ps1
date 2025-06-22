<#
.SYNOPSIS
    Automated log parser and GELF forwarder to Graylog.
.DESCRIPTION
    Scans log files, parses key information (IP, timestamp, etc.), avoids duplicates,
    formats in GELF JSON, and sends to Graylog.
.NOTES
    Author: Mustapha EL BAKAI
    Email: m.elbakai@gmail.com
    License: MIT
#>

# forces PowerShell to use Transport Layer Security (TLS) 1.2 for all outbound HTTPS connections
# [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$server = "127.0.0.1"
$logFolder = "D:\graylog\logs"
$uri = "http://localhost:12201/gelf"
$archiveSuffix = ".done.txt"
$errorLogFile = "D:\graylog\logs\logs_failed.txt"
$today = (Get-Date).ToString("yyyy-MM-dd")

$counter = 0
$sentCount = 0
$skippedCount = 0
$hashCache = @{}

# Fonction de hash SHA1 pour anti-doublon
function Get-Hash($text) {
    $sha1 = [System.Security.Cryptography.SHA1]::Create()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($text)
    $hash = $sha1.ComputeHash($bytes)
    return ([BitConverter]::ToString($hash)).Replace("-", "").ToLower()
}

# Error logging
function logParsingError {
    param (
        [string]$logFilePath,   # Log output file
        [string]$blockContent,  # Error block content
        [string]$errorMessage   # Error message or reason for skipping
    )

    $separator = '>' * 60
    $footer    = '<' * 60

    try {
        Add-Content -Path $logFilePath -Value $separator
        Add-Content -Path $logFilePath -Value "Unparsed block :"
        Add-Content -Path $logFilePath -Value $blockContent
        Add-Content -Path $logFilePath -Value ""
        Add-Content -Path $logFilePath -Value "Reason: $errorMessage"
        Add-Content -Path $logFilePath -Value $footer
        Add-Content -Path $logFilePath -Value ""
        Write-Host "[logErrorParse] $errorMessage" -ForegroundColor DarkRed
    } catch {
        Write-Host "[logErrorParse] Unable to write in $logFilePath : $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# Display the values
function logParsedBlock {
    param (
        [string]$ip,
        [string]$timestamp,
        [datetime]$datetime,
        [string]$level,
        [string]$exception,
        [string]$message,
        [string]$url
    )

    Write-Host "`n>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
    Write-Host "IP        : $ip"
    Write-Host "Timestamp : $timestamp"
    Write-Host "Datetime  : $datetime"
    Write-Host "Level     : $level"
    Write-Host "Exception : $exception"
    Write-Host "Message   : $message"
    Write-Host "URL       : $url"
    Write-Host "//////////////////////////////////////"
}

# Loop through all .log files in the folder
# Where-Object { $_.Extension -ne ".txt" -and $_.Name -notlike "*_hashing.txt" -and $_.Name -notlike "*_parsing.txt" }
Get-ChildItem -Path $logFolder -Filter "error.log.*" | Where-Object { $_.Extension -ne ".txt"} | ForEach-Object {
    # log filename
    $logFile = $_.FullName
    Write-Host "File processing: $logFile"

    try {
        # Read the entire file as plain text
        $content = Get-Content -Path $logFile -Raw
    } catch {
        Add-Content -Path $errorLogFile -Value "ERROR - Unable to read : $logFile"
        return
    }

    # log filebase
    $logFileBase = (Get-Item $logFile).Name
    $logHashFile = "$logFolder\$($logFileBase)_hashing.txt"
    $logParsingErrorFile = "$logFolder\$($logFileBase)_parsing.txt"
    $newHashes = @()

    # Read the file if it exists
    if (Test-Path $logHashFile) {
        Get-Content $logHashFile | ForEach-Object {
            $hash = $_.Trim()
            if ($hash -ne "") {
                $hashCache[$hash] = $true
            }
        }
    }

    # Split log blocks based on timestamp
    $blocks = $content -split '(?m)^(?=.*\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})'

    foreach ($block in $blocks) {
        $block = $block.Trim()

        # Clean up empty blocks
        if ($block -eq "") { continue }
        if ([string]::IsNullOrWhiteSpace($block)) { continue }

        # Duplicate prevention
        $hashedLogId = Get-Hash $block
        if ($hashCache.ContainsKey($hashedLogId)) {
            $skippedCount++
            logParsingError -logFilePath $logParsingErrorFile -blockContent $block -errorMessage "Block ignored: Already indexed."
            continue
        } else {
            $newHashes += $hashedLogId
        }

        # Variables initialization
        $ip = $timestamp = $datetime = $level = $exception = $message = $url = $null

        # IP extraction
        if ($block -match '(?<ip>\b\d{1,3}(?:\.\d{1,3}){3}\b)') {
            $ip = $matches.ip
        } elseif ($block -match '(?<ip>\b(?:[A-Fa-f0-9]{1,4}:){1,7}[A-Fa-f0-9]{1,4}|::1\b)') {
            $ip = $matches.ip
        } else {
            logParsingError -logFilePath $logParsingErrorFile -blockContent $block -errorMessage "Block ignored: No IP address detected."
            $skippedCount++
            continue
        }

        # Timestamp
        if ($block -match "(?<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})") {
            $timestamp = $matches.ts
            try {
                $datetime = Get-Date $timestamp
            } catch {
                logParsingError -logFilePath $logParsingErrorFile -blockContent $block -errorMessage "Block skipped: Unable to convert timestamp."
                $skippedCount++
                continue
            }
        } else {
            logParsingError -logFilePath $logParsingErrorFile -blockContent $block -errorMessage "Block skipped: Unable to extract timestamp."
            $skippedCount++
            continue
        }

        # Uncomment the lines below to process only today's logs
        #if ($datetime.ToString("yyyy-MM-dd") -ne $today) {
        #    $skippedCount++
        #    continue
        #}

        # Niveau de log
        if ($block -match "(?<level>Error|Warning|Info|Debug|Notice|Critical|Alert|Emergency):") {
            $level = $matches.level
            $levelMap = @{
                "Emergency" = 0; "Alert" = 1; "Critical" = 2; "Error" = 3;
                "Warning" = 4; "Notice" = 5; "Info" = 6; "Debug" = 7
            }
            $level = $levelMap[$level]
        } else {
            logParsingError -logFilePath $logParsingErrorFile -blockContent $block -errorMessage "Block skipped: Unable to extract level."
            $skippedCount++
            continue
        }

        # Exception
        if ($block -match '\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} \w+: \[(?<exception>[^\]]+)\]') {
            $exception = $matches.exception
        } else {
            $exception = '---'
            logParsingError -logFilePath $logParsingErrorFile -blockContent $block -errorMessage "Unable to extract exception, replaced by ---."
            $skippedCount++
        }

        # Message
        if ($block -match '\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} \w+: (?<message>.+)') {
            $message = $matches.message
        } else {
            logParsingError -logFilePath $logParsingErrorFile -blockContent $block -errorMessage "Block skipped: Unable to extract message."
            $skippedCount++
            continue
        }

        # URL (facultatif)
        if ($block -match "Request URL: (?<url>\S+)") {
            $url = $matches.url
        } else {
            $url = "No URL"
            logParsingError -logFilePath $logParsingErrorFile -blockContent $block -errorMessage "Block ignored: Missing URL, replaced by No URL."
            $skippedCount++
        }

        # Uncomment the line below to display parsed log information
        # logParsedBlock -ip $ip -timestamp $timestamp -datetime $datetime -level $level -exception $exception -message $message -url $url

        # Calculate UNIX timestamp
        $unixTimestamp = [math]::Round((($datetime.ToUniversalTime()) - [datetime]'1970-01-01').TotalSeconds, 3)

        # GELF JSON construction
        $body = @{
            version = "1.1"
            host = $server
            short_message = "${exception}: $message"
            full_message = $block
            timestamp = $unixTimestamp
            level = $level
            _ip = $ip
            _url = $url
            _exception_class = $exception
            _datetime = $datetime.ToString("yyyy-MM-dd HH:mm:ss")
            _log_id = $hashedLogId
        } | ConvertTo-Json -Depth 10 -Compress

        # Push GELF message to Graylog
        try {
            Invoke-RestMethod -Method Post -Uri $uri -Body $body -ContentType "application/json"
            $sentCount++
            $counter++
        } catch {
            $skippedCount++
            Write-Host "`nError sent: $($_.Exception.Message)"
        }

        if ($counter % 100 -eq 0) {
            Start-Sleep -Milliseconds 100
        }
    }

    # Save hash keys used for duplicate detection
    try {
        if ($newHashes.Count -gt 0) {
            $newHashes | Add-Content -Encoding UTF8 -Path $logHashFile
        }
    } catch {
        Add-Content -Path $errorLogFile -Value "Error saving hash : $logFile"
    }

    # Archiver le fichier traité
    try {
        Rename-Item -Path $logFile -NewName ($logFile + $archiveSuffix)
    } catch {
        Add-Content -Path $errorLogFile -Value "Failed to rename the file : $logFile"
    }
}

# Summary
Write-Host "`nProcessing complete."
Write-Host "Logs sent : $sentCount"
Write-Host "Logs ignored : $skippedCount"
Write-Host "Errors in : $errorLogFile"
