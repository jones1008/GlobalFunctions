<# 
.SYNOPSIS
Log file logger object to write and purge log files

.DESCRIPTION
Function that returns an object to write an purge logfiles. The object creates a new
log folder as a child object to the script execution folder. The log file folder
name can be set, default is "logs". If the folder does not exist it will be created.
Severity levels supported are:
0 : Info (default)
1 : Error
2 : Warning
The default retention time for log files is 30 days.
Copyright by Thomas Stensitzki (https://github.com/Apoc70)

.Write
Method to write messages with a given severity level to a log file, optionally write messages to the console output pipeline

.WriteEventLog
Method to write an event log entry to the local computer event log

.Purge
Method to purge log files older than log file retentionin days

.SendLogFile
Send the current logger log file as an email attachment

.PARAMETER ScriptRoot
The script folder the referencing script is being executing in. 
Example: $ScriptDir = Split-Path $script:MyInvocation.MyCommand.Path

.PARAMETER ScriptName
The name of the script referencing the function. This name is used for Windows event log purposes
Default = MyScriptName
Example: $ScriptName = $MyInvocation.MyCommand.Name

.PARAMETER LogFolder
Name of the log files folder 
Default = ''

.PARAMETER FileNameDate
Name pattern for the log file Prefix as date pattern. This parameter is using utilizing the datetime format notation
Default = yyyy-MM-ddTHH-mm

.PARAMETER FileName
Name pattern for after the Prefix specified in FileNameDate. If ".log" is not appended in given String it will be appended automatically.
Default = .log

.PARAMETER TimeFormat
DateTime format to be used as a line prefix when appending messages to the log file
Default = yyyy-MM-dd HH:mm

.PARAMETER LogFileRetention
Retention period in days for expired log files
Default = 90

.PARAMETER EventLogName
Name of the Windows Event Log events are written to.
Default = Application

.EXAMPLE
# Instantiate a new logger object using a log time renttion of 14 days
$ScriptDir = Split-Path $script:MyInvocation.MyCommand.Path
$logger = New-Logger -ScriptRoot $ScriptDir -ScriptName $ScriptName -LogFileRetention 14
    
.EXAMPLE
# Write a new informational message to the log
$logger.Write("My informational message")

.EXAMPLE
# Write a new warning message to the log
$logger.Write("My standard warning", 1)

.EXAMPLE
# Write a new error message to the log
$logger.Write("My critical error", 2)

.EXAMPLE
$logger.SendLogFile("sender@mcsmemail.de", "recipient@mcsmemail.de", "smtpserver.mcsmemail.de")

.EXAMPLE
# Purge log files
$logger.Purge()
#>
function New-Logger {
    param (
        [Parameter(Mandatory,HelpMessage='Absolute path to script folder')]
        [string]$ScriptRoot,
        [string]$ScriptName = 'MyScriptName',
        [string]$LogFolder = '',
        [string]$FileNameDate = 'yyyy-MM-ddTHH-mm',
        [string]$FileName = '.log',
        [string]$TimeFormat = 'yyyy-MM-dd HH:mm',
        [int]$LogFileRetention = 90,
        [string]$EventLogName = 'Application'
    )

    if($FileName -notmatch ".*?\.log$"){
        $FileName = $FileName + ".log"
    }
    $FileName = (Get-Date -Format $FileNameDate) + "_" + $FileName

    # create logger object
    $logger = New-Object -TypeName PSCustomObject
    # add logger properties
    $logger | Add-Member -MemberType NoteProperty -Name ScriptRoot -Value $ScriptRoot
    $logger | Add-Member -MemberType NoteProperty -Name ScriptName -Value $ScriptName
    $logger | Add-Member -MemberType NoteProperty -Name LogFolder -Value $('logs\'+$LogFolder)
    $logger | Add-Member -MemberType NoteProperty -Name FileNameDate -Value $FileNameDate
    $logger | Add-Member -MemberType NoteProperty -Name FileName -Value $FileName
    $logger | Add-Member -MemberType NoteProperty -Name TimeFormat -Value $TimeFormat
    $logger | Add-Member -MemberType NoteProperty -Name LogFileRetention -Value $LogFileRetention
    $logger | Add-Member -MemberType NoteProperty -Name EventLogName -Value $EventLogName

    # WRITE
    # Script method to write log messages to disk
    $logger | Add-Member -MemberType ScriptMethod -Name Write -Value {
        param (
            [Parameter(Mandatory,HelpMessage='A log message is required')]
            [string]$Message,
            [int]$Severity = 0,
            [switch]$WriteOnConsole
        )
        try {
            if ($WriteOnConsole) {
                Write-Output $Message
            }
            [string]$timeStamp = (Get-Date -Format $this.TimeFormat)
            [string]$folderPath = Join-Path -Path $this.ScriptRoot -ChildPath $this.LogFolder
            #[string]$file = (Get-Date -Format $this.FileNameDate) + $this.FileName
            [string]$file = $this.FileName
            [string]$filePath = Join-Path -Path $folderPath -ChildPath $file
      
            # log file line prefix
            $prefix = "$($timeStamp):"

            # map severity code to string value
            switch($Severity) {
                1 { [string]$SeverityString = 'WARN' }
                2 { [string]$SeverityString = 'ERROR' }
                default { [string]$SeverityString = 'INFO' } #0
            }

            # check if log directory exists
            if(!(Test-Path -Path $folderPath)) {
                # create log directory
                $null = New-Item -Path $folderPath -ItemType Directory
            }

            # define log line columns
            $col1 = $($prefix)
            $col2 = ([string]$PID).PadRight(10).Substring(0,10)
            $col3 = ([string]$SeverityString).PadRight(8).Substring(0,8)
            $col4 = $($Message)

            # check, if file exists
            if(!(Test-Path -Path $filePath)) {
                $null = New-Item -Path $filePath -ItemType File -Force
                $line ='TIMESTAMP       : PROCESS ID - SEVERITY - MESSAGE'
                Add-Content -Path $filePath -Value $line
            }
            # write message to file
            $line = "$($prefix) $($col2) - $($col3) - $($col4)"
            Add-Content -Path $filePath -Value $line
        }
        catch {}
    }

    # WRITEEVENTLOG
    # Script method to write messages to event log
    $logger | Add-Member -MemberType ScriptMethod -Name WriteEventLog -Value {
        param (
            [Parameter(Mandatory,HelpMessage='A log message is required')]
            [string]$Message,
            [int]$Severity = 0 
        )
        try {
            # Create new event log source first. Without event log source we cannot write to event log
            New-EventLog -LogName $this.EventLogName -Source $this.ScriptName

            # map severity code to string value
            switch($Severity) {
                1 { [string]$SeverityString = 'Error' }
                2 { [string]$SeverityString = 'Warning' }
                default { [string]$SeverityString = 'Information' } #0
            }

            Write-EventLog -LogName $this.EventLogName -Source $this.ScriptName -EntryType $SeverityString  -EventId $Severity -Message $Message             
        }
        catch {
            $this.Write("Error writing to event log. Error: $($Error)")           
        }
    }

    # PURGE
    # Script method to purge aged log files from disk
    $logger | Add-Member -MemberType ScriptMethod -Name Purge -Value {
        [CmdletBinding()]
        param (
            [switch]$Detailed
        )
        [string]$timeStamp = (Get-Date -Format $this.TimeFormat)
        [string]$folderPath = Join-Path -Path $this.ScriptRoot -ChildPath $this.LogFolder
        try {
            # fetch list of log files
            $logFiles = Get-ChildItem -Path $folderPath | Where-Object{$_.LastWriteTimeUtc.Date -le ([datetime]::UtcNow.AddDays(-($this.LogFileRetention))).Date}
            # write summary to log file
            if($logFiles.Count -ne 0){
                $this.Write("Deleting $($logFiles.Count) log files older than $($this.LogFileRetention) days")

                foreach($file in $logFiles) {
                    Remove-Item -Path $file.FullName -Confirm:$false
                }
            }
        }
        catch {}
    }

    # COPYFILE
    # Script method to copy a file to sub folder
    $logger | Add-Member -MemberType ScriptMethod -Name CopyFile -Value {
        param (
            [Parameter(Mandatory,HelpMessage='Source file path is required')]
            [string]$SourceFilePath,
            [Parameter(Mandatory,HelpMessage='Target file path is required')]
            [string]$RepositoryFolderName
        )
        try {
            [string]$folderPath = Join-Path -Path $this.ScriptRoot -ChildPath $RepositoryFolderName
            [string]$sourceFileName = Split-Path -Path $SourceFilePath -Leaf

            # check if repository directory exists
            if(!(Test-Path -Path $folderPath)) {
                # create log directory
                $null = New-Item -Path $folderPath -ItemType Directory
                $this.Write("$($folderPath) folder created")
            }            

            if(Test-Path -Path $SourceFilePath) {
                $this.Write("Moving $($SourceFilePath) to $(Join-Path -Path $folderPath -ChildPath $sourceFileName)")
                Move-Item -Path $SourceFilePath -Destination (Join-Path -Path $folderPath -ChildPath $sourceFileName)
            }
            else {
                $this.Write("$($folderPath) does not exist and cannot be copied",2)
            }
        }
        catch {}
    }

    # SENDLOGFILE
    # Script method to send log file via email
    $logger | Add-Member -MemberType ScriptMethod -Name SendLogFile -Value {
        param (
            [Parameter(Mandatory,HelpMessage='Sender address is required')]
            [string]$From,
            [Parameter(Mandatory,HelpMessage='Recipient address is required')]
            [string]$To,
            [Parameter(Mandatory,HelpMessage='Smtp server address is required')]
            [string]$SmtpServer
        )
        try {
            [string]$timeStamp = (Get-Date -Format $this.TimeFormat)
            [string]$folderPath = Join-Path -Path $this.ScriptRoot -ChildPath $this.LogFolder
            #[string]$file = (Get-Date -Format $this.FileNameDate) + $this.FileName
            [string]$file = $this.FileName
            [string]$filePath = Join-Path -Path $folderPath -ChildPath $file

            [string]$subject = "Requested Log File ($($this.ScriptName))"
            [string]$body = "<html>
            <body>
            <font size=""1"" face=""Arial,sans-serif"">
            <p2>Please find the requested log file $($filePath) attached to this email.</p>
            </font>
            </body>"

            # Write mail action to log file first
            $this.Write("Sending log file from $($From) to $($To) via $($SmtpServer)")

            # Send mail message
            Send-MailMessage -SmtpServer $SmtpServer -From $From -To $To -Subject $subject -Body $body -BodyAsHtml -Attachments $filePath
        }
        catch {}
    }

    # return object
    return $logger
}

# export all functions (append new ones here!)
Export-ModuleMember -Function Remove-SpecialChars
Export-ModuleMember -Function New-Logger
