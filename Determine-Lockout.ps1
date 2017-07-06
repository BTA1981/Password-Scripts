<#
.SYNOPSIS
    Get-LockedOutUser.ps1 returns a list of users who were locked out in Active Directory.
.DESCRIPTION
    Get-LockedOutUser.ps1 is an advanced script that returns a list of users who were locked out in Active Directory
    by querying the event logs on a DC.

    Prerequisite is to enable Auditing on the right account events:
    Computer Configuration > Policies → Windows Settings → Security Settings → Advanced Audit Policy Configuration → Audit Policies → 
    Account Management: Audit User Account Management → Define → Success and Failures.
.PARAMETER UserName
    The userid of the specific user you are looking for lockouts for. The default is all locked out users.
.PARAMETER StartTime
    The datetime to start searching from. The default is all datetimes that exist in the event logs.
.NOTES
  Version:        1.0
  Author:         Bart Tacken - Client ICT Groep
  Creation Date:  21-02-2017
  Purpose/Change: Initial script development
.EXAMPLE
    .\Determine-AccountLockouts.ps1 -DCs "SRVADC11","SRVADC12" -NumberOfDays 5
#>
#-----------------------------------------------------------[Execution]------------------------------------------------------------
Param(
    [Parameter(Mandatory=$True)] # List domain controllers that need to be investigated
    [array]$DCs, # "SRVADC11","SRVADC12"

    [Parameter(Mandatory=$True)] # Enter the number of days to search for. (5 for searching logs for events of the last five days)
    [int]$NumberOfDays # 5
)

$EventArray = @()
[datetime]$Today = (Get-Date)    
[datetime]$StartTime = (Get-Date).AddDays(-$NumberOfDays)

    # Cycle through each domain controller and get all eventlogs in an array
    ForEach ($DC in $DCs) {
	    Write-Output "Getting security events for Domain Controller [$DC].."
        $events = Get-WinEvent -FilterHashtable @{LogName='Security';Id = 4740;StartTime=$StartTime} -ComputerName $DC
        ForEach ($event in $events) {
            $EventArray += New-Object -TypeName PSObject -Property @{ # Fill Array with custom objects
                'TimeCreated' = $($Event.TimeCreated)
                'UserName' = $($Event.Properties[0].Value)
                'ClientName' = $($Event.Properties[1].Value)
            } # End PS Object
        } # End ForEach
        $events = $null
    }
    Write-Output "Display all Locked events from [$StartTime] to [$Today].."
    $EventArray | Sort-Object TimeCreated | Select-Object TimeCreated, UserName, ClientName
# Determine-LockoutFunction -DCs "SRVADC11,SRVADC12" -Username * -History $NumberOfDays





