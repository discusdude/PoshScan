<#=================================================================================================
.SYNOPSIS
    Scanning functions for Start-PortScan.ps1

.DESCRIPTION
    This file is structured as it is with many similar functions to make job creation easier. Some
    functions create jobs to call another function, which in turn creates jobs to call other
    functions.

    This module contains the following functions:

    Test-TcpPort - Test a single TCP port on a given host.
    Invoke-TcpPortScan - Creates jobs to asynchronously scan ports on a single IP address. It calls
        Test-TcpPort
    Start-TcpPortScan - Creates jobs to asynchronously scan multiple IP addresses. It calls
        Invoke-TcpPortScan

=================================================================================================#>

function Test-TcpPort {
<#=================================================================================================
.SYNOPSIS
    Tests a single port on a single IP address to try to determine if it is open.
    
.DESCRIPTION
    Tests a single port on a single IP address to try to determine if it is open. It uses a timout
    of 1 second. Returns a bool: true if open and false if closed.

.PARAMETER IpAddress
    Type: System.Net.IPAddress

    The IP address of the host with the port to be tested.

.PARAMETER Port
    Type: uint16

    The Port that is going to be tested

.Example
    Test-TcpPort -IPAddress 127.0.0.1 -Port 80

    true
=================================================================================================#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,Position=0)]
        [System.Net.IPAddress]$IpAddress,
        [Parameter(Mandatory=$true,Position=1)]
        [uint16]$Port
    )
    $Timeout = 1000
    $TcpProbe = New-Object System.Net.Sockets.TcpClient
    $Connection = $TcpProbe.BeginConnect($IpAddress,$Port,$null,$null)  #Initiate asynchronous
                                                                        #connection
    $await = $Connection.AsyncWaitHandle.WaitOne($Timeout,$false)

    if(-not $await){
        $TcpProbe.Close()
        $false
    }
    else{
        $Connected = $TcpProbe.Connected
        $TcpProbe.Close()
        $Connected
    }
}

function Invoke-TcpPortScan{
<#=================================================================================================
.SYNOPSIS
    Asynchronously tests ports on a given Host (specified as an IP address)

.DESCRIPTION
    Asynchronously calls Test-TcpPort to test the supplied ports on a single IP Address. It returns
    the port number if it is open and ommits it if it is closed.

.PARAMETER IpAddress
    Type: System.Net.IPAddress

    The IP address of the host that is going to be scanned.

.PARAMETER Port
    Type: uint16[]

    A unint16 array of ports to be scanned.

.Example
    Invoke-TcpPortScan -IPAddress 204.79.197.200 -Port 80, 443

    80
    443

=================================================================================================#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,Position=0)]
        [System.Net.IPAddress]$IpAddress,
        [Parameter(Position=1)]
        [uint16[]]$Port = 80#@(21,22,23,53,69,71,80,98,110,139,111,389,443,445,1080,1433,2001,2049,
        #3001,3128,5222,6667,6868,7777,7878,8080,1521,3306,3389,5801,5900,5555,5901)
    )
    $OpenPorts = @()
    $ThisFile = "$PSScriptRoot\Start-PortScan.psm1"
    foreach ($p in $Port){
        while((Get-Job).count -ge 5){
            Start-Sleep 1
            $CompletedJobs = Get-Job -State Completed
            foreach ($Job in $CompletedJobs){
                $Result = $Job | Receive-Job
                if($Result){
                    $OpenPorts += $Job.Name
                }
                Remove-Job -Job $Job
            }
        }
        $JobParams = @{
            Name = $p
            ArgumentList = @($IpAddress, $p, $ThisFile)
            ScriptBlock = {
                Import-Module $args[2]
                Test-TcpPort -IpAddress $args[0] -Port $args[1]
            }
        }
        Start-Job @JobParams | Out-Null
    }
    
    get-job | Wait-Job | Out-Null
    $CompletedJobs = get-job
    foreach ($Job in $CompletedJobs){
        $Result = $Job | Receive-Job
        if($Result){
            $OpenPorts += $Job.Name
        }
        Remove-Job -Job $Job
    }

    $OpenPorts
}

function Start-TcpPortScan {
<#=================================================================================================
.SYNOPSIS
    Scans a list of ports on a list of IP addresses.

.DESCRIPTION
    Scans a list of IP addresses and ports by asynchronously calling Invoke-TcpPortScan. It returns
    an object with the hosts' IP address and open ports.

.PARAMETER IpAddress
    Type: System.Net.IPAddress[]

    An array of IP addresses to be scanned.

.PARAMETER Port
    Type: uint16[]

    An array of ports to be tested

.Example

    Start-TcpPortScan -IpAddress 204.79.197.200, 128.187.16.99 -Ports 80,443

    Host           OpenPorts
    ----           ---------
    128.187.16.99  80...
    204.79.197.200 80...
=================================================================================================#>
    param(
        [Parameter(Mandatory=$true,Position=0)]
        [System.Net.IPAddress[]]$IpAddress,
        [Parameter(Position=1)]
        [uint16[]]$Port = 80#@(21,22,23,53,69,71,80,98,110,139,111,389,443,445,1080,1433,2001,2049,
        #3001,3128,5222,6667,6868,7777,7878,8080,1521,3306,3389,5801,5900,5555,5901)
    )
    $ThisFile = "$PSScriptRoot\Start-PortScan.psm1"
    $ScanResults = @()
    get-job | Stop-Job
    get-job | Remove-Job
    foreach($i in $IpAddress){
        while((Get-Job).count -ge 5){
            (get-job).count
            Start-Sleep 1
            $CompletedJobs = Get-Job -State Completed
            foreach ($Job in $CompletedJobs){
                $Result = $Job | Receive-Job
                if($Result){
                    $ObjectParams = @{
                        Host = $Job.Name
                        OpenPorts = ($Result | Out-String).Trim()
                    }
                    $ScanResults += New-Object -Type PSObject -Property $ObjectParams
                }
                Remove-Job -Job $Job
            }
        }
        $JobParams = @{
            Name = $i
            ArgumentList = @($i, $Port, $ThisFile)
            ScriptBlock = {
                Import-Module $args[2]
                Invoke-TcpPortScan -IpAddress $args[0] -Port $args[1]
            }
        }
        Start-Job @JobParams | Out-Null
    }

    Get-Job | Wait-Job | Out-Null
    $CompletedJobs = Get-Job
    foreach ($Job in $CompletedJobs){
        $Result = $Job | Receive-Job
        if($Result){
            $ObjectParams = @{
                Host = $Job.Name
                OpenPorts = ($Result | Out-String).Trim()
            }
            $ScanResults += New-Object -Type PSObject -Property $ObjectParams
        }
        Remove-Job -Job $Job
    }
    $ScanResults
}