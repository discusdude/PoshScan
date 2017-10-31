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
    $Timeout = 500
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
        if($Connected){
            $Port
        }
        else{
            $Connected
        }
    }
}

function Invoke-TypeScan{
<#=================================================================================================
.SYNOPSIS
    Asynchronously tests ports on a given Host (specified as an IP address) or performs an ARP
    request.

.DESCRIPTION
    Asynchronously calls the appropriate scan type to test the supplied ports or perform an ARP
    query on a single IP Address. If a connection fails, nothing is returned. Otherwise, it returns
    the result of function it calls.

.PARAMETER IpAddress
    Type: System.Net.IPAddress

    The IP address of the host that is going to be scanned.

.PARAMETER Port
    Type: uint16[]

    A unint16 array of ports to be scanned.

.PARAMETER Type
    Type: String

    A value constrained string declaring which type of scan to perform

.Example
    Invoke-TcpPortScan -IPAddress 204.79.197.200 -Port 80, 443

    80
    443

=================================================================================================#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [System.Net.IPAddress]$IpAddress,
        [Parameter(Position = 1)]
        [uint16[]]$Port = 80, #@(21,22,23,53,69,71,80,98,110,139,111,389,443,445,1080,1433,2001,2049,
        #3001,3128,5222,6667,6868,7777,7878,8080,1521,3306,3389,5801,5900,5555,5901)
        [Parameter(Mandatory = $true)]
        [ValidateSet("TCP", "ARP")]
        [String]$Type
    )
    #If arp request, ignore ports
    if($Type -eq "Arp"){
        $Port = 0
    }
    $OutPut = @()
    $ThisFile = "$PSScriptRoot\Start-PortScan.psm1"
    foreach ($p in $Port){
        while((Get-Job).count -ge 5){
            Start-Sleep -Milliseconds 100
            $CompletedJobs = Get-Job -State Completed
            foreach ($Job in $CompletedJobs){
                $Result = $Job | Receive-Job
                if($Result){
                    $OutPut += $Result
                }
                Remove-Job -Job $Job
            }
        }

        switch($Type){
            "Tcp" {
                $JobParams = @{
                    Name = $p
                    ArgumentList = @($IpAddress, $p, $ThisFile)
                    ScriptBlock = {
                        Import-Module $args[2]
                        Test-TcpPort -IpAddress $args[0] -Port $args[1]
                    }
                }
            }
            "Arp" {
                $JobParams = @{
                    Name = "Arp$IPAddress"
                    ArgumentList = @($IpAddress, $ThisFile)
                    ScriptBlock = {
                        Import-Module $args[1]
                        Send-ArpRequest -IpAddress $args[0]
                    }
                }
            }
        }

        
        Start-Job @JobParams | Out-Null
    }
    
    get-job | Wait-Job | Out-Null
    $CompletedJobs = get-job
    foreach ($Job in $CompletedJobs){
        $Result = $Job | Receive-Job
        if($Result){
            $OutPut += $Result
        }
        Remove-Job -Job $Job
    }
    $Obj = New-Object -Type PSObject -Property @{
        Type = $Type
        Output = $OutPut
    }
    $Obj
}

function Start-TypeScan {
<#=================================================================================================
.SYNOPSIS
    Scans a list of ports on a list of IP addresses.

.DESCRIPTION
    Scans a list of IP addresses and ports by asynchronously calling Invoke-TypeScan. It returns
    an object with the hosts' IP address and open ports or MAC Address.

.PARAMETER IpAddress
    Type: System.Net.IPAddress[]

    An array of IP addresses to be scanned.

.PARAMETER Port
    Type: uint16[]

    An array of ports to be tested

.PARAMETER Type
    Type: String

    A value constrained string declaring which type of scan to perform

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
        [uint16[]]$Port = 80,#@(21,22,23,53,69,71,80,98,110,139,111,389,443,445,1080,1433,2001,2049,
        #3001,3128,5222,6667,6868,7777,7878,8080,1521,3306,3389,5801,5900,5555,5901)
        [Parameter(Mandatory = $true)]
        [ValidateSet("TCP", "ARP")]
        [String]$Type
    )
    $ThisFile = "$PSScriptRoot\Start-PortScan.psm1"
    $ScanResults = @()
    get-job | Stop-Job
    get-job | Remove-Job
    foreach($i in $IpAddress){
        while((Get-Job).count -ge 5){
            Start-Sleep -Milliseconds 100
            $CompletedJobs = Get-Job -State Completed
            foreach ($Job in $CompletedJobs){
                $Result = $Job | Receive-Job
                if($Result){
                    $ObjectParams = @{
                        Host = $Job.Name
                        "$($Result.Type)Scan" = ($Result.Output | Out-String).Trim()
                    }
                    $ScanResults += New-Object -Type PSObject -Property $ObjectParams
                }
                Remove-Job -Job $Job
            }
        }
        $JobParams = @{
            Name = $i
            ArgumentList = @($i, $Port, $ThisFile, $Type)
            ScriptBlock = {
                Import-Module $args[2]
                Invoke-TypeScan -IpAddress $args[0] -Port $args[1] -Type $args[3]
            }
        }
        Write-Verbose "Creating job for $i."
        Start-Job @JobParams | Out-Null
    }

    Get-Job | Wait-Job | Out-Null
    $CompletedJobs = Get-Job
    foreach ($Job in $CompletedJobs){
        $Result = $Job | Receive-Job
        if($Result){
            $ObjectParams = @{
                Host = $Job.Name
                "$($Result.Type)Results" = ($Result.Output | Out-String).Trim()
            }
            $ScanResults += New-Object -Type PSObject -Property $ObjectParams
        }
        Remove-Job -Job $Job
    }
    $ScanResults
}

function Send-ArpRequest {
<#=================================================================================================
.SYNOPSIS
    Performs an Arp Request to obtain a target IP Address's MAC Address.

.DESCRIPTION
    Performs an Arp Request to obtain a target IP Address's MAC Address.

.PARAMETER IpAddress
    Type: System.Net.IPAddress

    The address of the target host.

.Example
    Send-ArpRequest -IpAddress 192.168.5.6

    AE:3A:32:8B:24:BA
=================================================================================================#>
    param(
        [Parameter(Mandatory=$true,Position=0)]
        [System.Net.IPAddress]$IpAddress
    )

    $NetTools = @" 
    [DllImport("iphlpapi.dll", ExactSpelling=true)] 
       public static extern int SendARP(  
           uint DestIP, uint SrcIP, byte[] pMacAddr, ref int PhyAddrLen); 
"@

    #---Import the SendARP function from iphelper dll----------------------------------------------
    Add-Type -MemberDefinition $NetTools -Name Utils -Namespace Network
    $MacTemp = New-Object Byte[] 6

    $Return = [Network.Utils]::SendARP($IpAddress.Address, 0, $MacTemp, [Ref]6) #[Ref]6 is MacTemp
                                                                                #array length.
    $MacAddress = @()
    if($Return -eq 0){
        foreach($Nibble in $MacTemp){
            $MacAddress += $Nibble.tostring('X2')
        }
        $MacAddress -join(':')
    }
    else{
        $false
    }
}