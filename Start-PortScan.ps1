<#=================================================================================================
.SYNOPSIS
    Asynchronously scan specified hosts and ports using TCP

.DESCRIPTION
    Takes input either as a text file, IP address range via CIDR notation, or a start address and
    end address. It then asynchronously scans 5 addresses at a time and 5 simultaneious ports per
    address for a total of 25 simultaneous ports. It will then display PSObject results or export
    the results as html, csv, xml, or json depending on the specified result type. It will only
    include hosts responded on a port.

    The functions that it uses are located in the Start-PortScan.psm1 file.

.PARAMETER Type
    Type: String

    In a future version, this will specify the type of scan to be performed (ICMP, TCP, UDP, ARP)
    and will be constrained to those options. Currenlty, TCP is the only valid option.

.PARAMETER StartAddress
    Type: String

    Specifies the start address of an IP address range or specifies a an IP address and its subnet
    in CIDR notation. If used with the "InputFile" parameter, it will be ignored. If it is not in
    CIDR notation, "EndAddress" will be expected. If it is in CIDR notation, it will ignore the
    "EndAddress" parameter and calculate the IP address range from the CIDR prefix. Acceptible
    formats are "192.168.2.5" and "192.168.25.2/27."

.PARAMETER EndAddress
    Type: String

    Specifies the end address of an IP address range. It is ignored if "StartAddress" is in CIDR
    notation or if "InputFile" is used.

.PARAMETER Port
    Type: String Array

    Specifies which ports should be scanned. If none are supplied, a default array of some well
    known ports will be used. Accepts comma separated port numbers and ranges.
    
    Example 1: 556, 25, 22, 80, 443

    Example 2: 22, 23, 90-102

.PARAMETER ReportType
    Type: String

    ReportType is constrained to the values "None", "HTML", "CSV", "XML", and "JSON." If this
    parameter is ommited or given the value "None" then the script will display the results of the
    scan on the terminal. If any other valid value is given, an appropriate file will be created in
    the current working directory. It will be named with the time of completion for the scan and
    the appropriate file extension.

.PARAMETER InputFile
    Type: String

    The path to a .txt or .csv file containing the IP addresses to scan. Will override
    "StartAddress" and "EndAddress"

.EXAMPLE
    Start-PortScan -StartAddress 192.168.2.0 -EndAddress 192.168.3.0 -Port 80, 443

    Host           TCPResults
    ----           ----------
    192.168.2.15   80, 443
    192.168.2.16   80, 443
    192.168.2.26   80
    192.168.2.200  443

.EXAMPLE
    Start-PortScan -StartAddress 192.168.2.5/24 -Port 80, 443
    
    Host           TCPResults
    ----           ----------
    192.168.2.15   80, 443
    192.168.2.16   80, 443
    192.168.2.26   80
    192.168.2.200  443

.EXAMPLE
    Start-PortScan -InputFile .\address.txt -Port 80,443 -Type tcp

    Host           TCPResults
    ----           ----------
    128.187.16.99  80, 443
    204.79.197.200 80, 443

.EXAMPLE
    Start-PortScan -InputFile .\address.txt -Port 80,443 -Type tcp -ReportType HTML

    This will create an HTML document in the current working directory with a table of the results.

.EXAMPLE
    Start-PortScan -InputFile .\address.txt -Type ARP

    Host           ARPResults
    ----           ----------
    192.168.111.1  AB:CD:EF:12:34:56
    192.168.123.6  AB:CD:EF:12:34:55
    
=================================================================================================#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet("TCP","ARP")]
    [String]$Type = "TCP",
    [Parameter()]
    [String]$StartAddress,
    [Parameter()]
    [String]$EndAddress,
    [Parameter()]
    [string[]]$Port = @(21, 22, 23, 53, 69, 71, 80, 98, 110, 139, 111, 389, 443, 445, 1080, 1433,
        2001, 2049, 3001, 3128, 5222, 6667, 6868, 7777, 7878, 8080, 1521, 3306, 3389, 5801, 5900,
        5555, 5901),
    [Parameter()]
    [ValidateSet("None", "HTML", "CSV", "XML", "JSON")]
    [String]$ReportType = "None",
    [Parameter()]
    [validatescript( {Test-Path $PSItem})]
    [string]$InputFile
)

<#-------------------------------------------------------------------------------------------------
Validate Parameters and set up environment
-------------------------------------------------------------------------------------------------#>
begin {
    Import-Module "$PSScriptRoot\Start-PortScan.psm1" -Force

    $TempErrorAction = $ErrorActionPreference
    $ErrorActionPreference = "Stop"

    $ArrayList = @()                                            #Array to hold IP Addresses
    [uint16[]]$Ports = @()                                      #Array for ports
    if ($StartAddress -like "255.255.255.255*") {
        throw "Invalid IP Address"
    }
    
    <#---------------------------------------------------------------------------------------------
    Generate Port List, IP Address Range, import list, populate address array
    ---------------------------------------------------------------------------------------------#>
    #---Parse through supplied ports---------------------------------------------------------------
    foreach ($p in $Port) {
        try {
            if ($p -like "*-*") {
                $p.split('-')[0]..$p.split('-')[1] | ForEach-Object {
                    $Ports += $PSItem
                }
            }
            else {
                $Ports += $p
            }
        }
        catch {
            Write-Warning ("Procesing ports failed with the following error. A port or range is " +
                "likely invalid.")
            Write-Error $Error
            exit
        }
    }

    #---Import IP Addresses from text file---------------------------------------------------------
    if ($InputFile) {
        if ($StartAddress -or $EndAddress) {
            Write-Warning ("StartAddress and EndAddress are not supported while using " + 
                "InputFile. Ignoring them.")
        }
        try {
            $ArrayList = [System.Net.IPAddress[]](get-content $InputFile)
        }
        catch {
            Write-Warning ("One or more IP Address from the input file is invalid. The following" +
                " error may give more information:")
            Write-Error $Error
            exit
        }
    }

    #---Determine and validate addressing scheme---------------------------------------------------
    else {
        if ($StartAddress -like "*/*") {
            try {
                $CIDR = [uint16]$StartAddress.Split('/', 2)[1]
                $StartAddress = $StartAddress.Split('/', 2)[0]
                $Octets = $StartAddress.Split('.')
            }
            catch {
                throw "CIDR notation incorrect"
                exit
            }
            if ($CIDR -eq 0 -or $CIDR -gt 31) {
                throw "CIDR notation incorrect"
                exit
            }
        }
    
        if ($CIDR -and $EndAddress) {
            Write-Host "You have given an end address and a CIDR notation start address. It will"
            "be ignored."
        }
    
        if (-not $CIDR -and -not $EndAddress) {
            throw "Please specify an end address."
            exit
        }
    
        if (-not $CIDR) {
            try {
                [System.Net.IPAddress]$StartAddress | Out-Null
                [System.Net.IPAddress]$EndAddress | Out-Null
            }
            catch {
                Write-Warning ("We suspect a one of the supplied IP addresses is invalid. " + 
                    "The following error occured:")
                Write-Error $Error
                exit
            }
        }

        #---Calculate CIDR range if necessary------------------------------------------------------
        if ($CIDR) {
            #Calculate start address
            $FullOctets = [math]::floor($CIDR / 8)              #Determine how many full octets
            $PartialOctet = $FullOctets + 1                     #Which octet is the first partial?
            $PartialFill = $CIDR % 8                            #Get network address bits in 
            #first partial octet
            $OctetMask = 0
            if ($PartialFill -gt 0) {
                #Convert leading bits to decimal
                1..$PartialFill | foreach-Object {
                    $OctetMask += [math]::pow(2, 8 - $PSItem)
                }
            }
            $NetAddress = $Octets[$PartialOctet - 1] -band $OctetMask
            #At this point, zero out the unnecessary octets and define first address. Then find the end
            #address.

            $OctetSlider = $PartialOctet                        #Slider for Octet array indexes
            [int]$Octets[$PartialOctet - 1] = $NetAddress
            while ($OctetSlider -le 3) {
                $Octets[$OctetSlider] = 0
                $OctetSlider++
            }
            $StartAddress = "$($Octets[0]).$($Octets[1]).$($Octets[2]).$($Octets[3])"

            #Calculate End Address
            $EndOctets = $Octets
            $AddressRangeBits = 7 - $PartialFill
            if ($AddressRangeBits -gt 0) {
                #Convert leading bits to decimal
                0..$AddressRangeBits | ForEach-Object {
                    $Range += [math]::pow(2, $PSItem)
                }
            }
            [int]$EndOctets[$PartialOctet - 1] += $Range
            
            $EndAddress = "$($EndOctets[0]).$($EndOctets[1]).$($EndOctets[2]).$($EndOctets[3])"

            #---Claen up variables-----------------------------------------------------------------
            Remove-Variable "EndOctets", "AddressRangeBits", "Range", "OctetSlider", "NetAddress",
            "OctetMask", "PartialFill", "PartialOctet", "FullOctets"
        }

        #---Create List of IP Addresses------------------------------------------------------------
        $StartParts = $StartAddress.Split('.')
        $EndParts = $EndAddress.Split('.')
        $StopZero = $EndParts[0]
        $StopOne = 255
        $StopTwo = 255
        $StopThree = 255
        
        $ItZero = [int]$StartParts[0] 

        do {
            if ($ItZero -eq [int]$StartParts[0]) {
                $ItOne = [int]$StartParts[1]
            }
            else {
                $ItOne = 0
            }
            if ($ItZero -eq $StopZero) {
                $StopOne = [int]$EndParts[1]
                $EndZero = $true
            }
            do {
                if ($ItOne -eq $StartParts[1]) {
                    $ItTwo = [int]$StartParts[2]
                }
                else {
                    $ItTwo = 0
                }
                if ($ItOne -eq $EndParts[1] -and $EndZero) {
                    $StopTwo = [int]$EndParts[2]
                    $EndOne = $true
                }
                do {
                    if ($ItTwo -eq $StartParts[2]) {
                        $ItThree = [int]$StartParts[3]
                    }
                    else {
                        $ItThree = 0
                    }
                    if ($ItTwo -eq $EndParts[2] -and $EndZero -and $EndOne) {
                        $StopThree = [int]$EndParts[3]
                    }
                    do {
                        $ArrayList += "$ItZero.$ItOne.$ItTwo.$ItThree"
                        $ItThree++
                    }while ($ItThree -le $StopThree)
                    $ItTwo++
                }while ($ItTwo -le $StopTwo)
                $ItOne++
            }while ($ItOne -le $StopOne)
            $ItZero++
        }while ($ItZero -le $StopZero)

        #---Clean up environment-------------------------------------------------------------------
        Remove-Variable "ItZero", "ItOne", "ItTwo", "ItThree", "StopZero", "StopOne", "StopTwo",
        "StopThree", "StartParts", "EndParts"
    }
    
    
    #---Begin the Scanning-------------------------------------------------------------------------

    $Results = Start-TypeScan -IpAddress $ArrayList -Port $Ports -Type $Type -Verbose


    #---Prepare for output-------------------------------------------------------------------------
    $File = get-date -Format "yyyy-MM-dd.hh.mm.ss"

    if ($ReportType -eq "HTML") {
        $Results | ConvertTo-Html | Out-File "$PWD\$File.html"
    }
    elseif ($ReportType -eq "CSV") {
        $Results | ConvertTo-Csv | Out-File "$PWD\$File.csv"
    }
    elseif ($ReportType -eq "XML") {
        $Results | Export-Clixml -Path "$PWD\$File.xml"
    }
    elseif ($ReportType -eq "JSON") {
        $Results | ConvertTo-Json | Out-File "$PWD\$File.json"
    }
    else {
        $Results
    }

}
