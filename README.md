# PoshScan

https://github.com/discusdude/PoshScan

Run the program by running Start-PortScan.ps1. Examples are below

## SYNOPSIS
Asynchronously scan specified hosts and ports using TCP

## DESCRIPTION
Takes input either as a text file, IP address range via CIDR notation, or a start address and
end address. It then asynchronously scans 5 addresses at a time and 5 simultaneious ports per
address for a total of 25 simultaneous ports. It will then display PSObject results or export
the results as html, csv, xml, or json depending on the specified result type. It will only
include hosts responded on a port.

The functions that it uses are located in the Start-PortScan.psm1 file.

## PARAMETER Type
Type: String

In a future version, this will specify the type of scan to be performed (ICMP, TCP, UDP, ARP)
and will be constrained to those options. Currenlty, TCP is the only valid option.

## PARAMETER StartAddress
Type: String

Specifies the start address of an IP address range or specifies a an IP address and its subnet
in CIDR notation. If used with the "InputFile" parameter, it will be ignored. If it is not in
CIDR notation, "EndAddress" will be expected. If it is in CIDR notation, it will ignore the
"EndAddress" parameter and calculate the IP address range from the CIDR prefix. Acceptible
formats are "192.168.2.5" and "192.168.25.2/27."

## PARAMETER EndAddress
Type: String

Specifies the end address of an IP address range. It is ignored if "StartAddress" is in CIDR
notation or if "InputFile" is used.

## PARAMETER Port
Type: String Array

Specifies which ports should be scanned. If none are supplied, a default array of some well
known ports will be used. Accepts comma separated port numbers and ranges.

Example 1: 556, 25, 22, 80, 443

Example 2: 22, 23, 90-102

## PARAMETER ReportType
Type: String

ReportType is constrained to the values "None", "HTML", "CSV", "XML", and "JSON." If this
parameter is ommited or given the value "None" then the script will display the results of the
scan on the terminal. If any other valid value is given, an appropriate file will be created in
the current working directory. It will be named with the time of completion for the scan and
the appropriate file extension.

## PARAMETER InputFile
Type: String

The path to a .txt or .csv file containing the IP addresses to scan. Will override
"StartAddress" and "EndAddress"

## EXAMPLE
```
Start-PortScan -StartAddress 192.168.2.0 -EndAddress 192.168.3.0 -Port 80, 443

Host           TCPResults
----           ----------
192.168.2.15   80, 443
192.168.2.16   80, 443
192.168.2.26   80
192.168.2.200  443
```

## EXAMPLE
```
Start-PortScan -StartAddress 192.168.2.5/24 -Port 80, 443

Host           TCPResults
----           ----------
192.168.2.15   80, 443
192.168.2.16   80, 443
192.168.2.26   80
192.168.2.200  443
```

## EXAMPLE
```
Start-PortScan -InputFile .\address.txt -Port 80,443 -Type tcp

Host           TCPResults
----           ----------
128.187.16.99  80, 443
204.79.197.200 80, 443
```

## EXAMPLE
```
Start-PortScan -InputFile .\address.txt -Port 80,443 -Type tcp -ReportType HTML
```
This will create an HTML document in the current working directory with a table of the results.

## EXAMPLE
```
Start-PortScan -InputFile .\address.txt -Type ARP

Host           ARPResults
----           ----------
192.168.111.1  AB:CD:EF:12:34:56
192.168.123.6  AB:CD:EF:12:34:55
```