sendarp
=======

Userland ARP scanner for Microsoft Windows

**Created By:** Chris Bisnett<br/>
**Date:** 16NOV08

SendARP is a program designed to take advantage of the ARP protocol to discover
hosts on a network segment that are otherwise unresponsive to ICMP echo
requests. Due to the fact that all hosts MUST respond to ARP requests no host
can be completely invisible if it still expects to receive traffic.

This version of SendARP uses a standard Windows dll file (iphlpapi.dll) that has
been included since Windows 98. This dll file allows unprivileged users to
perform network operations such as sending ARP and ICMP requests. Since winpcap
is not being used and this tool is meant to be run from an unprivileged user we
cannot spoof the source IP address, although depending on the network layout we
may not receive those replys anyway.

SendARP can be used to "ping" a single IP address or it can "ping" through a
range of IP addresses. Due to the fact that each host must be sent an ARP
request when a range of IP addresses is used this can cause a good deal of
"noise". SendARP includes a few features that can be used to reduce the "noise"
and possibility of detection. A hard delay can be used to specify the time to
wait between sending ARP requests. For more stealth a random delay can be
specified and will use a delay between 0 and the amount of seconds specified for
the delay.

Command-line Syntax
===================

    sendarp.exe [options] Destination [End Destination]
    
    Destination - The IP address to query or the start of the range
    
    End Destination - The last ip address in the range
    
    Option      Description
        s           Used to specify the IP address of the interface to use
                    as the source when sending ARP requests.
    
        d           Used to specify a delay between sending ARP requests.
    
        dr          Used to specify a random delay between 0 and the number
                    of seconds specified.