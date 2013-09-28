/*******************************************************************************
 * File: sendarp.c                                                             *
 * Date: 16NOV08                                                               *
 * Author: Chris Bisnett                                                       *
 * Description:  Uses the iphlpapi.dll file included in Windows since 98. It   *
 *  allows sending ARP requests to specified IP address and getting back the   *
 *  MAC address from the reply.  This can be done without needing a privileged *
 *  account since it creates the packet and listens for the reply. It cannot   *
 *  be used to spoof the source IP address but can be told which address to    *
 *  use if there are muliple interfaces.                                       *
 ******************************************************************************/

/*
The MIT License (MIT)

Copyright (c) 2013 Chris Bisnett

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include <winsock2.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

// Need to link with some libraries
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

// Prints out an error string and returns an error code
void makeError(char *errString)
{
    // Print the error
    printf("Error: %s\n", errString);
    
    // Return the error code
    exit(-1);
}

// Increments an IP address to the next higher
int nextIp(IPAddr *address)
{
    int i;
    unsigned char *ptr = (char *)address;
    
    // Loop the octets
    for (i = 3; i > -1; i--)
    {
        // Increase the octet if it won't roll over
        if (*(ptr+i) < 255)
        {
            // Increase the octet
            (*(ptr+i))++;
            break;
        }
        else
            // Set the octet to zero and goto the next octet
            *(ptr+i) = 0;
    }
    
    return 1;
}

int main(int argc, char **argv)
{
    // Return value
    DWORD dwRetVal;
    
    // Source IP addresses
    IPAddr SrcIp;
    
    // First and last IP address in the range
    IPAddr DestIp;
    IPAddr EndDestIp;
    
    // Pointer used only to convert from network order to dotted decimal
    struct in_addr *addr;
    
    // MAC address
    ULONG MacAddr[2];
    ULONG PhysAddrLen = 6;
    ULONG RetAddrLen = 0;
    
    // String IP addresses
    char *SrcIpString = NULL;
    char *StartDestIpString = NULL;
    char *EndDestIpString = NULL;
    
    // Used to loop the MAC address and print out the hex values
    BYTE *bPhysAddr;
    
    // Delay settings
    unsigned int delaySeconds = 0;
    unsigned char delayType = 0;
    time_t delayExit;
    
    // Loop counter
    int i;
    
    // Loop the arguments and get the options
    for (i = 1; i < argc; i++)
    {
        // Check if the argument starts with a -
        if (argv[i][0] == '-')
        {
            // Make all options lower case
            switch (tolower(argv[i][1]))
            {
            case 's':  // Source IP address
                // Get the source IP address
                SrcIpString = argv[++i];
                
                // Convert the source IP address string to an integer
                SrcIp = inet_addr(SrcIpString);
                break;
            case 'd':  // Delay
                // Check if the delay is random
                if (strlen(argv[i]) > 2 && argv[i][2] == 'r')
                    // Set the delay type to be random
                    delayType = 1;
                
                // Get the delay
                sscanf(argv[++i], "%d", &delaySeconds);
                break;
            }
        } 
        else
        {
            // If the destination has been set then this must be the end
            // destination ip
            if (StartDestIpString == NULL)
                StartDestIpString = argv[i];
            else
                EndDestIpString = argv[i];
        }
    }
    
    // Make sure that if a source IP was specified it is valid
    if (SrcIp == INADDR_NONE)
        makeError(strcat("Invalid source IP: ", SrcIpString));
    
    // Make sure a start destination address was specified
    if (StartDestIpString == NULL || StartDestIpString[0] == '\0')
        makeError("Must specify a destination address.");
    
    // Get the start destination ip integer
    DestIp = inet_addr(StartDestIpString);
    if (DestIp == INADDR_NONE || DestIp == INADDR_ANY)
        makeError(strcat("Invalid start destination address: ",
            StartDestIpString));
    
    // Check if a end destination ip address was specified
    if (EndDestIpString != NULL)
    {
        // Get the end destination ip integer
        EndDestIp = inet_addr(EndDestIpString);
        if (EndDestIp == INADDR_NONE || EndDestIp == INADDR_ANY)
            makeError(strcat("Invalid end destination address: ",
                EndDestIpString));
    }
    else
        // Only ping the start
        EndDestIp = DestIp;
    
    // Make sure the end destination ip address comes after the start
    if (DestIp > EndDestIp)
        makeError("Invalid destination range.  The end of the destination range"
            " must come after the start.");
    
    // Loop the addresses
    do
    {
        // Initialize the struct
        memset(&MacAddr, 0xff, PhysAddrLen);
        RetAddrLen = PhysAddrLen;
        
        // Send the arp request
        dwRetVal = SendARP(DestIp, SrcIp, (PULONG)&MacAddr, &RetAddrLen);
        
        // Set the in_addr structure
        addr = (struct in_addr *)&DestIp;
        
        // Check if there was an error
        if (dwRetVal == NO_ERROR)
        {
            // Print out the ip address
            printf("%s (", inet_ntoa(*addr));
            
            // Build the mac address
            bPhysAddr = (BYTE *) & MacAddr;
            for (i = 0; i < (int) PhysAddrLen; i++)
            {
                if (i == ((int)PhysAddrLen - 1))
                    printf("%.2X", (int) bPhysAddr[i]);
                else
                    printf("%.2X-", (int) bPhysAddr[i]);
            }
            
            // Close the mac address
            printf(")\n");
        }
        else
        {
            // Check if there was an error or if there was no response
            if (dwRetVal != ERROR_GEN_FAILURE  &&
                dwRetVal != ERROR_BAD_NET_NAME)
            {
                // Print out the ip address
                printf("%s: ", inet_ntoa(*addr));
                
                // Print out the error
                switch (dwRetVal) {
                case ERROR_INVALID_PARAMETER:
                    printf("Invalid parameter\n");
                    break;
                case ERROR_INVALID_USER_BUFFER:
                    printf("Invalid user buffer\n");
                    break;
                case ERROR_BUFFER_OVERFLOW:
                    printf("Buffer not large enough\n");
                    break;
                case ERROR_NOT_FOUND:
                    printf("Source IP not found on system\n");
                    break;
                case ERROR_NOT_SUPPORTED:
                    printf("Sending ARP requests not supported on this "
                        "operating system\n");
                default:
                    printf("Unknown error\n");
                    break;
                }
            }
        }
        
        // Check if there is a delay set
        if (delaySeconds > 0)
        {
            // Get the time
            delayExit = time(NULL);
            
            // Add the delay
            if (delayType == 1)
                delayExit += rand() % delaySeconds;
            else
                delayExit += delaySeconds;
            
            // Wait for the delay
            while (time(NULL) < delayExit);
        }
    // Verify the current IP is not the last and goto the next
    } while (DestIp != EndDestIp && nextIp(&DestIp));

    return 0;
}
