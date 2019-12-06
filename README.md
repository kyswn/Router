I used C++ to implement a simple router with a static routing table. It receives ethernet frames and process them: forward them to the right interface, create new frames, etc.

high level design:

handlePacket:

check for type
if arp:
	if arp request:
		if target mac is broadcast and target ip is the router:
			send arp response
	if arp respnse:
		if mac in the arp cache:
			send relevant packets out
if ip:
	check if it is legit
	if to this router:
		if icmp:
			if icmp echo:
				if ip in the cache: reply
				else: cache it 
			if icmp echo reply: 
				forward it
	else: forward it



periodicCheckArpRequestsAndCacheEntries:
first handle the arp reqest table, and then handle the arp entry table

lookup:
use linear search to find the longes matching prefix


problems:
It is a tedious project and I had to look into so many details.
At first I messsed up the interface used when forwarding a package.
Then I messed up the size passed into the checksum function and the file forwarded wouldn't get a reply(because the checksum would be wrong) and all the test files wouldn't appear in the folder
Then for some reason the files still wouldn't transmist and after I restarted the vagrant and changed the port number it works, which I don't understand why.
Basically when I have a bug I print out everything and just read the output in the router console and try to figure out what is wrong.
I went to Seungbae and Siva's office hour for help and I really appreciate their help. I wouldn't have figured it out without them.
