### Discover
- Send by Client
- Src 0.0.0.0, dst 255.255.255.255
- Src: 68, Dst: 67
- Bootp message type: request
- Secs: 1
- Bootp flags for unicast
- Client IP 0.0.0.0
- Your IP 0.0.0.0
- Client mac addr
- Has DHCP magic cookie

#### Options
- Has message type
- 61, client ident, same mac as client mac addr
- 55, request list
- List of options
- 57, max dhcp len 576
- 12, hostname, laptop host
- End opt

### Offer
- Src 192.168.1.1 (server), dst 192.168.1.204
- src 67, dst 68
- Bootp message type, reply
- client ip, 0.0.0.0
- your ip 192.168.1.204 

#### Options
- 53, offer type
- 54, dhcp server id
- 51, lease time
- 1, subnet mask
- 6, dns servers
- 15, domian name,
- 3, router
- End options

### Request
- src: 0.0.0.0 dst 255.255.255.255
- src: 68, dst 67
- boot p request
- cleint ip:; 0.0.0.0
- your ip: 0.0.0.0

#### Options
- 53, message request
- 61, cliend ident
- 55, param request list 
- 57, max dhcp message size 576
- 50, requested ip addr, 192.168.1.204
- 54, dhcp server ident 
- 12, hostname
- 255, end opt

### Ack
- src 192.168.1.1 dst 192.168.1.204
- src 67, dst 68
- bootp message type, reply
- cleint ip 0.0.0.0
- your ip 192.168.1.204

#### Options
- 53, type ack
- 54, dhcp server id
- 51, ip addr lease time
- 1, subnet mask
- 6, dns server
- 15, domain name 
- 3, router
- 255, end ops

### Patterns
- XID kept the same for all
- client mac addr stayed as the laptop the entire time
- request list in discover and offer
- from client, bootp request
- from server, bootp reply
- seconds elapsed stayed 0, hops stayed 0
- bootp flags, all unicast
- Offer did not contain IP addr field, only request had 50
- Server does not always completely answer request list

### Oddities
- On windows, the MAC dst seems to be malformed
- The discover will have a requested ip option, seems like if it does it will contain that IP as the dst IP in the offer as well as in yiaddr