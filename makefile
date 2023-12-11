#final: sql.c obj.c duo_node.c settings.c utility.c dhcppacket.c dhcp.c
#		gcc utility.c settings.c duo_node.c obj.c dhcppacket.c sql.c dhcp.c -o dhcp -lpq -lm -lsystemd
		
final: sql.c obj.c duo_node.c settings.c utility.c dhcppacket.c dhcp_2.c
		gcc -fsanitize=address utility.c settings.c duo_node.c obj.c dhcppacket.c sql.c dhcp_2.c -o dhcp -lpq -lm -lsystemd