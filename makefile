final: sql.c obj.c settings.c utility.c dhcp.c
		gcc utility.c settings.c obj.c sql.c dhcp.c -o dhcp -lpq -lm
