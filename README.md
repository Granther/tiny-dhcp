# Tiny DHCP
- A cute little DHCP server written from scratch (no dhcp packages) in Go

### Why?
- This was a learning experience, I had never written anything in Go nor had I ever written a server.
- I wanted to host a dedicated DHCP server in my homelab, I realize there are not many homelab friendly projects that allow me to do this

### Why is it Tiny?
- Well, it doesn't do any fancy vendor specific stuff

### RCFC?
- Nope, I'm not writing the server in complete accordance with RCFC's DHCP docs 

### The Low Down
- The server uses a Worker pool to accept, process and send.
