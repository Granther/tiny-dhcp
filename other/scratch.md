## Ideas

### Config 
- Port, cause why not
- Interface, maybe 'any' for now

#### Network configs
- Subnet mask
- Gateway
- Range
- Dns servers
- Lease length

### Entry
- Read config file first, important

### Arch
- Create n worker threads upon instant
- Upon connection, give worker packet
- Run all packet stuff from within worker thread
- Use channels to gracefully shutdown workers
- Officially called a worker pool

### Request List
- Write the config to a working datastructure
- If any packet contains a request list, read it completely and see if we can answer it and build the packet in accordance with it

### Leases
- What happens on the server when a lease expires?
- Do I run a job that periodically checks the status of all leases?
- What if a host is disconnected, has its lease expired, a new device sends discover and gets its IP? We dont want that

### Parsing complex config
- Make function to parse each different kind of data
- Some data is in a list so maybe switch to json

### Read reqeust list
- Read to see if I need to return something or do something
- Like a T1 or T2 that specifies I renew a lease

SERVER HAS TO LISTEN ON BROADCAST, YOU HAVET HE IQ OF A ROCK