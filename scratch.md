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