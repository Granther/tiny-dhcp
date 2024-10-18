package cache 

import (
	"time"
	"net"
)

// Have a queue of available addrs
// When static addr is encountered, add to end of queue
// At runtime queue of N addrs is created
// If queue is empty, add additionalt pool of N available addrs (if possible)

type LeasesCache struct {
	ipCache			map[*net.IP]*LeaseNode
	macCache		map[*net.HardwareAddr]*LeaseNode
	availableQueue	*CircularQueue
}

type LeaseNode struct {
	ip			net.IP
	mac			net.HardwareAddr
	leaseLen	time.Duration
	leasedOn	time.Time
}

func NewLeaseNode(ip net.IP, mac net.HardwareAddr, leaseLen time.Duration, leasedOn time.Time) *LeaseNode {
	return &LeaseNode {
		ip:			ip,
		mac:		mac,
		leaseLen:	leaseLen,
		leasedOn:	leasedOn,
	}
}

func NewLeasesCache(max int) *LeasesCache {
	ipCache := make(map[*net.IP]*LeaseNode)
	macCache := make(map[*net.HardwareAddr]*LeaseNode)
	availableQueue := NewCirularQueue(max)

	return &LeasesCache {
		ipCache: 		ipCache,
		macCache:		macCache,
		availableQueue:	availableQueue,
	}
}

