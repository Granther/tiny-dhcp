package cache

import (
	"fmt"
	"gdhcp/utils"
	"log/slog"
	"net"
	"time"
)

type AddrQueueHandler interface {
	FillQueue(num int) error
	DeQueue() bool
	EnQueue(val net.IP) bool
	Front() net.IP
}

type ListNode struct {
	val  net.IP
	prev *ListNode
	next *ListNode
}

type AddrQueue struct {
	space int
	left  *ListNode
	right *ListNode
}

func NewAddrQueue(max int) AddrQueueHandler {
	left := NewListNode(nil, nil, nil)
	right := NewListNode(nil, left, nil)
	left.next = right

	return &AddrQueue{
		space: max,
		left:  left,
		right: right,
	}
}

func NewListNode(val net.IP, prev *ListNode, next *ListNode) *ListNode {
	return &ListNode{
		val:  val,
		prev: prev,
		next: next,
	}
}

func (q *AddrQueue) isEmpty() bool {
	return q.left.next == q.right
}

func (q *AddrQueue) isFull() bool {
	return q.space == 0
}

func (q *AddrQueue) Empty() {
	slog.Debug("Emptying queue...")

	q.left.next = q.right
	q.left.prev = q.right
	q.right.prev = q.left
	q.right.next = q.left
}

func (q *AddrQueue) Front() net.IP {
	if q.isEmpty() {
		return nil
	}
	return q.left.next.val
}

func (q *AddrQueue) Rear() net.IP {
	if q.isEmpty() {
		return nil
	}
	return q.right.prev.val
}

func (q *AddrQueue) EnQueue(val net.IP) bool {
	if q.isFull() {
		return false
	}
	newNode := NewListNode(val, q.right.prev, q.right)
	q.right.prev.next = newNode
	q.right.prev = newNode
	q.space -= 1

	return true
}

func (q *AddrQueue) DeQueue() bool {
	if q.isEmpty() {
		return false
	}
	q.left.next = q.left.next.next
	q.left.next.prev = q.left
	q.space += 1

	return true
}

func (q *AddrQueue) FrontToEnd() {
	node := q.left.next
	// Fix left
	q.left.next = node.next
	q.left.next.prev = q.left
	// Fix Node
	node.next = q.right
	node.prev = q.right.prev
	// Fix right
	q.right.prev.next = node
	q.right.prev = node
}

func (q *AddrQueue) PrintQueue() {
	for ptr := q.left.next; ptr != q.right; ptr = ptr.next {
		fmt.Println(ptr.val)
	}
}

func (q *AddrQueue) ReadLeasesFromDB() error {
	// Read leases from db
	// Build leasenode object
	// Add to mac and ip cache
	leases, err := q.Storage.GetLeases()
	if err != nil {
		return err
	}

	for _, lease := range leases {
		mac, err := net.ParseMAC(lease.MAC)
		if err != nil {
			return fmt.Errorf("unable to extract mac from database lease: %v", err)
		}

		leasedOn, err := time.Parse("2006-01-02 15:04:05", lease.LeasedOn)
		if err != nil {
			return fmt.Errorf("unable to parse str time from db to time: %v", err)
		}

		ip := net.ParseIP(lease.IP)

		leaseNode := NewLeaseNode(ip, mac, time.Duration(lease.LeaseLen), leasedOn)
		q.LeasesCache.Put(leaseNode)
	}

	return nil
}

func (q *AddrQueue) FillQueue(num int) error {
	// While new addrs list < num
	// Generate addr from bottom of thing, if in cache or in queue, skip
	// else, add

	// Pass val to new addrs
	// If it has been longer than val.lease len since val.leased on, expired, add to back of queue as available

	// Clear Queue, fuck it
	q.Empty()

	var newAddrs []net.IP
	startIP := net.ParseIP(q.AddrPool[0])
	endIP := net.ParseIP(q.AddrPool[1])

	for ip := startIP; !ip.Equal(endIP) && len(newAddrs) < num; ip = utils.IncrementIP(ip) {
		val := q.LeasesCache.IPGet(ip)
		if val == nil { // Doesnt exist in leases
			newAddrs = append(newAddrs, ip)
		}
	}

	// Add new addrs first (first to be picked)
	for _, ip := range newAddrs {
		ok := q.EnQueue(ip)
		if !ok {
			slog.Debug("Wasn't able to add all addrs to queue, maybe full")
		}
	}

	return nil
}
