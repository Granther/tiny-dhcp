package main

// import (
// 	"fmt"
// 	"net"
// )

// // Function to iterate over the IP pool
// func iterateIPPool(startIP, endIP string) {
// 	// Parse the start and end IPs
// 	start := net.ParseIP(startIP).To4()
// 	end := net.ParseIP(endIP).To4()

// 	if start == nil || end == nil {
// 		fmt.Println("Invalid IP address")
// 		return
// 	}

// 	// Iterate from start IP to end IP
// 	for ip := start; !ipEqual(ip, end); ip = incrementIP(ip) {
// 		fmt.Println(ip)
// 	}

// 	// Print the last IP
// 	fmt.Println(end)
// }

// // Function to increment the last octet of the IP address
// func incrementIP(ip net.IP) net.IP {
// 	newIP := make(net.IP, len(ip))
// 	copy(newIP, ip)

// 	for i := len(newIP) - 1; i >= 0; i-- {
// 		newIP[i]++
// 		if newIP[i] != 0 {
// 			break
// 		}
// 	}
// 	return newIP
// }

// // Function to compare two IP addresses
// func ipEqual(ip1, ip2 net.IP) bool {
// 	return ip1.Equal(ip2)
// }

// func main() {
// 	startIP := "192.168.1.1"
// 	endIP := "192.168.2.255"

// 	iterateIPPool(startIP, endIP)
// }
