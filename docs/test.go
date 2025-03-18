package main

// import (
// 	"net"
// 	"fmt"
// )

// func JsonIPListToBytes(jsonList []string) []byte {
// 	var byteSlice []byte 

// 	for _, ip := range jsonList {
// 		newIP := net.ParseIP(ip)
// 		// byteVal := net.ParseIP(ip)
// 		byteSlice = append(byteSlice, newIP)
// 	}

// 	return byteSlice
// }

// func main() {
// 	var jsonList []string = []string{"192.168.1.1", "192.168.1.2"}

// 	JsonIPListToBytes(jsonList)
// }