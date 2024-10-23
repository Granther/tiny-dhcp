package database

import (
	"database/sql"
	"gdhcp/types"
	"net"
	"time"
)
type PersistentHandler interface {
	Connect() error
	CreateLeasesTable(db *sql.DB) error
	ConnectDatabase() (*sql.DB, error)
	IsIPAvailable(ip net.IP) bool
	IsMACLeased(mac net.HardwareAddr) net.IP
	LeaseIP(ip net.IP, mac net.HardwareAddr, leaseLen time.Duration, leasedOn time.Time) error
	GetLeases() ([]types.DatabaseLease, error)
	UnleaseMAC(mac net.HardwareAddr) error
	GetLeasedIPs() ([]net.IP, error)
	Unlease(dbLease *types.DatabaseLease) error
}
