package database

import (
	"database/sql"
	"fmt"
	"log/slog"
	"net"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"gdhcp/types"
	"gdhcp/utils"
)

type SQLiteManager struct {
	db *sql.DB
}

func NewSQLiteManager() PersistentHandler {
	return &SQLiteManager{}
}

func (s *SQLiteManager) Connect() error {
	db, err := s.ConnectDatabase()
	if err != nil {
		return fmt.Errorf("error occured when connecting to db object: %v", err)
	}
	s.db = db

	return nil
}

func (s *SQLiteManager) CreateLeasesTable(db *sql.DB) error {
	leasesTableSQL := `CREATE TABLE IF NOT EXISTS leases (
        "id" INTEGER PRIMARY KEY AUTOINCREMENT,
        "mac" TEXT UNIQUE NOT NULL,
        "ip" TEXT UNIQUE NOT NULL,
		"static" BOOLEAN NOT NULL DEFAULT 0,
		"lease_len" INTEGER,
		"leased_on" TEXT
    );`

	_, err := db.Exec(leasesTableSQL)
	if err != nil {
		return fmt.Errorf("error creating leases table: %w", err)
	}

	return nil
}

func (s *SQLiteManager) ConnectDatabase() (*sql.DB, error) {
	db, err := sql.Open("sqlite3", "./leases.db")
	if err != nil {
		return nil, fmt.Errorf("error occured when connecting to leases.db: %w", err)
	}

	err = db.Ping()
	if err != nil {
		return nil, fmt.Errorf("failed to ping db during init connection: %w", err)
	}

	err = s.CreateLeasesTable(db)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	return db, nil
}

func (s *SQLiteManager) IsIPAvailable(ip net.IP) bool {
	var lease types.DatabaseLease

	query := "SELECT ip, lease_len, leased_on FROM leases WHERE ip = ?;"
	err := s.db.QueryRow(query, ip.String()).Scan(&lease.IP, &lease.LeaseLen, &lease.LeasedOn)
	if err != nil {
		if err == sql.ErrNoRows {
			slog.Debug("No lease found for that IP", "ip", ip.String())
			return true
		}
		return false
	}

	if utils.IsExpired(lease.LeaseLen, lease.LeasedOn) {
		return true
	}
	return false
}

func (s *SQLiteManager) IsMACLeased(mac net.HardwareAddr) net.IP {
	var lease types.DatabaseLease

	query := "SELECT ip, mac, lease_len, leased_on FROM leases WHERE mac = ?;"
	err := s.db.QueryRow(query, mac.String()).Scan(&lease.IP, &lease.MAC, &lease.LeaseLen, &lease.LeasedOn)
	if err != nil {
		if err == sql.ErrNoRows {
			slog.Debug("MAC does not have a lease")
			return nil
		}
		// Actual error return
		slog.Error("Unexpected error while querying for mac lease")
		return nil
	}

	if utils.IsExpired(lease.LeaseLen, lease.LeasedOn) {
		slog.Debug("Mac was leased, but is expired")
		return nil
	}

	ip := net.ParseIP(lease.IP)
	slog.Debug("Mac had lease", "ip", ip)
	return ip
}

func (s *SQLiteManager) LeaseIP(ip net.IP, mac net.HardwareAddr, leaseLen time.Duration, leasedOn time.Time) error {
	leaseSelect := `DELETE FROM leases WHERE ip = ? AND mac = ?;`
	s.db.Exec(leaseSelect, ip.String(), mac.String())

	intLen := int(leaseLen.Seconds())
	currentTime := utils.FormatTime(leasedOn)
	insertLease := `INSERT INTO leases (ip, mac, lease_len, leased_on) VALUES (?, ?, ?, ?);`
	_, err := s.db.Exec(insertLease, ip.String(), mac.String(), intLen, currentTime)
	if err != nil {
		return fmt.Errorf("error leasing IP: %v", err)
	}

	return nil
}

func (s *SQLiteManager) Unlease(dbLease *types.DatabaseLease) error {
	leaseSelect := `DELETE FROM leases WHERE ip = ? AND mac = ?;`
	_, err := s.db.Exec(leaseSelect, dbLease.IP, dbLease.MAC)

	return err
}

func (s *SQLiteManager) GetLeasedIPs() ([]net.IP, error) {
	query := "SELECT id, ip FROM leases"

	rows, err := s.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("%v", err)
	}
	defer rows.Close()

	var ips []net.IP
	for rows.Next() {
		var lease types.DatabaseLease
		err = rows.Scan(&lease.ID, &lease.IP)
		if err != nil {
			if err == sql.ErrNoRows {
				break
			}
			return nil, fmt.Errorf("%v", err)
		}

		ips = append(ips, net.ParseIP(lease.IP))
	}

	return ips, nil
}

func (s *SQLiteManager) GetLeases() ([]types.DatabaseLease, error) {
	query := "SELECT ip, mac, lease_len, leased_on FROM leases"

	rows, err := s.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("%v", err)
	}
	defer rows.Close()

	var leases []types.DatabaseLease

	for rows.Next() {
		var lease types.DatabaseLease

		err = rows.Scan(&lease.IP, &lease.MAC, &lease.LeaseLen, &lease.LeasedOn)
		if err != nil {
			if err == sql.ErrNoRows {
				break
			}
			return nil, fmt.Errorf("%v", err)
		}

		leases = append(leases, lease)
	}

	return leases, nil
}

func (s *SQLiteManager) UnleaseMAC(mac net.HardwareAddr) error {
	leaseSelect := `DELETE FROM leases WHERE mac = ?;`
	_, err := s.db.Exec(leaseSelect, mac.String())

	if err != nil {
		return fmt.Errorf("failed to delete mac %s lease: %v", mac.String(), err)
	}

	return nil
}
