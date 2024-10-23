package database

import (
    "database/sql"
	"log/slog"
	"fmt"
	"net"
	"time"

    _ "github.com/mattn/go-sqlite3"
	types "gdhcp/types"
)

func CreateLeasesTable(db *sql.DB) (error) {
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
        return fmt.Errorf("Error creating leases table: %v\n", err)
    }

	return nil
} 

func FillDatabase(db *sql.DB) {
	leasesTableSQL := `INSERT INTO leases (ip, mac, lease_len, leased_on) VALUES (?, ?, ?, ?);`
	db.Exec(leasesTableSQL, "10.10.1.20", "0a:0a:0a:0a:0a:0a", 84600, "2006-01-02 15:04:05")
}

func ConnectDatabase() (*sql.DB, error) {
	db, err := sql.Open("sqlite3", "./leases.db")
    if err != nil {
        return nil, fmt.Errorf("Error occured when connecting to leases.db: %v", err)
    }

    err = db.Ping()
    if err != nil {
        return nil, fmt.Errorf("Error occured when pinging db...%v", err)
    }

	err = CreateLeasesTable(db)
	if err != nil {
		return nil, fmt.Errorf("%v\n", err)
	}

	return db, nil
}

func IsExpired(leaseLen int, leasedOn string) (bool) {
	leasedOnTime, err := time.Parse("2006-01-02 15:04:05", leasedOn)
	if err != nil {
		return true
	}

	timeSince := time.Since(leasedOnTime)
	if int(timeSince.Seconds()) >= leaseLen {
		return true
	}

	return false
}

func IsIPAvailable(db *sql.DB, ip net.IP) (bool) {
	var lease types.DatabaseLease

    query := "SELECT ip, lease_len, leased_on FROM leases WHERE ip = ?;"
    err := db.QueryRow(query, ip.String()).Scan(&lease.IP, &lease.LeaseLen, &lease.LeasedOn)
    if err != nil {
        if err == sql.ErrNoRows {
            slog.Debug("No lease found for that IP", "ip", ip.String())
            return true
        }
        return false
    }

	if IsExpired(lease.LeaseLen, lease.LeasedOn) {
		return true
	}
    return false
}

func IsMACLeased(db *sql.DB, mac net.HardwareAddr) (net.IP) {
	var lease types.DatabaseLease

    query := "SELECT ip, mac, lease_len, leased_on FROM leases WHERE mac = ?;"
    err := db.QueryRow(query, mac.String()).Scan(&lease.IP, &lease.MAC, &lease.LeaseLen, &lease.LeasedOn)
    if err != nil {
        if err == sql.ErrNoRows {
            slog.Debug("MAC does not have a lease")
			return nil        
		}
		// Actual error return
		slog.Error("Unexpected error while querying for mac lease")
        return nil
    }

	if IsExpired(lease.LeaseLen, lease.LeasedOn) {
		slog.Debug("Mac was leased, but is expired")
		return nil
	}

	ip := net.ParseIP(lease.IP)
	slog.Debug(fmt.Sprintf("Mac had lease to ip: %v", ip))
    return ip
}

func LeaseIP(db *sql.DB, ip net.IP, mac net.HardwareAddr, leaseLen time.Duration, leasedOn time.Time) error {
	leaseSelect := `DELETE FROM leases WHERE ip = ? AND mac = ?;`
	_, _ = db.Exec(leaseSelect, ip.String(), mac.String())

	intLen := int(leaseLen.Seconds())
	currentTime := FormatTime(leasedOn)
    insertLease := `INSERT INTO leases (ip, mac, lease_len, leased_on) VALUES (?, ?, ?, ?);`
    _, err := db.Exec(insertLease, ip.String(), mac.String(), intLen, currentTime)
    if err != nil {
        return fmt.Errorf("error leasing IP: %v", err)
    }

	return nil
}

func Unlease(db *sql.DB, dbLease *types.DatabaseLease) error {
	leaseSelect := `DELETE FROM leases WHERE ip = ? AND mac = ?;`
	_, err := db.Exec(leaseSelect, dbLease.IP, dbLease.MAC)

	return err
}

func GetLeasedIPs(db *sql.DB) ([]net.IP, error) {
    query := "SELECT id, ip FROM leases"

    rows, err := db.Query(query)
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

func GetLeases(db *sql.DB) ([]types.DatabaseLease, error) {
    query := "SELECT ip, mac, lease_len, leased_on FROM leases"

    rows, err := db.Query(query)
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

func UnleaseMAC(db *sql.DB, mac net.HardwareAddr) error {
	leaseSelect := `DELETE FROM leases WHERE mac = ?;`
	_, err := db.Exec(leaseSelect, mac.String())

    if err != nil {
        return fmt.Errorf("Error deleting MAC's lease: %v\n", err)
    }

	return nil
}

