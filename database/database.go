package database

import (
    "database/sql"
    "log"
	"fmt"
	"net"

    _ "github.com/mattn/go-sqlite3"
)

func SetupDatabase() {
	db, err := sql.Open("sqlite3", "./leases.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	leasesTableSQL := `CREATE TABLE IF NOT EXISTS leases (
        "id" INTEGER PRIMARY KEY AUTOINCREMENT,
        "mac" TEXT,
        "ip" TEXT,
		"lease_len" INTEGER,
		"leased_on" TEXT,
    );`

	err = db.Ping()
	if err != nil {
		log.Fatal(err)
	}

	_, err = db.Exec(leasesTableSQL)
    if err != nil {
        log.Fatal(err)
    }

	log.Println("Created/Opened leases.db, created leases table, all success")
}

func CreateLeasesTable(db *sql.DB) (error) {

	leasesTableSQL := `CREATE TABLE IF NOT EXISTS leases (
        "id" INTEGER PRIMARY KEY AUTOINCREMENT,
        "mac" TEXT,
        "ip" TEXT
    );`

	_, err := db.Exec(leasesTableSQL)
    if err != nil {
        return fmt.Errorf("Error creating leases table: %v\n", err)
    }

	return nil
} 

func ConnectDatabase() (*sql.DB, error) {
	db, err := sql.Open("sqlite3", "./leases.db")
    if err != nil {
        return nil, fmt.Errorf("Error occured when connecting to leases.db: %v", err)
    }
    defer db.Close()

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

func IsIPLeased(db *sql.DB, ip net.IP) (bool, error) {
	return false, nil
}

func IsMACLeased(db *sql.DB, mac net.HardwareAddr) (bool, error) {
	return false, nil
}

func LeaseIP(db *sql.DB, ip net.IP, mac net.HardwareAddr, leaseLen int, leasedOn string) (error) {
	return nil
}

func UnleaseIP(db *sql.DB, ip net.IP) (error) {
	return nil
}

func GenerateIP(db *sql.DB) (net.IP, error) {
	var ip net.IP
	return ip, nil
}