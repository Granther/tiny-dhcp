package database

import (
    "database/sql"
    "log"
	"fmt"
	"net"
	"time"

    _ "github.com/mattn/go-sqlite3"
)

type Lease struct {
	ID			int
	IP			string
	MAC			string
	LeaseLen	int
	LeasedOn	string
}

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

func IsExpired(leaseLen int, leasedOn string) (bool) {
	format := "2006-01-02 15:04:05"

	leasedOnTime, err := time.Parse(format, leasedOn)
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
	var lease Lease

    query := "SELECT ip, lease_len, leased_on FROM leases WHERE ip = ?"
    err := db.QueryRow(query, ip.String()).Scan(&lease.IP, &lease.LeaseLen, &lease.LeasedOn)
    if err != nil {
        if err == sql.ErrNoRows {
            log.Println("No lease found for that IP")
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
	var lease Lease

    query := "SELECT ip, mac, lease_len, leased_on FROM leases WHERE mac = ?"
    err := db.QueryRow(query, mac.String()).Scan(&lease.IP, &lease.MAC, &lease.LeaseLen, &lease.LeasedOn)
    if err != nil {
        if err == sql.ErrNoRows {
            log.Println("MAC does not have a lease")
			return nil        
		}
		// Actual error return
        return nil
    }

	if IsExpired(lease.LeaseLen, lease.LeasedOn) {
		return nil
	}

    return net.ParseIP(lease.IP)
}

func LeaseIP(db *sql.DB, ip net.IP, mac net.HardwareAddr, leaseLen int, leasedOn string) (error) {
	return nil
}

func UnleaseIP(db *sql.DB, ip net.IP) (error) {
	return nil
}

func GenerateIP(db *sql.DB) (net.IP, error) {
    query := "SELECT id, ip FROM leases"

    rows, err := db.Query(query)
    if err != nil {
        return nil, ftm.Errorf("%w\n", err)
    }
    defer rows.Close()

    var leases []Lease
    for rows.Next() {
        var lease Lease
        err = rows.Scan(&lease.ID, &lease.IP)
        if err != nil {
            return nil fmt.Errorf("%w\n", err)
        }

		log.Printf("Leased IP: %v\n", lease.IP)

        leases = append(leases, lease)
    }

	return nil, nil
}

    // // Open the database connection
    // db, err := sql.Open("sqlite3", "./example.db")
    // if err != nil {
    //     log.Fatal(err)
    // }
    // defer db.Close()

    // // Create a SELECT query
    // query := "SELECT id, name, age FROM users"

    // // Execute the query, getting a result set
    // rows, err := db.Query(query)
    // if err != nil {
    //     log.Fatal(err)
    // }
    // defer rows.Close()

    // // Loop through the result set
    // var users []User
    // for rows.Next() {
    //     var user User
    //     // Read the columns (id, name, age) into variables
    //     err = rows.Scan(&user.ID, &user.Name, &user.Age)
    //     if err != nil {
    //         log.Fatal(err)
    //     }
    //     users = append(users, user)
    // }

    // // Check for errors after iterating through the rows
    // err = rows.Err()
    // if err != nil {
    //     log.Fatal(err)
    // }

    // // Print the results
    // for _, user := range users {
    //     fmt.Printf("ID: %d, Name: %s, Age: %d\n", user.ID, user.Name, user.Age)
    // }