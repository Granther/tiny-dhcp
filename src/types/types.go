package types

type DatabaseLease struct {
	ID			int
	IP			string
	MAC			string
	Static		bool
	LeaseLen	int
	LeasedOn	string
}