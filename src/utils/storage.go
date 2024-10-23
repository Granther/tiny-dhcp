package utils

import "time"

func IsExpired(leaseLen int, leasedOn string) bool {
	leasedOnTime, err := time.Parse("2006-01-02 15:04:05", leasedOn)
	if err != nil {
		return true
	}

	timeSince := time.Since(leasedOnTime)

	return int(timeSince.Seconds()) >= leaseLen
}

func FormatTime(time time.Time) string {
	return time.Format("2006-01-02 15:04:05")
}
