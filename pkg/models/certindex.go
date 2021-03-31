package models

import (
	"time"
)

// CertIndex : entry in the index for a certificate
type CertIndex struct {
	Root           string
	Subject        string
	Active         bool
	SerialNumber   string
	RevocationTime time.Time
}
