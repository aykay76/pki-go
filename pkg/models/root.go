package models

import (
	"time"
)

// Root : model of root CA
type Root struct {
	Identifier   string    `json:"id"`
	Name         string    `json:"name"`
	SerialNumber int64     `json:"serial"`
	Expiry       time.Time `json:"expires"`
}
