package models

import "github.com/jinzhu/gorm"

// User represents a user account in the database.
type User struct {
	gorm.Model
	Username string `json:"username" gorm:"unique_index"`
	Password string `json:"password"`
}
