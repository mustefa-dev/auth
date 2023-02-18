package models

import (
	"fmt"
	"github.com/jinzhu/gorm"
	_ "github.com/lib/pq"
)

var DB *gorm.DB

func ConnectDatabase() {
	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s "+
		"password=%s dbname=%s sslmode=disable", "localhost", 5432, "postgres", "postgres", "mcu")
	database, err := gorm.Open("postgres", psqlInfo)
	if err != nil {
		// handle error
	}

	database.AutoMigrate(&User{})
	DB = database
}

func GetDB() *gorm.DB {
	return DB
}
