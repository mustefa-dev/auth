package models

import "github.com/jinzhu/gorm"

type UserController struct {
	DB             *gorm.DB
	JWT_SECRET_KEY string
}
