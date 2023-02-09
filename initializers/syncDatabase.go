package initializers

import "github.com/souravdev-eng/go-auth/models"

func SyncDatabase() {
	DB.AutoMigrate(&models.User{})
}
