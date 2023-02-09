package main

import (
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/souravdev-eng/go-auth/controllers"
	"github.com/souravdev-eng/go-auth/initializers"
	"github.com/souravdev-eng/go-auth/middleware"
)

func init() {
	initializers.LoadEnvVariable()
	initializers.ConnectToDb()
	initializers.SyncDatabase()

}

func main() {
	fmt.Println("Hello world 2")

	r := gin.Default()
	r.POST("/signup", controllers.SignUp)
	r.POST("/login", controllers.Login)
	r.GET("/validate", middleware.RequireAuth, controllers.Validate)
	r.Run()
}
