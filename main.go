package main

import(
	"os"
	middleware "gotut/jwt/middlewares"
	routes "gotut/jwt/routes"
	"github.com/gin-gonic/gin"
    _ "github.com/heroku/x/hmetrics/onload"




)
func main()  {
	port := os.Getenv("PORT")
	if port == "" {
        port = "8000"
    }
    router:=gin.New()
	router.Use(gin.Logger())
	protectedRoutes := router.Group("/api")
	protectedRoutes.Use(middleware.Authentication())
	
	routes.UserRoutes(router)

	router.Run(":" + port)
}