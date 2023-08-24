package routes

import (
	controller "gotut/jwt/controllers"
	"github.com/gin-gonic/gin"
)
func UserRoutes(incomingRoutes *gin.Engine) {
    incomingRoutes.POST("/users/signup", controller.SignUp())
    incomingRoutes.POST("/users/login", controller.Login())
	incomingRoutes.GET("/users/verifyemail/:verificationCode",controller.VerifyEmail())
}