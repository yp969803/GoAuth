package routes

import (
	controller "gotut/jwt/controllers"
	"github.com/gin-gonic/gin"
)
func UserRoutes(incomingRoutes *gin.Engine) {
    incomingRoutes.POST("/users/signup", controller.SignUp())
    incomingRoutes.POST("/users/login", controller.Login())
	incomingRoutes.GET("/users/verifyemail/:verificationCode",controller.VerifyEmail())
	incomingRoutes.POST("/users/forgotpassword",controller.ForgotPassword())
	incomingRoutes.PATCH("/users/resetpassword/:resetToken",controller.ResetPassword())
}