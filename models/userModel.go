package models

import(
	"time"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type User struct {

	ID             primitive.ObjectID       `bson:"_id"`
    First_name     *string                   `json:"first_name" validate:"required,min=2,max=100"`
	Last_name      *string                   `json:"last_name" validate:"required,min=2,max=100"`
	Password      *string                   `json:"Password" validate:"required,min=6"`
    Email         *string                     `json:"email" validate:"email,required"`
    Phone         *string                    `json:"phone" validate:"required"`
	Token         *string                    `json:"token"`
	Refresh_token *string                    `json:"refresh_token"`
	Created_at    time.Time                 `json:"created_at"`
	Updated_at    time.Time          `json:"updated_at"`
	User_id       string             `json:"user_id"`
    Verified      bool                        `default:"false" json:"verified"` 
	VerificationCode  string                 `json:"verificationcode"`
}

type ForgotPasswordInput struct {
	Email string `json:"email" binding:"required"`
}

type ResetPasswordInput struct {
	Password        string `json:"password" binding:"required"`
	PasswordConfirm string `json:"passwordConfirm" binding:"required"`
}
