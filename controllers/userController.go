package controllers

import(
	"context"
	"fmt"
	"log"
	"net/http"
	
	"os"
	"github.com/joho/godotenv"
	"time"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"gotut/jwt/database"
	helper "gotut/jwt/helpers"
    "gotut/jwt/models"
    "go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
    "go.mongodb.org/mongo-driver/mongo"
    "golang.org/x/crypto/bcrypt"
	
	"github.com/thanhpk/randstr"
     "gotut/jwt/utils"


)
var userCollection *mongo.Collection = database.OpenCollection(database.Client, "user")
var validate = validator.New()
func HashPassword(password string) string  {
	bytes,err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil{
		log.Panic(err)
	}
	return string(bytes)
}

func VerifyPassword(userPassword string, providedPassword string)(bool,string)  {

	err := bcrypt.CompareHashAndPassword([]byte(providedPassword), []byte(userPassword))
    check := true
	msg:=""
	if err!=nil {
		msg=fmt.Sprintf("Invalid user credentials")
		check=false
	}
	return check,msg
}
func SignUp() gin.HandlerFunc{
	return func(c *gin.Context){
		var ctx, cancel= context.WithTimeout(context.Background(),100*time.Second)
		var user models.User 
		if err := c.BindJSON(&user);err != nil{
			c.JSON(http.StatusBadRequest, gin.H{"error":err.Error()})
			return
		}
		validationErr:= validate.Struct(user)
		if validationErr != nil {
			c.JSON(http.StatusBadRequest,gin.H{"error":validationErr.Error()})
			return
		}
		count,err := userCollection.CountDocuments(ctx, bson.M{"email":user.Email})
		defer cancel()
		if err!=nil {
			log.Panic(err)
			c.JSON(http.StatusInternalServerError,gin.H{"error":"Error occured while checking for the email"})
			return

		}
		err = godotenv.Load(".env")
		configUrl:= os.Getenv("CLIENT_ORIGIN")
	    if err!= nil{
		log.Fatal("Error loading .env file")

	    }
		password:=HashPassword(*user.Password)
		user.Password=&password
		count,err = userCollection.CountDocuments(ctx,bson.M{"phone":user.Phone})
		defer cancel()
		if err != nil {
            log.Panic(err)
            c.JSON(http.StatusInternalServerError, gin.H{"error": "error occured while checking for the phone number"})
            return
        }
		if count > 0 {
            c.JSON(http.StatusInternalServerError, gin.H{"error": "this email or phone number already exists"})
            return
        }
	
        code := randstr.String(20)
        verification_code := code
		emailData := utils.EmailData{
			URL:       configUrl + "/verifyemail/" + code,
			FirstName: *user.First_name,
			Subject:   verification_code,
		}
		user.VerificationCode=verification_code
		user.Created_at, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
        user.Updated_at, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
        user.ID = primitive.NewObjectID()
        user.User_id = user.ID.Hex()
        token, refreshToken, _ := helper.GenerateAllTokens(*user.Email, *user.First_name, *user.Last_name, user.User_id)
        user.Token = &token
        user.Refresh_token = &refreshToken
		_, insertErr := userCollection.InsertOne(ctx, user)
        utils.SendEmail(&user, &emailData)
         

		if insertErr != nil {
            msg := fmt.Sprintf("User item was not created")
            c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
            return
        }
        defer cancel()

		msg:=fmt.Sprintf("We sent an email with a verification code to %s", *user.Email)
		c.JSON(http.StatusOK, gin.H{"msg":msg})
        
	
	}

}

func VerifyEmail() gin.HandlerFunc {
	return func(c *gin.Context){
		var ctx,_=context.WithTimeout(context.Background(),100*time.Second)
		code := c.Params.ByName("verificationCode")
        
		verification_code:=code
		var user models.User 
		err:= userCollection.FindOne(ctx,bson.M{"verificationcode":verification_code}).Decode(&user)
		
		if err!=nil{
            c.JSON(http.StatusBadRequest, gin.H{"status":"fail","message": "Invalid verification code or user doesn't exists"})
			return
		}
		if user.Verified {
			c.JSON(http.StatusConflict, gin.H{"status": "fail", "message": "User already verified"})
			return

		}
		user.VerificationCode = ""
		user.Verified=true
        update := bson.D{{"$set", bson.D{{"verificationcode", ""},{"verified",true}}}}
		
		
        filter := bson.D{{"verificationcode", verification_code}}
		_, err = userCollection.UpdateOne(
			ctx,
			filter,
			update,
			
		)
		
	
		if err != nil {
			log.Panic(err)
			return
		}
		c.JSON(http.StatusOK,gin.H{"status": "success", "message": "Email verified successfully"})
        
	}
}

func Login() gin.HandlerFunc {
	return func(c *gin.Context){
		var ctx,cancel=context.WithTimeout(context.Background(),100*time.Second)
		var user models.User 
		var foundUser models.User
		if err:= c.BindJSON(&user); err!=nil{
			c.JSON(http.StatusBadRequest,gin.H{"error":err.Error()})
			return
		}
		err:= userCollection.FindOne(ctx,bson.M{"email":user.Email}).Decode(&foundUser)
		defer cancel()
        if err != nil {
            c.JSON(http.StatusInternalServerError, gin.H{"error": "login or passowrd is incorrect"})
            return
        }
		passwordIsValid, msg := VerifyPassword(*user.Password, *foundUser.Password)
        defer cancel()
        if passwordIsValid != true {
            c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
            return
        }
		if !foundUser.Verified{
			c.JSON(http.StatusBadRequest, gin.H{"error": "Email not verified"})
            return
		} 
        token, refreshToken, _ := helper.GenerateAllTokens(*foundUser.Email, *foundUser.First_name, *foundUser.Last_name, foundUser.User_id)

        helper.UpdateAllTokens(token, refreshToken, foundUser.User_id)

        c.JSON(http.StatusOK, foundUser)
	}
}