package main

import (
	"nbfriend/apps/config"
	"nbfriend/apps/controller"
	"nbfriend/apps/pkg/token"
	"nbfriend/apps/response"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

func main() {
	db, err := config.ConnectDB()
	if err != nil {
		panic(err)
	}

	router := gin.New()
	router.Use(gin.Logger())

	authContoller := controller.AuthContoller{
		Db: db,
	}

	v1 := router.Group("/v1")
	router.GET("/ping", Ping)
	auth := v1.Group("/auth")

	auth.POST("register", authContoller.Register)
	auth.POST("login", authContoller.Login)
	auth.GET("profile", CheckAuth(), authContoller.Profile)

	router.Run(":4444")
}

func Ping(ctx *gin.Context) {
	ctx.JSON(http.StatusOK, map[string]interface{}{
		"message ": "OKE",
	})
}

func CheckAuth() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		header := ctx.GetHeader("Authorization")
		header = strings.TrimSpace(header)

		if !strings.HasPrefix(header, "Bearer ") {
			resp := response.ResponseAPI{
				StatusCode: http.StatusUnauthorized,
				Message:    "UNAUTHORIZED",
			}

			ctx.AbortWithStatusJSON(resp.StatusCode, resp)
			return
		}

		tokenString := strings.TrimPrefix(header, "Bearer ")

		payload, err := token.ValidateToken(tokenString)
		if err != nil {
			resp := response.ResponseAPI{
				StatusCode: http.StatusUnauthorized,
				Message:    "INVALID TOKEN",
				Payload:    err.Error(),
			}
			ctx.AbortWithStatusJSON(resp.StatusCode, resp)
			return
		}

		ctx.Set("authId", payload.AuthId)
		ctx.Next()
	}
}
