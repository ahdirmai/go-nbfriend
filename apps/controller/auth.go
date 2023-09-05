package controller

import (
	"database/sql"
	"nbfriend/apps/pkg/token"
	"nbfriend/apps/response"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

type AuthContoller struct {
	Db *sql.DB
}

// Definisi Variable yang akan digunakan (Input)
type RegisterRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password"`
	ImgUrl   string `json:"img_url"`
}

type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password"`
}

type Auth struct {
	Id       int
	Email    string
	Password string
}

var (
	queryCreate = `
		INSERT INTO auth (email, password, img_url)
		VALUES ($1, $2, $3)`

	queryFindByEmail = `
		SELECT id, email, password
		FROM auth
		WHERE email=$1`
)

// Function Register
func (a *AuthContoller) Register(ctx *gin.Context) {

	// Inisitasi Request sebagai Struct
	var req = RegisterRequest{}

	// Dapatkan Error
	err := ctx.ShouldBindJSON(&req)
	// Jika Error != Null, maka kerjakan perintah dibawah
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	// Menggunakan Validator
	val := validator.New()
	err = val.Struct(req)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	// Encrypt password
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	// Handle Error
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}
	// Set req.Password to password_hashed
	req.Password = string(hash)

	// Preparasi Database
	stmt, err := a.Db.Prepare(queryCreate)

	// Handle Error Prepare DB
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	// Exsekusi Statement
	_, err = stmt.Exec(
		req.Email,
		req.Password,
		req.ImgUrl,
	)

	// Handle Eksekusi Statement
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	// Respon API
	resp := response.ResponseAPI{
		StatusCode: http.StatusCreated,
		Message:    "Register Success",
	}

	ctx.JSON(resp.StatusCode, resp)
}

func (a *AuthContoller) Login(ctx *gin.Context) {

	var req = LoginRequest{}
	err := ctx.ShouldBindJSON(&req)
	// Jika Error != Null, maka kerjakan perintah dibawah
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	// Preparasi Database
	stmt, err := a.Db.Prepare(queryFindByEmail)

	// Handle Error Prepare DB
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	// Exsekusi Statement
	row := stmt.QueryRow(
		req.Email,
	)

	// Simpan hasil dari find by email ke var auth
	var auth = Auth{}
	err = row.Scan(
		&auth.Id,
		&auth.Email,
		&auth.Password,
	)

	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	// compare pass di auth dan pass di db
	err = bcrypt.CompareHashAndPassword([]byte(auth.Password), []byte(req.Password))
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusNotFound, gin.H{
			"error": err.Error(),
		})
		return
	}

	tok := token.PayloadToken{
		AuthId: auth.Id,
	}

	tokString, err := token.GenerateToken(&tok)

	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	resp := response.ResponseAPI{
		StatusCode: http.StatusOK,
		Message:    "Login Success",
		Payload: gin.H{
			"token": tokString,
		},
	}
	ctx.JSON(resp.StatusCode, resp)
}

func (a *AuthContoller) Profile(ctx *gin.Context) {
	ctx.JSON(http.StatusOK, gin.H{
		"id": ctx.GetInt("authId"),
	})

}
