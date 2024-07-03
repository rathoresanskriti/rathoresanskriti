
package controllers

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"main/database"
	"main/models"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var jwtKey = []byte("my_secret_key")

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

func GenerateJWT(username string) (string, error) {
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		Username: username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func JWTAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Authorization header is missing"})
			c.Abort()
			return
		}

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid token"})
			c.Abort()
			return
		}

		c.Set("username", claims.Username)
		c.Next()
	}
}

func AddUser(c *gin.Context) {
	var user models.User
	user.ID = primitive.NewObjectID()

	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}

	_, err := database.MongoCollection.InsertOne(context.TODO(), user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to add user to the database"})
		return
	}

	c.JSON(http.StatusCreated, user)
}

func GetUser(c *gin.Context) {
	id := c.Param("id")
	objID, _ := primitive.ObjectIDFromHex(id)
	var user models.User

	err := database.MongoCollection.FindOne(context.TODO(), bson.M{"_id": objID}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			c.JSON(http.StatusNotFound, gin.H{"message": "User not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to retrieve user"})
		return
	}

	c.JSON(http.StatusOK, user)
}


func UpdateUser(c *gin.Context) {
	id := c.Param("id")
	objID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid user ID"})
		return
	}

	var user models.User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}

	update := bson.M{
		"$set": bson.M{

			"username": user.Username,
			// Add other fields that need to be updated
		},
	}

	result, err := database.MongoCollection.UpdateOne(context.TODO(), bson.M{"_id": objID}, update)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to update user"})
		return
	}

	if result.MatchedCount == 0 {
		c.JSON(http.StatusNotFound, gin.H{"message": "User not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User updated successfully"})
}

func DeleteUser(c *gin.Context) {
	id := c.Param("id")
	objID, _ := primitive.ObjectIDFromHex(id)

	_, err := database.MongoCollection.DeleteOne(context.TODO(), bson.M{"_id": objID})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to delete user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User deleted successfully"})
}

func Login(c *gin.Context) {
	var user models.User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}

	var foundUser models.User
	err := database.MongoCollection.FindOne(context.TODO(), bson.M{"username": user.Username}).Decode(&foundUser)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid username or password"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to retrieve user"})
		return
	}

	if !CheckPassword(user.Password, foundUser.Password) {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid username or password"})
		return
	}

	token, err := GenerateJWT(user.Username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": token})
}

func CheckPassword(providedPassword, storedPassword string) bool {
	// Implement password checking logic, e.g., using bcrypt
	return providedPassword == storedPassword
}

func GetUsersWithPagination(c *gin.Context) {
	pageParam := c.Query("page")
	limitParam := c.Query("limit")

	page, err := strconv.Atoi(pageParam)
	if err != nil || page <= 0 {
		page = 1
	}

	limit, err := strconv.Atoi(limitParam)
	if err != nil || limit <= 0 {
		limit = 5
	}

	skip := (page - 1) * limit

	findOptions := options.Find()
	findOptions.SetSkip(int64(skip))
	findOptions.SetLimit(int64(limit))

	cursor, err := database.MongoCollection.Find(context.TODO(), bson.M{}, findOptions)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to retrieve users"})
		return
	}
	defer cursor.Close(context.TODO())

	var users []models.User
	if err = cursor.All(context.TODO(), &users); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to decode users"})
		return
	}

	c.JSON(http.StatusOK, users)
}

func SearchUsers(c *gin.Context) {
	filters := bson.M{}
	if username := c.Query("username"); username != "" {
		filters["username"] = username
	}
	if firstname := c.Query("firstname"); firstname != "" {
		filters["firstname"] = firstname
	}
	if lastname := c.Query("lastname"); lastname != "" {
		filters["lastname"] = lastname
	}
	if city := c.Query("city"); city != "" {
		filters["city"] = city
	}

	cursor, err := database.MongoCollection.Find(context.TODO(), filters)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to search users"})
		return
	}
	defer cursor.Close(context.TODO())

	var users []models.User
	if err = cursor.All(context.TODO(), &users); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to decode users"})
		return
	}

	c.JSON(http.StatusOK, users)
}
