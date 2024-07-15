// // package controllers

// // import (
// // 	"context"
// // 	"net/http"
// // 	"strconv"
// // 	"time"

// // 	"main/database"
// // 	"main/models"

// // 	"github.com/dgrijalva/jwt-go"
// // 	"github.com/gin-gonic/gin"
// // 	"go.mongodb.org/mongo-driver/bson"
// // 	"go.mongodb.org/mongo-driver/bson/primitive"
// // 	"go.mongodb.org/mongo-driver/mongo"
// // 	"go.mongodb.org/mongo-driver/mongo/options"
// // 	"golang.org/x/crypto/bcrypt"
// // )

// // var jwtKey = []byte("my_secret_key")

// // type Claims struct {
// // 	Username string `json:"username"`
// // 	jwt.StandardClaims
// // }

// // func GenerateJWT(username string) (string, error) {
// // 	expirationTime := time.Now().Add(24 * time.Hour)
// // 	claims := &Claims{
// // 		Username: username,
// // 		StandardClaims: jwt.StandardClaims{
// // 			ExpiresAt: expirationTime.Unix(),
// // 		},
// // 	}
// // 	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
// // 	tokenString, err := token.SignedString(jwtKey)
// // 	if err != nil {
// // 		return "", err
// // 	}
// // 	return tokenString, nil
// // }

// // func JWTAuthMiddleware() gin.HandlerFunc {
// // 	return func(c *gin.Context) {
// // 		tokenString := c.GetHeader("Authorization")
// // 		if tokenString == "" {
// // 			c.JSON(http.StatusUnauthorized, gin.H{"message": "Authorization header is missing"})
// // 			c.Abort()
// // 			return
// // 		}

// // 		claims := &Claims{}
// // 		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
// // 			return jwtKey, nil
// // 		})

// // 		if err != nil || !token.Valid {
// // 			c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid token"})
// // 			c.Abort()
// // 			return
// // 		}

// // 		c.Set("username", claims.Username)
// // 		c.Next()
// // 	}
// // }

// // func AddUser(c *gin.Context) {
// // 	var user models.User
// // 	user.ID = primitive.NewObjectID()

// // 	if err := c.ShouldBindJSON(&user); err != nil {
// // 		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
// // 		return
// // 	}

// // 	hashedPassword, err := HashPassword(user.Password)
// // 	if err != nil {
// // 		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to hash password"})
// // 		return
// // 	}
// // 	user.Password = hashedPassword

// // 	dbName := "memberdb_" + user.Username

// // 	userCollection := database.MongoClient.Database(dbName).Collection("Details")
// // 	memberCollection := database.MongoClient.Database("general_memberdb").Collection("Details")

// // 	_, err = userCollection.InsertOne(context.TODO(), user)
// // 	if err != nil {
// // 		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to add user to the database"})
// // 		return
// // 	}

// // 	_, err = memberCollection.InsertOne(context.TODO(), user)
// // 	if err != nil {
// // 		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to add user to the general member database"})
// // 		return
// // 	}

// // 	c.JSON(http.StatusCreated, user)
// // }

// // func GetUser(c *gin.Context) {
// // 	username, exists := c.Get("username")
// // 	if !exists {
// // 		c.JSON(http.StatusUnauthorized, gin.H{"message": "Unauthorized"})
// // 		return
// // 	}

// // 	dbName := "memberdb_" + username.(string)
// // 	userCollection := database.MongoClient.Database(dbName).Collection("Details")

// // 	id := c.Param("id")
// // 	objID, _ := primitive.ObjectIDFromHex(id)
// // 	var user models.User

// // 	err := userCollection.FindOne(context.TODO(), bson.M{"_id": objID}).Decode(&user)
// // 	if err != nil {
// // 		if err == mongo.ErrNoDocuments {
// // 			c.JSON(http.StatusNotFound, gin.H{"message": "User not found"})
// // 			return
// // 		}
// // 		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to retrieve user"})
// // 		return
// // 	}

// // 	c.JSON(http.StatusOK, user)
// // }

// // func UpdateUser(c *gin.Context) {
// // 	currentUsername, exists := c.Get("username")
// // 	if !exists {
// // 		c.JSON(http.StatusUnauthorized, gin.H{"message": "Unauthorized"})
// // 		return
// // 	}

// // 	currentDbName := "memberdb_" + currentUsername.(string)
// // 	currentUserCollection := database.MongoClient.Database(currentDbName).Collection("Details")
// // 	memberCollection := database.MongoClient.Database("general_memberdb").Collection("Details")

// // 	id := c.Param("id")
// // 	objID, err := primitive.ObjectIDFromHex(id)
// // 	if err != nil {
// // 		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid user ID"})
// // 		return
// // 	}

// // 	var user models.User
// // 	if err := c.ShouldBindJSON(&user); err != nil {
// // 		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
// // 		return
// // 	}

// // 	if user.Password != "" {
// // 		hashedPassword, err := HashPassword(user.Password)
// // 		if err != nil {
// // 			c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to hash password"})
// // 			return
// // 		}
// // 		user.Password = hashedPassword
// // 	}

// // 	update := bson.M{
// // 		"$set": bson.M{
// // 			"username":        user.Username,
// // 			"firstname":       user.Firstname,
// // 			"lastname":        user.Lastname,
// // 			"password":        user.Password,
// // 			"cellNumber":      user.CellPhoneNumber,
// // 			"homeNumber":      user.HomePhoneNumber,
// // 			"address":         user.Address,
// // 			"city":            user.City,
// // 			"province":        user.Province,
// // 			"postalCode":      user.PostalCode,
// // 			"role":            user.Role,
// // 		},
// // 	}

// // 	result, err := currentUserCollection.UpdateOne(context.TODO(), bson.M{"_id": objID}, update)
// // 	if err != nil {
// // 		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to update user"})
// // 		return
// // 	}

// // 	if result.MatchedCount == 0 {
// // 		c.JSON(http.StatusNotFound, gin.H{"message": "User not found"})
// // 		return
// // 	}

// // 	_, err = memberCollection.UpdateOne(context.TODO(), bson.M{"_id": objID}, update)
// // 	if err != nil {
// // 		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to update user in general member database"})
// // 		return
// // 	}

// // 	if currentUsername != user.Username {
// // 		newDbName := "memberdb_" + user.Username

// // 		err := copyDatabase(database.MongoClient, currentDbName, newDbName)
// // 		if err != nil {
// // 			c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to copy database"})
// // 			return
// // 		}

// // 		err = database.MongoClient.Database(currentDbName).Drop(context.TODO())
// // 		if err != nil {
// // 			c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to drop old database"})
// // 			return
// // 		}
// // 	}

// // 	c.JSON(http.StatusOK, gin.H{"message": "User updated successfully"})
// // }

// // func copyDatabase(client *mongo.Client, currentDbName, newDbName string) error {
// // 	collections, err := client.Database(currentDbName).ListCollectionNames(context.TODO(), bson.M{})
// // 	if err != nil {
// // 		return err
// // 	}

// // 	for _, collectionName := range collections {
// // 		currentCollection := client.Database(currentDbName).Collection(collectionName)
// // 		newCollection := client.Database(newDbName).Collection(collectionName)

// // 		cursor, err := currentCollection.Find(context.TODO(), bson.M{})
// // 		if err != nil {
// // 			return err
// // 		}

// // 		var documents []interface{}
// // 		if err = cursor.All(context.TODO(), &documents); err != nil {
// // 			return err
// // 		}

// // 		if len(documents) > 0 {
// // 			_, err = newCollection.InsertMany(context.TODO(), documents)
// // 			if err != nil {
// // 				return err
// // 			}
// // 		}
// // 	}

// // 	return nil
// // }

// // func DeleteUser(c *gin.Context) {
// // 	username, exists := c.Get("username")
// // 	if !exists {
// // 		c.JSON(http.StatusUnauthorized, gin.H{"message": "Unauthorized"})
// // 		return
// // 	}

// // 	dbName := "memberdb_" + username.(string)
// // 	userCollection := database.MongoClient.Database(dbName).Collection("Details")
// // 	memberCollection := database.MongoClient.Database("general_memberdb").Collection("Details")

// // 	id := c.Param("id")
// // 	objID, _ := primitive.ObjectIDFromHex(id)

// // 	_, err := userCollection.DeleteOne(context.TODO(), bson.M{"_id": objID})
// // 	if err != nil {
// // 		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to delete user"})
// // 		return
// // 	}

// // 	_, err = memberCollection.DeleteOne(context.TODO(), bson.M{"_id": objID})
// // 	if err != nil {
// // 		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to delete user from general member database"})
// // 		return
// // 	}

// // 	c.JSON(http.StatusOK, gin.H{"message": "User deleted successfully"})
// // }

// // func Login(c *gin.Context) {
// // 	var user models.User
// // 	if err := c.ShouldBindJSON(&user); err != nil {
// // 		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
// // 		return
// // 	}

// // 	dbName := "memberdb_" + user.Username
// // 	userCollection := database.MongoClient.Database(dbName).Collection("Details")

// // 	var foundUser models.User
// // 	err := userCollection.FindOne(context.TODO(), bson.M{"username": user.Username}).Decode(&foundUser)
// // 	if err != nil {
// // 		if err == mongo.ErrNoDocuments {
// // 			c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid username or password"})
// // 			return
// // 		}
// // 		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to retrieve user"})
// // 		return
// // 	}

// // 	if !CheckPassword(user.Password, foundUser.Password) {
// // 		c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid username or password"})
// // 		return
// // 	}

// // 	token, err := GenerateJWT(user.Username)
// // 	if err != nil {
// // 		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to generate token"})
// // 		return
// // 	}

// // 	c.JSON(http.StatusOK, gin.H{"token": token})
// // }

// // func CheckPassword(providedPassword, storedPassword string) bool {
// // 	err := bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(providedPassword))
// // 	return err == nil
// // }

// // func HashPassword(password string) (string, error) {
// // 	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
// // 	return string(bytes), err
// // }

// // func GetUsersWithPagination(c *gin.Context) {
// // 	username, exists := c.Get("username")
// // 	if !exists {
// // 		c.JSON(http.StatusUnauthorized, gin.H{"message": "Unauthorized"})
// // 		return
// // 	}

// // 	dbName := "memberdb_" + username.(string)
// // 	userCollection := database.MongoClient.Database(dbName).Collection("Details")

// // 	pageParam := c.Query("page")
// // 	limitParam := c.Query("limit")

// // 	page, err := strconv.Atoi(pageParam)
// // 	if err != nil || page <= 0 {
// // 		page = 1
// // 	}

// // 	limit, err := strconv.Atoi(limitParam)
// // 	if err != nil || limit <= 0 {
// // 		limit = 10
// // 	}

// // 	skip := (page - 1) * limit

// // 	findOptions := options.Find()
// // 	findOptions.SetSkip(int64(skip))
// // 	findOptions.SetLimit(int64(limit))

// // 	cursor, err := userCollection.Find(context.TODO(), bson.M{}, findOptions)
// // 	if err != nil {
// // 		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to retrieve users"})
// // 		return
// // 	}
// // 	defer cursor.Close(context.TODO())

// // 	var users []models.User
// // 	for cursor.Next(context.TODO()) {
// // 		var user models.User
// // 		if err := cursor.Decode(&user); err != nil {
// // 			c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to decode user"})
// // 			return
// // 		}
// // 		users = append(users, user)
// // 	}

// // 	if err := cursor.Err(); err != nil {
// // 		c.JSON(http.StatusInternalServerError, gin.H{"message": "Cursor error"})
// // 		return
// // 	}

// // 	c.JSON(http.StatusOK, users)
// // }

// package controllers

// import (
// 	"context"
// 	"log"
// 	"math/rand"
// 	"net/http"
// 	"strconv"
// 	"time"

// 	"main/database"
// 	"main/models"

// 	"github.com/dgrijalva/jwt-go"
// 	"github.com/gin-gonic/gin"
// 	"go.mongodb.org/mongo-driver/bson"
// 	"go.mongodb.org/mongo-driver/bson/primitive"
// 	"go.mongodb.org/mongo-driver/mongo"
// 	"go.mongodb.org/mongo-driver/mongo/options"
// 	"golang.org/x/crypto/bcrypt"
// )

// var jwtKey = []byte("my_secret_key")

// type Claims struct {
// 	Username string `json:"username"`
// 	jwt.StandardClaims
// }

// func GenerateJWT(username string) (string, error) {
// 	expirationTime := time.Now().Add(24 * time.Hour)
// 	claims := &Claims{
// 		Username: username,
// 		StandardClaims: jwt.StandardClaims{
// 			ExpiresAt: expirationTime.Unix(),
// 		},
// 	}
// 	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
// 	tokenString, err := token.SignedString(jwtKey)
// 	if err != nil {
// 		return "", err
// 	}
// 	return tokenString, nil
// }

// // func JWTAuthMiddleware() gin.HandlerFunc {
// // 	return func(c *gin.Context) {
// // 		tokenString := c.GetHeader("Authorization")
// // 		if tokenString == "" {
// // 			c.JSON(http.StatusUnauthorized, gin.H{"message": "Authorization header is missing"})
// // 			c.Abort()
// // 			return
// // 		}

// // 		claims := &Claims{}
// // 		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
// // 			return jwtKey, nil
// // 		})

// // 		if err != nil || !token.Valid {
// // 			c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid token"})
// // 			c.Abort()
// // 			return
// // 		}

// // 		c.Set("username", claims.Username)
// // 		c.Next()
// // 	}
// // }

// func JWTAuthMiddleware() gin.HandlerFunc {
// 	return func(c *gin.Context) {
// 		tokenString := c.GetHeader("Authorization")
// 		if tokenString == "" {
// 			c.JSON(http.StatusUnauthorized, gin.H{"message": "Authorization header is missing"})
// 			c.Abort()
// 			return
// 		}

// 		claims := &Claims{}
// 		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
// 			return jwtKey, nil
// 		})

// 		if err != nil || !token.Valid {
// 			c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid token"})
// 			c.Abort()
// 			return
// 		}

// 		tenantID := c.GetHeader("Tenant-ID")
// 		if tenantID == "" {
// 			c.JSON(http.StatusBadRequest, gin.H{"message": "Tenant-ID header is missing"})
// 			c.Abort()
// 			return
// 		}

// 		c.Set("username", claims.Username)
// 		c.Set("tenant_id", tenantID)
// 		c.Next()
// 	}
// }

// func generateTenantID() string {
// 	rand.Seed(time.Now().UnixNano())
// 	return "vyz_" + strconv.Itoa(rand.Intn(100000000))
// }

// func AddUser(c *gin.Context) {
// 	var user models.User
// 	user.ID = primitive.NewObjectID()
// 	user.TenantID = generateTenantID()

// 	if err := c.ShouldBindJSON(&user); err != nil {
// 		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
// 		return
// 	}

// 	hashedPassword, err := HashPassword(user.Password)
// 	if err != nil {
// 		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to hash password"})
// 		return
// 	}
// 	user.Password = hashedPassword

// 	dbName := "memberdb_" + user.Username

// 	userCollection := database.MongoClient.Database(dbName).Collection("Details")
// 	memberCollection := database.MongoClient.Database("general_memberdb").Collection("Details")

// 	_, err = userCollection.InsertOne(context.TODO(), user)
// 	if err != nil {
// 		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to add user to the database"})
// 		return
// 	}

// 	_, err = memberCollection.InsertOne(context.TODO(), user)
// 	if err != nil {
// 		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to add user to the general member database"})
// 		return
// 	}

// 	c.JSON(http.StatusCreated, user)
// }

// // func GetUser(c *gin.Context) {
// // 	username, exists := c.Get("username")
// // 	if !exists {
// // 		c.JSON(http.StatusUnauthorized, gin.H{"message": "Unauthorized"})
// // 		return
// // 	}

// // 	tenantID := c.Param("tenant_id")
// // 	dbName := "memberdb_" + username.(string)
// // 	userCollection := database.MongoClient.Database(dbName).Collection("Details")

// // 	var user models.User
// // 	err := userCollection.FindOne(context.TODO(), bson.M{"tenant_id": tenantID}).Decode(&user)
// // 	if err != nil {
// // 		if err == mongo.ErrNoDocuments {
// // 			c.JSON(http.StatusNotFound, gin.H{"message": "User not found"})
// // 			return
// // 		}
// // 		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to retrieve user"})
// // 		return
// // 	}

// // 	c.JSON(http.StatusOK, user)
// // }

// // func GetUser(c *gin.Context) {
// // 	username, exists := c.Get("username")
// // 	if !exists {
// // 		c.JSON(http.StatusUnauthorized, gin.H{"message": "Unauthorized"})
// // 		return
// // 	}

// // 	tenantID, exists := c.Get("tenant_id")
// // 	if !exists {
// // 		c.JSON(http.StatusBadRequest, gin.H{"message": "Tenant-ID is missing"})
// // 		return
// // 	}

// // 	dbName := "memberdb_" + username.(string)
// // 	userCollection := database.MongoClient.Database(dbName).Collection("Details")

// // 	var user models.User
// // 	err := userCollection.FindOne(context.TODO(), bson.M{"tenant_id": tenantID.(string)}).Decode(&user)
// // 	if err != nil {
// // 		if err == mongo.ErrNoDocuments {
// // 			c.JSON(http.StatusNotFound, gin.H{"message": "User not found"})
// // 			return
// // 		}
// // 		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to retrieve user"})
// // 		return
// // 	}

// // 	c.JSON(http.StatusOK, user)
// // }

// func GetUser(c *gin.Context) {
// 	username, exists := c.Get("username")
// 	if !exists {
// 		c.JSON(http.StatusUnauthorized, gin.H{"message": "Unauthorized"})
// 		return
// 	}

// 	tenantID, exists := c.Get("tenant_id")
// 	if !exists {
// 		c.JSON(http.StatusBadRequest, gin.H{"message": "Tenant-ID is missing"})
// 		return
// 	}

// 	log.Printf("username: %s, tenant_id: %s", username, tenantID)

// 	dbName := "memberdb_" + username.(string)
// 	userCollection := database.MongoClient.Database(dbName).Collection("Details")

// 	var user models.User
// 	err := userCollection.FindOne(context.TODO(), bson.M{"tenant_id": tenantID.(string)}).Decode(&user)
// 	if err != nil {
// 		if err == mongo.ErrNoDocuments {
// 			log.Printf("User with tenant_id %s not found in database %s", tenantID, dbName)
// 			c.JSON(http.StatusNotFound, gin.H{"message": "User not found"})
// 			return
// 		}
// 		log.Printf("Error finding user: %v", err)
// 		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to retrieve user"})
// 		return
// 	}

// 	log.Printf("User found: %+v", user)
// 	c.JSON(http.StatusOK, user)
// }

// // func UpdateUser(c *gin.Context) {
// // 	currentUsername, exists := c.Get("username")
// // 	if !exists {
// // 		c.JSON(http.StatusUnauthorized, gin.H{"message": "Unauthorized"})
// // 		return
// // 	}

// // 	currentDbName := "memberdb_" + currentUsername.(string)
// // 	currentUserCollection := database.MongoClient.Database(currentDbName).Collection("Details")
// // 	memberCollection := database.MongoClient.Database("general_memberdb").Collection("Details")

// // 	tenantID := c.Param("tenant_id")

// // 	var user models.User
// // 	if err := c.ShouldBindJSON(&user); err != nil {
// // 		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
// // 		return
// // 	}

// // 	if user.Password != "" {
// // 		hashedPassword, err := HashPassword(user.Password)
// // 		if err != nil {
// // 			c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to hash password"})
// // 			return
// // 		}
// // 		user.Password = hashedPassword
// // 	}

// // 	update := bson.M{
// // 		"$set": bson.M{
// // 			"username":        user.Username,
// // 			"firstname":       user.Firstname,
// // 			"lastname":        user.Lastname,
// // 			"password":        user.Password,
// // 			"cellNumber":      user.CellPhoneNumber,
// // 			"homeNumber":      user.HomePhoneNumber,
// // 			"address":         user.Address,
// // 			"city":            user.City,
// // 			"province":        user.Province,
// // 			"postalCode":      user.PostalCode,
// // 			"role":            user.Role,
// // 		},
// // 	}

// // 	result, err := currentUserCollection.UpdateOne(context.TODO(), bson.M{"tenant_id": tenantID}, update)
// // 	if err != nil {
// // 		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to update user"})
// // 		return
// // 	}

// // 	if result.MatchedCount == 0 {
// // 		c.JSON(http.StatusNotFound, gin.H{"message": "User not found"})
// // 		return
// // 	}

// // 	_, err = memberCollection.UpdateOne(context.TODO(), bson.M{"tenant_id": tenantID}, update)
// // 	if err != nil {
// // 		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to update user in general member database"})
// // 		return
// // 	}

// // 	if currentUsername != user.Username {
// // 		newDbName := "memberdb_" + user.Username

// // 		err := copyDatabase(database.MongoClient, currentDbName, newDbName)
// // 		if err != nil {
// // 			c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to copy database"})
// // 			return
// // 		}

// // 		err = database.MongoClient.Database(currentDbName).Drop(context.TODO())
// // 		if err != nil {
// // 			c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to drop old database"})
// // 			return
// // 		}
// // 	}

// // 	c.JSON(http.StatusOK, gin.H{"message": "User updated successfully"})
// // }

// func DeleteUser(c *gin.Context) {
// 	username, exists := c.Get("username")
// 	if !exists {
// 		c.JSON(http.StatusUnauthorized, gin.H{"message": "Unauthorized"})
// 		return
// 	}

// 	tenantID := c.Param("tenant_id")
// 	dbName := "memberdb_" + username.(string)
// 	userCollection := database.MongoClient.Database(dbName).Collection("Details")
// 	memberCollection := database.MongoClient.Database("general_memberdb").Collection("Details")

// 	_, err := userCollection.DeleteOne(context.TODO(), bson.M{"tenant_id": tenantID})
// 	if err != nil {
// 		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to delete user"})
// 		return
// 	}

// 	_, err = memberCollection.DeleteOne(context.TODO(), bson.M{"tenant_id": tenantID})
// 	if err != nil {
// 		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to delete user from general member database"})
// 		return
// 	}

// 	c.JSON(http.StatusOK, gin.H{"message": "User deleted successfully"})
// }

// func Login(c *gin.Context) {
// 	var user models.User
// 	if err := c.ShouldBindJSON(&user); err != nil {
// 		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
// 		return
// 	}

// 	dbName := "memberdb_" + user.Username
// 	userCollection := database.MongoClient.Database(dbName).Collection("Details")

// 	var foundUser models.User
// 	err := userCollection.FindOne(context.TODO(), bson.M{"username": user.Username}).Decode(&foundUser)
// 	if err != nil {
// 		if err == mongo.ErrNoDocuments {
// 			c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid username or password"})
// 			return
// 		}
// 		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to retrieve user"})
// 		return
// 	}

// 	if !CheckPassword(user.Password, foundUser.Password) {
// 		c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid username or password"})
// 		return
// 	}

// 	token, err := GenerateJWT(user.Username)
// 	if err != nil {
// 		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to generate token"})
// 		return
// 	}

// 	c.JSON(http.StatusOK, gin.H{"token": token})
// }

// func CheckPassword(providedPassword, storedPassword string) bool {
// 	err := bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(providedPassword))
// 	return err == nil
// }

// func HashPassword(password string) (string, error) {
// 	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
// 	return string(bytes), err
// }

// func GetUsersWithPagination(c *gin.Context) {
// 	username, exists := c.Get("username")
// 	if !exists {
// 		c.JSON(http.StatusUnauthorized, gin.H{"message": "Unauthorized"})
// 		return
// 	}

// 	dbName := "memberdb_" + username.(string)
// 	userCollection := database.MongoClient.Database(dbName).Collection("Details")

// 	pageParam := c.Query("page")
// 	limitParam := c.Query("limit")

// 	page, err := strconv.Atoi(pageParam)
// 	if err != nil || page <= 0 {
// 		page = 1
// 	}

// 	limit, err := strconv.Atoi(limitParam)
// 	if err != nil || limit <= 0 {
// 		limit = 10
// 	}

// 	skip := (page - 1) * limit

// 	findOptions := options.Find()
// 	findOptions.SetSkip(int64(skip))
// 	findOptions.SetLimit(int64(limit))

// 	cursor, err := userCollection.Find(context.TODO(), bson.M{}, findOptions)
// 	if err != nil {
// 		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to retrieve users"})
// 		return
// 	}
// 	defer cursor.Close(context.TODO())

// 	var users []models.User
// 	for cursor.Next(context.TODO()) {
// 		var user models.User
// 		if err := cursor.Decode(&user); err != nil {
// 			c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to decode user"})
// 			return
// 		}
// 		users = append(users, user)
// 	}

// 	if err := cursor.Err(); err != nil {
// 		c.JSON(http.StatusInternalServerError, gin.H{"message": "Cursor error"})
// 		return
// 	}

// 	c.JSON(http.StatusOK, users)
// }

package controllers

import (
	"context"
	"log"
	//	"log"
	"math/rand"
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

	//	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
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

		tenantID := c.GetHeader("Tenant_id")
		if tenantID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"message": "Tenant-ID header is missing"})
			c.Abort()
			return
		}

		c.Set("username", claims.Username)
		c.Set("tenant_id", tenantID)
		c.Next()
	}
}

func generateTenantID() string {
	rand.Seed(time.Now().UnixNano())
	return "vyz_" + strconv.Itoa(rand.Intn(100000000))
}

func AddUser(c *gin.Context) {
	var user models.User
	user.ID = primitive.NewObjectID()
	user.TenantID = generateTenantID()

	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}

	hashedPassword, err := HashPassword(user.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to hash password"})
		return
	}
	user.Password = hashedPassword

	dbName := "memberdb_" + user.Username
	
	userCollection := database.MongoClient.Database(dbName).Collection("Details")
	memberCollection := database.MongoClient.Database("general_memberdb").Collection("Details")

	_, err = userCollection.InsertOne(context.TODO(), user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to add user to the database"})
		return
	}

	_, err = memberCollection.InsertOne(context.TODO(), user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to add user to the general member database"})
		return
	}

	c.JSON(http.StatusCreated, user)
}

func GetUser(c *gin.Context) {
	username, exists := c.Get("username")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Unauthorized"})
		return
	}

	tenantID, exists := c.Get("tenant_id")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Tenant-ID is missing"})
		return
	}

	log.Printf("username: %s, tenant_id: %s", username, tenantID)

	dbName := "memberdb_" + username.(string)
	userCollection := database.MongoClient.Database(dbName).Collection("Details")

	var user models.User
	err := userCollection.FindOne(context.TODO(), bson.M{"tenant_id": tenantID.(string)}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			log.Printf("User with tenant_id %s not found in database %s", tenantID, dbName)
			c.JSON(http.StatusNotFound, gin.H{"message": "User not found"})
			return
		}
		log.Printf("Error finding user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to retrieve user"})
		return
	}

	log.Printf("User found: %+v", user)
	c.JSON(http.StatusOK, user)
}




// func UpdateUser(c *gin.Context) {
// 	currentUsername, exists := c.Get("username")
// 	if !exists {
// 		c.JSON(http.StatusUnauthorized, gin.H{"message": "Unauthorized"})
// 		return
// 	}

// 	currentDbName := "memberdb_" + currentUsername.(string)
// 	currentUserCollection := database.MongoClient.Database(currentDbName).Collection("Details")
// 	memberCollection := database.MongoClient.Database("general_memberdb").Collection("Details")

// 	tenantID := c.Param("tenant_id")

// 	var user models.User
// 	if err := c.ShouldBindJSON(&user); err != nil {
// 		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
// 		return
// 	}

// 	if user.Password != "" {
// 		hashedPassword, err := HashPassword(user.Password)
// 		if err != nil {
// 			c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to hash password"})
// 			return
// 		}
// 		user.Password = hashedPassword
// 	}

// 	update := bson.M{
// 		"$set": bson.M{
// 			"username":        user.Username,
// 			"firstname":       user.Firstname,
// 			"lastname":        user.Lastname,
// 			"password":        user.Password,
// 			"cellNumber":      user.CellPhoneNumber,
// 			"homeNumber":      user.HomePhoneNumber,
// 			"address":         user.Address,
// 			"city":            user.City,
// 			"province":        user.Province,
// 			"postalCode":      user.PostalCode,
// 			"role":            user.Role,
// 		},
// 	}

// 	result, err := currentUserCollection.UpdateOne(context.TODO(), bson.M{"tenant_id": tenantID}, update)
// 	if err != nil {
// 		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to update user"})
// 		return
// 	}

// 	if result.MatchedCount == 0 {
// 		c.JSON(http.StatusNotFound, gin.H{"message": "User not found"})
// 		return
// 	}

// 	_, err = memberCollection.UpdateOne(context.TODO(), bson.M{"tenant_id": tenantID}, update)
// 	if err != nil {
// 		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to update user in general member database"})
// 		return
// 	}

// 	if currentUsername != user.Username {
// 		newDbName := "memberdb_" + user.Username
// currentUsername := ""
// 		err := copyDatabase(database.MongoClient, currentDbName, newDbName)
// 		if err != nil {
// 			c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to copy database"})
// 			return
// 		}

// 		err = database.MongoClient.Database(currentDbName).Drop(context.TODO())
// 		if err != nil {
// 			c.JSON	currentUsername := ""(http.StatusInternalServerError, gin.H{"message": "Failed to drop old database"})
// 			return
// 		}
// 	}

// 	c.JSON(http.StatusOK, gin.H{"message": "User updated successfully"})
// } 

// func UpdateUser(c *gin.Context) {
// 	// Authorization check
// 	token := c.GetHeader("Authorization")
// 	if token == "" {
// 		c.JSON(http.StatusUnauthorized, gin.H{"message": "Authorization token is required"})
// 		return
// 	}

// 	// Extract current username from context
// 	currentUsername, exists := c.Get("username")
// 	if !exists {
// 		c.JSON(http.StatusUnauthorized, gin.H{"message": "Unauthorized"})
// 		return
// 	}

// 	// Construct current database name
// 	currentDbName := "memberdb_" + currentUsername.(string)
// 	currentUserCollection := database.MongoClient.Database(currentDbName).Collection("Details")

// 	// Get tenantID from header
// 	tenantID := c.GetHeader("tenant_id")
// 	if tenantID == "" {
// 		c.JSON(http.StatusBadRequest, gin.H{"message": "Tenant-ID header is missing"})
// 		return
// 	}

// 	// Bind JSON data to user model
// 	var user models.User
// 	if err := c.ShouldBindJSON(&user); err != nil {
// 		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
// 		return
// 	}

// 	// Define update operation
// 	update := bson.M{
// 		"$set": bson.M{
// 			"username":      user.Username,
// 			"firstname":     user.Firstname,
// 			"lastname":      user.Lastname,
// 			"password":      user.Password, // Example: Update password if provided
// 			"cellNumber":    user.CellPhoneNumber,
// 			"homeNumber":    user.HomePhoneNumber,
// 			"address":       user.Address,
// 			"city":          user.City,
// 			"province":      user.Province,
// 			"postalCode":    user.PostalCode,
// 			"role":          user.Role,
// 		},
// 	}

// 	// Log the update operation for debugging
// 	log.Printf("Updating user with tenant_id %s in database %s", tenantID, currentDbName)

// 	// Perform update in current user database
// 	result, err := currentUserCollection.UpdateOne(context.TODO(), bson.M{"tenant_id": tenantID}, update)
// 	if err != nil {
// 		log.Printf("Failed to update user in current database: %v", err)
// 		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to update user"})
// 		return
// 	}

// 	if result.MatchedCount == 0 {
// 		log.Printf("User not found in current database with tenant_id %s", tenantID)
// 		c.JSON(http.StatusNotFound, gin.H{"message": "User not found"})
// 		return
// 	}

// 	log.Printf("User updated in current database with tenant_id %s", tenantID)

// 	// Handle database name update if username is changed
// 	if currentUsername != user.Username {
// 		newDbName := "memberdb_" + user.Username

// 		err := copyDatabase(database.MongoClient, currentDbName, newDbName)
// 		if err != nil {
// 			log.Printf("Failed to copy database: %v", err)
// 			c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to copy database"})
// 			return
// 		}

// 		// Drop old database after copying
// 		// err = database.MongoClient.Database(currentDbName).Drop(context.TODO())
// 		// if err != nil {
// 		// 	log.Printf("Failed to drop old database: %v", err)
// 		// 	c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to drop old database"})
// 		// 	return
// 		// }

// 		// log.Printf("Database %s dropped successfully", currentDbName)
// 	}

// 	c.JSON(http.StatusOK, gin.H{"message": "User updated successfully"})
// }


// func UpdateUser(c *gin.Context) {
	
// 	token := c.GetHeader("Authorization")
// 	if token == "" {
// 		c.JSON(http.StatusUnauthorized, gin.H{"message": "Authorization token is required"})
// 		return
// 	}
// 	currentUsername, exists := c.Get("username")
// 		if !exists {
// 			c.JSON(http.StatusUnauthorized, gin.H{"message": "Unauthorized"})
// 			return
// 		}
	
// 		currentDbName := "memberdb_" + currentUsername.(string)


	
// 	currentUserCollection := database.MongoClient.Database(currentDbName).Collection("Details")
// 	//memberCollection := database.MongoClient.Database("general_memberdb").Collection("Details")

	
// 	tenantID := c.GetHeader("tenantID")
// 	if tenantID == "" {
// 		c.JSON(http.StatusBadRequest, gin.H{"message": "Tenant-ID header is missing"})
// 		return
// 	}

// 	var user models.User
// 	if err := c.ShouldBindJSON(&user); err != nil {
// 		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
// 		return
// 	}
// 	update := bson.M{
// 		"$set": bson.M{
// 			"username":      user.Username,
// 			"firstname":     user.Firstname,
// 			"lastname":      user.Lastname,
// 			"password":      user.Password, // Example: Update password if provided
// 			"cellNumber":    user.CellPhoneNumber,
// 			"homeNumber":    user.HomePhoneNumber,
// 			"address":       user.Address,
// 			"city":          user.City,
// 			"province":      user.Province,
// 			"postalCode":    user.PostalCode,
// 			"role":          user.Role,
// 		},
// 	}

// 	// Log the update operation for debugging
// 	log.Printf("Updating user with tenantID %s in database %s", tenantID, currentDbName)

// 	// Perform update in current user database
// 	result, err := currentUserCollection.UpdateOne(context.TODO(), bson.M{"tenantID": tenantID}, update)
// 	if err != nil {
// 		log.Printf("Failed to update user in current database: %v", err)
// 		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to update user"})
// 		return
// 	}

// 	if result.MatchedCount == 0 {
// 		log.Printf("User not found in current database with tenantID %s", tenantID)
// 		c.JSON(http.StatusNotFound, gin.H{"message": "User not found"})
// 		return
// 	}

// 	log.Printf("User updated in current database with tenantID %s", tenantID)

// 	// Perform update in general member database
// 	// _, err = memberCollection.UpdateOne(context.TODO(), bson.M{"tenantID": tenantID}, update)
// 	// if err != nil {
// 	// 	log.Printf("Failed to update user in general member database: %v", err)
// 	// 	c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to update user in general member database"})
// 	// 	return
// 	// }

// 	log.Printf("User updated in general member database with tenantID %s", tenantID)

// 	// Handle database name update if username is changed
// 	if currentUsername != user.Username {
// 		newDbName := "memberdb_" + user.Username

// 		err := copyDatabase(database.MongoClient, currentDbName, newDbName)
// 		if err != nil {
// 			log.Printf("Failed to copy database: %v", err)
// 			c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to copy database"})
// 			return
// 		}

// 		// Drop old database
// 		err = database.MongoClient.Database(currentDbName).Drop(context.TODO())
// 		if err != nil {
// 			log.Printf("Failed to drop old database: %v", err)
// 			c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to drop old database"})
// 			return
// 		}

// 		log.Printf("Database %s dropped successfully", currentDbName)
// 	}

// 	c.JSON(http.StatusOK, gin.H{"message": "User updated successfully"})
// }

// func UpdateUser(c *gin.Context) {
// 	token := c.GetHeader("Authorization")
// 	if token == "" {
// 		c.JSON(http.StatusUnauthorized, gin.H{"message": "Authorization token is required"})
// 		return
// 	}
// 	currentUsername, exists := c.Get("username")
// 	if !exists {
// 		c.JSON(http.StatusUnauthorized, gin.H{"message": "Unauthorized"})
// 		return
// 	}

// 	currentDbName := "memberdb_" + currentUsername.(string)
// 	currentUserCollection := database.MongoClient.Database(currentDbName).Collection("Details")
// 	memberCollection := database.MongoClient.Database("general_memberdb").Collection("Details")

// 	tenantID := c.GetHeader("tenant_id")

// 	var user models.User
// 	if err := c.ShouldBindJSON(&user); err != nil {
// 		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
// 		return
// 	}

// 	// if user.Password != "" {
// 	// 	hashedPassword, err := HashPassword(user.Password)
// 	// 	if err != nil {
// 	// 		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to hash password"})
// 	// 		return
// 	// 	}
// 	// 	user.Password = hashedPassword
// 	// }

// 	update := bson.M{
// 		"$set": bson.M{
// 			"username":        user.Username,
// 			"firstname":       user.Firstname,
// 			"lastname":        user.Lastname,
// 			"password":        user.Password,
// 			"cellNumber":      user.CellPhoneNumber,
// 			"homeNumber":      user.HomePhoneNumber,
// 			"address":         user.Address,
// 			"city":            user.City,
// 			"province":        user.Province,
// 			"postalCode":      user.PostalCode,
// 			"role":            user.Role,
// 		},
// 	}

// 	// Log the update operation for debugging
// 	log.Printf("Updating user with tenant_id %s in database %s", tenantID, currentDbName)

// 	result, err := currentUserCollection.UpdateOne(context.TODO(), bson.M{"tenant_id": tenantID}, update)
// 	if err != nil {
// 		log.Printf("Failed to update user in current database: %v", err)
// 		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to update user"})
// 		return
// 	}

// 	if result.MatchedCount == 0 {
// 		log.Printf("User not found in current database with tenant_id %s", tenantID)
// 		c.JSON(http.StatusNotFound, gin.H{"message": "User not found"})
// 		return
// 	}

// 	log.Printf("User updated in current database with tenant_id %s", tenantID)

// 	// Update in the general member database
// 	_, err = memberCollection.UpdateOne(context.TODO(), bson.M{"tenant_id": tenantID}, update)
// 	if err != nil {
// 		log.Printf("Failed to update user in general member database: %v", err)
// 		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to update user in general member database"})
// 		return
// 	}

// 	log.Printf("User updated in general member database with tenant_id %s", tenantID)

// 	// Handle database name update if username is changed
// 	if currentUsername != user.Username {
// 		newDbName := "memberdb_" + user.Username

// 		err := copyDatabase(database.MongoClient, currentDbName, newDbName)
// 		if err != nil {
// 			log.Printf("Failed to copy database: %v", err)
// 			c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to copy database"})
// 			return
// 		}

// 		// Drop old database
// 		err = database.MongoClient.Database(currentDbName).Drop(context.TODO())
// 		if err != nil {
// 			log.Printf("Failed to drop old database: %v", err)
// 			c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to drop old database"})
// 			return
// 		}

// 		log.Printf("Database %s dropped successfully", currentDbName)
// 	}

// 	c.JSON(http.StatusOK, gin.H{"message": "User updated successfully"})
// }

// func copyDatabase(client *mongo.Client, currentDbName, newDbName string) error {
// 	collections, err := client.Database(currentDbName).ListCollectionNames(context.TODO(), bson.M{})
// 	if err != nil {
// 		return err
// 	}

// 	for _, collectionName := range collections {
// 		currentCollection := client.Database(currentDbName).Collection(collectionName)
// 		newCollection := client.Database(newDbName).Collection(collectionName)

// 		cursor, err := currentCollection.Find(context.TODO(), bson.M{})
// 		if err != nil {
// 			return err
// 		}

// 		var documents []interface{}
// 		if err = cursor.All(context.TODO(), &documents); err != nil {
// 			return err
// 		}

// 		if len(documents) > 0 {
// 			_, err = newCollection.InsertMany(context.TODO(), documents)
// 			if err != nil {
// 				return err
// 			}
// 		}
// 	}

// 	return nil
// }


func UpdateUser(c *gin.Context) {
    // Authorization check
    token := c.GetHeader("Authorization")
    if token == "" {
        c.JSON(http.StatusUnauthorized, gin.H{"message": "Authorization token is required"})
        return
    }

    // Extract current username from context
    currentUsername, exists := c.Get("username")
    if !exists {
        c.JSON(http.StatusUnauthorized, gin.H{"message": "Unauthorized"})
        return
    }

    // Construct current database name
    currentDbName := "memberdb_" + currentUsername.(string)
    currentUserCollection := database.MongoClient.Database(currentDbName).Collection("Details")

    // General member database collection
    generalMemberCollection := database.MongoClient.Database("general_memberdb").Collection("Details")

    // Get tenantID from header
    tenantID := c.GetHeader("tenant_id")
    if tenantID == "" {
        c.JSON(http.StatusBadRequest, gin.H{"message": "Tenant-ID header is missing"})
        return
    }

    // Bind JSON data to user model
    var user models.User
    if err := c.ShouldBindJSON(&user); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
        return
    }

    // Define update operation
    update := bson.M{
        "$set": bson.M{},
    }

    if user.Username != "" {
        update["$set"].(bson.M)["username"] = user.Username
    }
    if user.Firstname != "" {
        update["$set"].(bson.M)["firstname"] = user.Firstname
    }
    if user.Lastname != "" {
        update["$set"].(bson.M)["lastname"] = user.Lastname
    }
    if user.Password != "" {
        // Example: Update password if provided
        update["$set"].(bson.M)["password"] = user.Password
    }
    if user.CellPhoneNumber != "" {
        update["$set"].(bson.M)["cellNumber"] = user.CellPhoneNumber
    }
    if user.HomePhoneNumber != "" {
        update["$set"].(bson.M)["homeNumber"] = user.HomePhoneNumber
    }
    if user.Address != "" {
        update["$set"].(bson.M)["address"] = user.Address
    }
    if user.City != "" {
        update["$set"].(bson.M)["city"] = user.City
    }
    if user.Province != "" {
        update["$set"].(bson.M)["province"] = user.Province
    }
    if user.PostalCode != "" {
        update["$set"].(bson.M)["postalCode"] = user.PostalCode
    }
    if user.Role != "" {
        update["$set"].(bson.M)["role"] = user.Role
    }

    // Log the update operation for debugging
    log.Printf("Updating user with tenant_id %s in database %s", tenantID, currentDbName)

    // Perform update in current user database
    result, err := currentUserCollection.UpdateOne(context.TODO(), bson.M{"tenant_id": tenantID}, update)
    if err != nil {
        log.Printf("Failed to update user in current database: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to update user"})
        return
    }

    if result.MatchedCount == 0 {
        log.Printf("User not found in current database with tenant_id %s", tenantID)
        c.JSON(http.StatusNotFound, gin.H{"message": "User not found"})
        return
    }

    log.Printf("User updated in current database with tenant_id %s", tenantID)

    // Perform update in general member database
    _, err = generalMemberCollection.UpdateOne(context.TODO(), bson.M{"tenant_id": tenantID}, update)
    if err != nil {
        log.Printf("Failed to update user in general member database: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to update user in general member database"})
        return
    }

    log.Printf("User updated in general member database with tenant_id %s", tenantID)

    // Handle database name update if username is changed
    if currentUsername != user.Username {
        newDbName := "memberdb_" + user.Username

        err := copyDatabase(database.MongoClient, currentDbName, newDbName)
        if err != nil {
            log.Printf("Failed to copy database: %v", err)
            c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to copy database"})
            return
        }

        // Drop old database after copying
        err = database.MongoClient.Database(currentDbName).Drop(context.TODO())
        if err != nil {
            log.Printf("Failed to drop old database: %v", err)
            c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to drop old database"})
            return
        }

        log.Printf("Database %s dropped successfully", currentDbName)
    }

    c.JSON(http.StatusOK, gin.H{"message": "User updated successfully"})
}

// Function to copy the database
func copyDatabase(client *mongo.Client, currentDbName, newDbName string) error {
    collections, err := client.Database(currentDbName).ListCollectionNames(context.TODO(), bson.M{})
    if err != nil {
        return err
    }

    for _, collectionName := range collections {
        currentCollection := client.Database(currentDbName).Collection(collectionName)
        newCollection := client.Database(newDbName).Collection(collectionName)

        cursor, err := currentCollection.Find(context.TODO(), bson.M{})
        if err != nil {
            return err
        }

        var documents []interface{}
        if err = cursor.All(context.TODO(), &documents); err != nil {
            return err
        }

        if len(documents) > 0 {
            _, err = newCollection.InsertMany(context.TODO(), documents)
            if err != nil {
                return err
            }
        }
    }

    return nil
}

// func UpdateUser(c *gin.Context) {
// 	// Authorization check
// 	token := c.GetHeader("Authorization")
// 	if token == "" {
// 		c.JSON(http.StatusUnauthorized, gin.H{"message": "Authorization token is required"})
// 		return
// 	}

// 	// Extract current username from context
// 	currentUsername, exists := c.Get("username")
// 	if !exists {
// 		c.JSON(http.StatusUnauthorized, gin.H{"message": "Unauthorized"})
// 		return
// 	}

// 	// Construct current database name
// 	currentDbName := "memberdb_" + currentUsername.(string)
// 	currentUserCollection := database.MongoClient.Database(currentDbName).Collection("Details")
// 	memberCollection := database.MongoClient.Database("general_memberdb").Collection("Details")

// 	// Get tenantID from header
// 	tenantID := c.GetHeader("tenant_id")
// 	if tenantID == "" {
// 		c.JSON(http.StatusBadRequest, gin.H{"message": "Tenant-ID header is missing"})
// 		return
// 	}

// 	// Bind JSON data to user model
// 	var user models.User
// 	if err := c.ShouldBindJSON(&user); err != nil {
// 		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
// 		return
// 	}

// 	// Define update operation
// 	update := bson.M{
// 		"$set": bson.M{},
// 	}

// 	if user.Username != "" {
// 		update["$set"].(bson.M)["username"] = user.Username
// 	}
// 	if user.Firstname != "" {
// 		update["$set"].(bson.M)["firstname"] = user.Firstname
// 	}
// 	if user.Lastname != "" {
// 		update["$set"].(bson.M)["lastname"] = user.Lastname
// 	}
// 	if user.Password != "" {
// 		// Example: Update password if provided
// 		update["$set"].(bson.M)["password"] = user.Password
// 	}
// 	if user.CellPhoneNumber != "" {
// 		update["$set"].(bson.M)["cellNumber"] = user.CellPhoneNumber
// 	}
// 	if user.HomePhoneNumber != "" {
// 		update["$set"].(bson.M)["homeNumber"] = user.HomePhoneNumber
// 	}
// 	if user.Address != "" {
// 		update["$set"].(bson.M)["address"] = user.Address
// 	}
// 	if user.City != "" {
// 		update["$set"].(bson.M)["city"] = user.City
// 	}
// 	if user.Province != "" {
// 		update["$set"].(bson.M)["province"] = user.Province
// 	}
// 	if user.PostalCode != "" {
// 		update["$set"].(bson.M)["postalCode"] = user.PostalCode
// 	}
// 	if user.Role != "" {
// 		update["$set"].(bson.M)["role"] = user.Role
// 	}

// 	// Log the update operation for debugging
// 	log.Printf("Updating user with tenant_id %s in database %s", tenantID, currentDbName)

// 	// Perform update in current user database
// 	result, err := currentUserCollection.UpdateOne(context.TODO(), bson.M{"tenant_id": tenantID}, update)
// 	if err != nil {
// 		log.Printf("Failed to update user in current database: %v", err)
// 		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to update user"})
// 		return
// 	}

// 	if result.MatchedCount == 0 {
// 		log.Printf("User not found in current database with tenant_id %s", tenantID)
// 		c.JSON(http.StatusNotFound, gin.H{"message": "User not found"})
// 		return
// 	}

// 	log.Printf("User updated in current database with tenant_id %s", tenantID)

// 	// Perform update in general member database
// 	_, err = memberCollection.UpdateOne(context.TODO(), bson.M{"tenant_id": tenantID}, update)
// 	if err != nil {
// 		log.Printf("Failed to update user in general member database: %v", err)
// 		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to update user in general member database"})
// 		return
// 	}

// 	log.Printf("User updated in general member database with tenant_id %s", tenantID)

// 	// Handle database name update if username is changed
// 	if currentUsername != user.Username {
// 		newDbName := "memberdb_" + user.Username

// 		err := copyDatabase(database.MongoClient, currentDbName, newDbName)
// 		if err != nil {
// 			log.Printf("Failed to copy database: %v", err)
// 			c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to copy database"})
// 			return
// 		}

// 		// Drop old database after copying
// 		err = database.MongoClient.Database(currentDbName).Drop(context.TODO())
// 		if err != nil {
// 			log.Printf("Failed to drop old database: %v", err)
// 			c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to drop old database"})
// 			return
// 		}

// 		log.Printf("Database %s dropped successfully", currentDbName)
// 	}

// 	c.JSON(http.StatusOK, gin.H{"message": "User updated successfully"})
// }

// // Function to copy the database
// func copyDatabase(client *mongo.Client, currentDbName, newDbName string) error {
// 	collections, err := client.Database(currentDbName).ListCollectionNames(context.TODO(), bson.M{})
// 	if err != nil {
// 		return err
// 	}

// 	for _, collectionName := range collections {
// 		currentCollection := client.Database(currentDbName).Collection(collectionName)
// 		newCollection := client.Database(newDbName).Collection(collectionName)

// 		cursor, err := currentCollection.Find(context.TODO(), bson.M{})
// 		if err != nil {
// 			return err
// 		}

// 		var documents []interface{}
// 		if err = cursor.All(context.TODO(), &documents); err != nil {
// 			return err
// 		}

// 		if len(documents) > 0 {
// 			_, err = newCollection.InsertMany(context.TODO(), documents)
// 			if err != nil {
// 				return err
// 			}
// 		}
// 	}

// 	return nil
// }



func DeleteUser(c *gin.Context) {
	username, exists := c.Get("username")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Unauthorized"})
		return
	}

	tenantID := c.Param("tenant_id")
	dbName := "memberdb_" + username.(string)
	userCollection := database.MongoClient.Database(dbName).Collection("Details")
	memberCollection := database.MongoClient.Database("general_memberdb").Collection("Details")

	_, err := userCollection.DeleteOne(context.TODO(), bson.M{"tenant_id": tenantID})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to delete user"})
		return
	}

	_, err = memberCollection.DeleteOne(context.TODO(), bson.M{"tenant_id": tenantID})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to delete user from general member database"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User deleted successfully"})
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func VerifyPassword(hashedPassword, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}

func GetAllUsers(c *gin.Context) {
	

	dbName:="general_memberdb"
	userCollection := database.MongoClient.Database(dbName).Collection("Details")

	cursor, err := userCollection.Find(context.TODO(), bson.M{})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to retrieve users"})
		return
	}
	defer cursor.Close(context.TODO())

	var users []models.User
	for cursor.Next(context.TODO()) {
		var user models.User
		if err = cursor.Decode(&user); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to decode user"})
			return
		}
		users = append(users, user)
	}

	if err := cursor.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Cursor error"})
		return
	}

	c.JSON(http.StatusOK, users)
}
func Login(c *gin.Context) {
	var creds models.User
	if err := c.ShouldBindJSON(&creds); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}

	var user models.User
	userCollection := database.MongoClient.Database("general_memberdb").Collection("Details")

	err := userCollection.FindOne(context.TODO(), bson.M{"username": creds.Username}).Decode(&user)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid username or password"})
		return
	}

	err = VerifyPassword(user.Password, creds.Password)
	if err != nil {
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
