package main


import (

	"main/database"
	"main/routes"
	"os"

	"github.com/gin-gonic/gin"
)

func init() {
    dbUrl := os.Getenv("DBURL")
    if dbUrl == "" {
        dbUrl = "mongodb://localhost:27017"
    }
    database.MongoDBInit(dbUrl)
}

func main() {
    r := gin.Default()
    routes.UserRouter(r)

    port := os.Getenv("PORT")
    if port == "" {
        port = "8080"
    }
    r.Run(":" + port)

}

