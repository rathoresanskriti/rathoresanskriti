// // package database

// // import (
// // 	"context"
	
// // 	"log"

// // 	"go.mongodb.org/mongo-driver/mongo"
// // 	"go.mongodb.org/mongo-driver/mongo/options"
// // )





// // var MongoCollection *mongo.Collection

// // // Init Mongo
// // func MongoDBInit(dbUrl string) {
// // 	clientOptions := options.Client().ApplyURI(dbUrl)
// // 	client, err := mongo.Connect(context.TODO(), clientOptions)
// // 	if err != nil {
// // 		log.Fatal(err)
// // 	}
// // 	err = client.Ping(context.TODO(), nil)
// // 	if err != nil {
// // 		log.Fatal(err)
// // 		return
// // 	}

// // 	MongoCollection = client.Database("go-api").Collection("members")
// // }


// package database

// import (
// 	"context"
// 	"log"

// 	"go.mongodb.org/mongo-driver/mongo"
// 	"go.mongodb.org/mongo-driver/mongo/options"
// )

// var MongoClient *mongo.Client

// // Init Mongo
// func MongoDBInit(dbUrl string) {
// 	clientOptions := options.Client().ApplyURI(dbUrl)
// 	client, err := mongo.Connect(context.TODO(), clientOptions)
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	err = client.Ping(context.TODO(), nil)
// 	if err != nil {
// 		log.Fatal(err)
// 		return
// 	}

// 	MongoClient = client
// }


package database

import (
	"context"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var MongoClient *mongo.Client

func ConnectMongoDB(uri string) {
	clientOptions := options.Client().ApplyURI(uri)
	client, err := mongo.NewClient(clientOptions)
	if err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = client.Connect(ctx)
	if err != nil {
		log.Fatal(err)
	}

	MongoClient = client
	log.Println("Connected to MongoDB!")
}
