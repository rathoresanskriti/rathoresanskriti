package models

import "go.mongodb.org/mongo-driver/bson/primitive"

type User struct {
	ID              primitive.ObjectID `bson:"_id"`
	Username        string            `bson:"username" validate:"required, min=2, max=100"`
	Firstname       string            `bson:"firstname" `
	Lastname        string            `bson:"lastname" evalidate:"requird, min=2, max=100"`
	Password        string            `bson:"password" validate:"required, min=6, max=18"`
	CellPhoneNumber string            `bson:"cellNumber" validate:"required, min=6, max=18"`
	HomePhoneNumber string            `bson:"homeNumber"`
	Address         string            `bson:"address"`
	City            string            `bson:"city"`
	Province        string            `bson:"province"`
	PostalCode      string            `bson:"postalCode"`
	Role            string            `bson:"role" validate:"required"`
}
