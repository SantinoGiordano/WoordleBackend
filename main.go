package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/gofiber/fiber/v2"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

type Word struct {
	ID   primitive.ObjectID `json:"_id,omitempty" bson:"_id,omitempty"`
	Name string             `json:"name" bson:"name"`
	Hint string             `json:"hint" bson:"hint"`
}

type Users struct {
	ID       primitive.ObjectID `json:"_id,omitempty" bson:"_id,omitempty"`
	Username string             `json:"username" bson:"username"`
	Password string             `json:"password" bson:"password"`
	Score    int64              `json:"score" bson:"score"`
}

var usersCollection *mongo.Collection
var collection *mongo.Collection

func CORSMiddleware(c *fiber.Ctx) error {
	c.Set("Access-Control-Allow-Origin", "*")
	c.Set("Access-Control-Allow-Credentials", "true")
	c.Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
	c.Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")

	if c.Method() == "OPTIONS" {
		return c.SendStatus(fiber.StatusNoContent)
	}
	return c.Next()
}

func main() {
	fmt.Println("hello world")

	if err := godotenv.Load(".env"); err != nil {
		log.Println("No .env file found — using system environment variables")
	}

	MONGO_URI := os.Getenv("MONGO_URI")
	if MONGO_URI == "" {
		log.Fatal("MONGO_URI not set in environment")
	}

	clientOptions := options.Client().ApplyURI(MONGO_URI)
	client, err := mongo.Connect(context.Background(), clientOptions)
	if err != nil {
		log.Fatal(err)
	}

	if err := client.Ping(context.Background(), nil); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Connected to Mongo")

	usersCollection = client.Database("woordleData").Collection("users")
	collection = client.Database("woordleData").Collection("words")

	app := fiber.New()
	app.Use(CORSMiddleware)

	app.Get("/api/users", func(c *fiber.Ctx) error {
		var users []Users
		cursor, err := usersCollection.Find(context.Background(), bson.M{})
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": err.Error()})
		}
		if err := cursor.All(context.Background(), &users); err != nil {
			return c.Status(500).JSON(fiber.Map{"error": err.Error()})
		}
		return c.JSON(users)
	})

	app.Get("/api/words", func(c *fiber.Ctx) error {
		var words []Word
		cursor, err := collection.Find(context.Background(), bson.M{})
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": err.Error()})
		}
		if err := cursor.All(context.Background(), &words); err != nil {
			return c.Status(500).JSON(fiber.Map{"error": err.Error()})
		}
		return c.JSON(words)
	})

	app.Post("/api/login", func(c *fiber.Ctx) error {
		var credentials struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}

		if err := c.BodyParser(&credentials); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
		}

		var user Users
		err := usersCollection.FindOne(context.Background(), bson.M{"username": credentials.Username}).Decode(&user)
		if err == mongo.ErrNoDocuments {
			return c.Status(404).JSON(fiber.Map{"error": "Account not found"})
		} else if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "Database error"})
		}

		// Check password
		if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(credentials.Password)); err != nil {
			return c.Status(401).JSON(fiber.Map{"error": "Invalid password"})
		}

		return c.JSON(fiber.Map{
			"message":  "Login successful",
			"username": user.Username,
			"userId":   user.ID.Hex(),
		})

	})

	app.Post("/api/register", func(c *fiber.Ctx) error {
		var user Users
		if err := c.BodyParser(&user); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
		}

		count, err := usersCollection.CountDocuments(context.Background(), bson.M{"username": user.Username})
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": err.Error()})
		}
		if count > 0 {
			return c.Status(400).JSON(fiber.Map{"error": "Username already exists"})
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), 14)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "Error hashing password"})
		}
		user.Password = string(hashedPassword)
		user.Score = 0
		user.ID = primitive.NewObjectID()

		_, err = usersCollection.InsertOne(context.Background(), user)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": err.Error()})
		}

		return c.JSON(fiber.Map{"message": "User registered successfully"})
	})

	app.Post("/api/score", func(c *fiber.Ctx) error {
		var body struct {
			UserID string `json:"userId"`
			Score  int64  `json:"score"`
		}
		if err := c.BodyParser(&body); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
		}

		if body.UserID == "" || body.UserID == "undefined" || body.UserID == "null" {
			return c.Status(400).JSON(fiber.Map{"error": "Invalid user ID"})
		}

		objID, err := primitive.ObjectIDFromHex(body.UserID)
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Invalid user ID format"})
		}

		filter := bson.M{"_id": objID}
		update := bson.M{"$inc": bson.M{"score": body.Score}}

		result := usersCollection.FindOneAndUpdate(
			context.Background(),
			filter,
			update,
			options.FindOneAndUpdate().SetReturnDocument(options.After),
		)

		var updatedUser Users
		if err := result.Decode(&updatedUser); err != nil {
			return c.Status(500).JSON(fiber.Map{"error": err.Error()})
		}

		fmt.Println("Updated user:", body.UserID, "New score:", updatedUser.Score)

		return c.JSON(fiber.Map{
			"success":  true,
			"newScore": updatedUser.Score,
		})
	})

	log.Fatal(app.Listen(":8080"))
}
