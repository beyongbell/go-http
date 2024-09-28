package main

import (
	"fmt"
	"log"
	"os"
	"time"

	_ "github.com/beyongbell/go-http/docs" // Generated docs will be imported here

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	jwtware "github.com/gofiber/jwt/v2"
	"github.com/golang-jwt/jwt/v4"
	"github.com/joho/godotenv"
	fiberSwagger "github.com/swaggo/fiber-swagger"
)

var jwtKey = []byte(os.Getenv("JWT_SECRET"))

// Struct for storing user credentials
type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Struct for JWT claims
type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// // Dummy user credentials (in-memory)
// var users = map[string]string{
// 	"user1": "password123",
// }

func checkMiddleware(c *fiber.Ctx) error {
	start := time.Now()

	fmt.Printf("URL = %s, Method = %s, Time = %s \n", c.OriginalURL(), c.Method(), start)

	return c.Next()
}

type User struct {
	Email    string
	Password string
}

// // Login function to issue a JWT token
// func login(c *fiber.Ctx) error {
// 	var creds Credentials

// 	// Parse request body into the Credentials struct
// 	if err := c.BodyParser(&creds); err != nil {
// 		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request"})
// 	}

// 	// Validate credentials
// 	expectedPassword, ok := users[creds.Username]
// 	if !ok || expectedPassword != creds.Password {
// 		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid credentials"})
// 	}

// 	// Set token expiration time
// 	expirationTime := time.Now().Add(5 * time.Minute)

// 	// Create JWT claims with the username
// 	claims := &Claims{
// 		Username: creds.Username,
// 		RegisteredClaims: jwt.RegisteredClaims{
// 			ExpiresAt: jwt.NewNumericDate(expirationTime),
// 		},
// 	}

// 	// Create the token
// 	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
// 	tokenString, err := token.SignedString(jwtKey)
// 	fmt.Println(tokenString)
// 	if err != nil {
// 		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "could not create token"})
// 	}

// 	// Return JWT token in the response
// 	return c.JSON(fiber.Map{"token": tokenString})
// }

// // JWT Middleware function
// func jwtMiddleware() fiber.Handler {
// 	return func(c *fiber.Ctx) error {
// 		// Get token from Authorization header
// 		authHeader := c.Get("Authorization")

// 		// Check if the Authorization header is present and starts with 'Bearer '
// 		if authHeader == "" || len(authHeader) < 7 || authHeader[:7] != "Bearer " {
// 			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "missing or malformed token"})
// 		}

// 		// Remove 'Bearer ' from the token string to get the actual token
// 		tokenString := authHeader[7:]

// 		// Parse the token
// 		claims := &Claims{}
// 		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
// 			return jwtKey, nil
// 		})

// 		if err != nil {
// 			if err == jwt.ErrSignatureInvalid {
// 				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid token signature"})
// 			}
// 			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "could not parse token"})
// 		}

// 		if !token.Valid {
// 			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid token"})
// 		}

// 		// Store the username in the context
// 		c.Locals("user", claims.Username)

// 		// Call the next handler
// 		return c.Next()
// 	}
// }

// // Protected endpoint
// func protectedEndpoint(c *fiber.Ctx) error {
// 	// Retrieve the username from context
// 	username := c.Locals("user").(string)
// 	return c.JSON(fiber.Map{"message": fmt.Sprintf("Welcome, %s! This is a protected route.", username)})
// }

func login(c *fiber.Ctx) error {
	username := c.FormValue("username")
	password := c.FormValue("password")

	// Throws Unauthorized error
	if username != "user1" || password != "password123" {
		return c.SendStatus(fiber.StatusUnauthorized)
	}

	// Create token
	token := jwt.New(jwt.SigningMethodHS256)

	// Set claims
	claims := token.Claims.(jwt.MapClaims)
	claims["name"] = "Thinnakorn BelL"
	claims["admin"] = true
	claims["exp"] = time.Now().Add(time.Hour * 72).Unix()

	// Generate encoded token and send it as response.
	t, err := token.SignedString(jwtKey)
	if err != nil {
		return c.SendStatus(fiber.StatusInternalServerError)
	}

	return c.JSON(fiber.Map{"token": t})
}

func accessible(c *fiber.Ctx) error {
	return c.SendString("Accessible")
}

func restricted(c *fiber.Ctx) error {
	user := c.Locals("user").(*jwt.Token)
	claims := user.Claims.(jwt.MapClaims)
	name := claims["name"].(string)
	return c.SendString("Welcome " + name)
}

// @title Fiber Swagger Example API
// @version 1.0
// @description This is a simple API example with Fiber and Swagger.
// @termsOfService http://swagger.io/terms/
// @contact.name API Support
// @contact.url http://www.swagger.io/support
// @contact.email support@swagger.io
// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html
// @host localhost:3000
// @BasePath /

// @Summary Ping the server
// @Description Responds with "pong" message
// @Tags ping
// @Produce json
// @Success 200 {object} map[string]string
// @Router /ping [get]
func ping(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{"message": "pong"})
}

func main() {
	// Load environment variables from .env file
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	app := fiber.New()

	// Apply CORS middleware
	app.Use(cors.New(cors.Config{
		AllowOrigins: "*", // Adjust this to be more restrictive if needed
		AllowMethods: "GET,POST,HEAD,PUT,DELETE,PATCH",
		AllowHeaders: "Origin, Content-Type, Accept",
	}))

	// Route for Swagger documentation
	app.Get("/swagger/*", fiberSwagger.WrapHandler)

	// API endpoint
	app.Get("/ping", ping)

	// Login route
	app.Post("/login", login)

	// Unauthenticated route
	app.Get("/", accessible)

	// JWT Middleware
	app.Use(jwtware.New(jwtware.Config{
		SigningKey: jwtKey,
	}))

	// Restricted Routes
	app.Get("/restricted", restricted)

	// // Protected route using JWT middleware
	// app.Use("/protected", jwtMiddleware())

	// // Protected endpoint
	// app.Get("/protected", protectedEndpoint)

	app.Use(checkMiddleware)
	// Setup routes
	app.Get("/book", getBooks)
	app.Get("/book/:id", getBook)
	app.Post("/book", createBook)
	app.Put("/book/:id", updateBook)
	app.Delete("/book/:id", deleteBook)

	// Setup routes
	app.Get("/api/config", getConfig)

	// Use the environment variable for the port
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080" // Default port if not specified
	}

	app.Listen(":" + port)
}

func getConfig(c *fiber.Ctx) error {
	// Example: Return a configuration value from environment variable
	secretKey := os.Getenv("SECRET_KEY")
	if secretKey == "" {
		secretKey = "defaultSecret" // Default value if not specified
	}

	return c.JSON(fiber.Map{
		"secret_key": secretKey,
	})
}
