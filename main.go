package main

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
)

func main() {
	app := fiber.New()

	// Apply CORS middleware
	app.Use(cors.New(cors.Config{
		AllowOrigins: "*", // Adjust this to be more restrictive if needed
		AllowMethods: "GET,POST,HEAD,PUT,DELETE,PATCH",
		AllowHeaders: "Origin, Content-Type, Accept",
	}))

	// Setup routes
	app.Get("/book", getBooks)
	app.Get("/book/:id", getBook)
	app.Post("/book", createBook)
	app.Put("/book/:id", updateBook)
	app.Delete("/book/:id", deleteBook)

	app.Listen(":8080")
}
