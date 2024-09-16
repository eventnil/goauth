package pkg

import (
	"context"
	"regexp"

	"github.com/go-playground/validator/v10"
	"github.com/sirupsen/logrus"

	"github.com/c0dev0yager/goauth"
	"github.com/c0dev0yager/goauth/internal/domain"
)

var Validate *validator.Validate

func init() {
	Validate = validator.New()
	Validate.RegisterValidation("special_character_validation", validateOnlyDashAndUnderscore)
}

// Custom validation function to check for only allowed special characters
func validateOnlyDashAndUnderscore(fl validator.FieldLevel) bool {
	// Define the allowed pattern: alphanumeric characters, dashes, and underscores
	regex := `^[a-zA-Z0-9_-]*$`

	// Compile the regex
	re := regexp.MustCompile(regex)

	// Get the field value as a string
	value := fl.Field().String()

	// Return whether the value matches the regex
	return re.MatchString(value)
}

func GetFromContext(
	ctx context.Context,
) *logrus.Logger {
	logger, ok := ctx.Value(goauth.LoggerContextKey).(logrus.Logger)
	if ok {
		logger.WithField("event", "message")
		return &logger
	}

	newLogger := domain.Logger()
	newLogger.WithField("event", "message")
	return newLogger
}
