package validation

import "gopkg.in/go-playground/validator.v8"

// StandardAuthValidator sets up validator to validate requests
func StandardAuthValidator() (ret *validator.Validate) {
	ret = validator.New(&validator.Config{TagName: "validate"})

	// TODO: setup per-struct validation here

	return
}
