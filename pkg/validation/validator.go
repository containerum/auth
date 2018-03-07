package validation

import (
	enLocale "github.com/go-playground/locales/en"
	"github.com/go-playground/universal-translator"
	"gopkg.in/go-playground/validator.v9"
	enTranslations "gopkg.in/go-playground/validator.v9/translations/en"
)

// StandardAuthValidator sets up validator to Validate requests
func StandardAuthValidator(uni *ut.UniversalTranslator) (ret *validator.Validate) {
	ret = validator.New()
	ret.SetTagName("binding")

	enTranslator, _ := uni.GetTranslator(enLocale.New().Locale())
	enTranslations.RegisterDefaultTranslations(ret, enTranslator)

	return
}
