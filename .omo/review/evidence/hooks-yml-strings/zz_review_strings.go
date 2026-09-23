package testapp

import "strings"

type reviewNamedString string

func ReviewNamedTrim(value string) string {
	named := reviewNamedString(value)
	return strings.TrimSpace(string(named))
}

func reviewGenericTrim[T ~string](value T) string {
	return strings.TrimSpace(string(value))
}

func ReviewGenericTrim(value string) string {
	return reviewGenericTrim(reviewNamedString(value))
}

func reviewGenericCut[T ~string](value T) (string, string, bool) {
	return strings.Cut(string(value), ",")
}

func ReviewGenericCut(value string) (string, string, bool) {
	return reviewGenericCut(reviewNamedString(value))
}

func ReviewReplacerEvaluation(value string) (result string, receivers, arguments int) {
	replace := func() *strings.Replacer {
		receivers++
		return strings.NewReplacer(",", ";")
	}
	arg := func() string {
		arguments++
		return value
	}
	result = replace().Replace(arg())
	return
}

func ReviewReplacerMethodExpression(value string) string {
	return (*strings.Replacer).Replace(strings.NewReplacer(",", ";"), value)
}

func ReviewBuilderMethodExpression(value string) string {
	var builder strings.Builder
	_, _ = (*strings.Builder).WriteString(&builder, value)
	return builder.String()
}
