package ciba

import (
	"net/url"
	"strconv"
)

type AuthenticationParam func(values url.Values)

func LoginHint(loginHint string) AuthenticationParam {
	return func(values url.Values) {
		values.Set("login_hint", loginHint)
	}
}

func LoginHintToken(loginHintToken string) AuthenticationParam {
	return func(values url.Values) {
		values.Set("login_hint_token", loginHintToken)
	}
}

func IDTokenHint(idTokenHint string) AuthenticationParam {
	return func(values url.Values) {
		values.Set("id_token_hint", idTokenHint)
	}
}

func BindingMessage(bindingMessage string) AuthenticationParam {
	return func(values url.Values) {
		values.Set("binding_message", bindingMessage)
	}
}

func ACRValues(acrValues string) AuthenticationParam {
	return func(values url.Values) {
		values.Set("acr_values", acrValues)
	}
}

func UserCode(userCode string) AuthenticationParam {
	return func(values url.Values) {
		values.Set("user_code", userCode)
	}
}

func RequestedExpiry(requestedExpiry int) AuthenticationParam {
	return func(values url.Values) {
		values.Set("requested_expiry", strconv.Itoa(requestedExpiry))
	}
}
