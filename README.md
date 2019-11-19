# go-ciba

OpenID Connect CIBA flow client for golang.

## Usage

```go
package main

import (
	"context"
	"fmt"
	"github.com/okzk/go-ciba"
)

func main() {
	client := ciba.NewClient(
		"https://example.com",          // issuer
		"https://example.com/bc-authn", // backchannel_authentication_endpoint
		"https://example.com/token",    // token_endpoint
		"openid",                       // scope
		"sample_client",                // client_id
		"xxxxxxxxxxxxxxxxxxxxx",        // client_secret
	)

	ctx := context.Background()
	token, err := client.Authenticate(ctx, ciba.LoginHint("alice"))
	if err != nil {
		panic(err)
	}
	claims, err := client.ParseIDToken(token.IDToken)
	if err != nil {
		panic(err)
	}

	fmt.Println(claims["sub"])
}
```


## Limitations

- Support poll mode only.
- Support `client_secret_basic` only.


## License
MIT
