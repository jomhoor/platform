package jwt

import (
	"fmt"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"
)

const (
	AuthorizationHeaderName = "Authorization"
	BearerTokenPrefix       = "Bearer "

	AccessTokenType  = "access"
	RefreshTokenType = "refresh"

	claimType       = "token_type"
	claimSub        = "sub"
	claimClientID   = "client_id"
	claimZKVerified = "zk_verified"
)

type AuthClaim struct {
	// Subject is the pairwise subject for the relying party (never walletAddress).
	Subject  string
	ClientID string
	Type     string
	// ZKVerified is informational in Phase 1; expected false for most users.
	ZKVerified bool
}

type JWTIssuer struct {
	prv               []byte
	accessExpiration  time.Duration
	refreshExpiration time.Duration
}

func (i *JWTIssuer) IssueJWT(claim *AuthClaim) (token string, exp time.Time, err error) {
	exp = time.Now().UTC()

	claims := jwtlib.MapClaims{
		claimSub:        claim.Subject,
		claimClientID:   claim.ClientID,
		claimType:       claim.Type,
		claimZKVerified: claim.ZKVerified,
	}

	switch claim.Type {
	case AccessTokenType:
		exp = exp.Add(i.accessExpiration)
	case RefreshTokenType:
		exp = exp.Add(i.refreshExpiration)
	default:
		err = fmt.Errorf("unknown token type: %s", claim.Type)
		return
	}

	claims["exp"] = exp.Unix()
	claims["iat"] = time.Now().UTC().Unix()

	token, err = jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, claims).SignedString(i.prv)
	return
}

func (i *JWTIssuer) ValidateJWT(str string) (*AuthClaim, error) {
	token, err := jwtlib.Parse(str, func(t *jwtlib.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwtlib.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return i.prv, nil
	}, jwtlib.WithExpirationRequired())
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwtlib.MapClaims)
	if !ok {
		return nil, fmt.Errorf("failed to unwrap claims")
	}

	sub, _ := claims[claimSub].(string)
	cid, _ := claims[claimClientID].(string)
	typ, _ := claims[claimType].(string)
	zkv, _ := claims[claimZKVerified].(bool)

	if sub == "" || typ == "" {
		return nil, fmt.Errorf("malformed token: missing required claims")
	}

	return &AuthClaim{
		Subject:    sub,
		ClientID:   cid,
		Type:       typ,
		ZKVerified: zkv,
	}, nil
}
