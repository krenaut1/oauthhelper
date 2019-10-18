package oauthhelper_test

import (
	"fmt"
	"testing"

	"github.com/krenaut1/oauthhelper"
)

func TestOauthHelper(t *testing.T) {

	oauth := &oauthhelper.Oauthhelper{
		MyClientID:         "ebf3ba22-f0ba-4012-ae6b-468ed1a123c6",                             // client id
		MyClientSecret:     "1U7WZoPd70q1Ru1wvdL01xAdWEJbrMtX3ZOXEUAnvat8QBsb4suQ4MnHL4wqDSIj", // client secret
		MyTokenEndPoint:    "https://login-dev.windstream.com/as/token.oauth2",                 // token end point
		MyCertEndPoint:     "https://login-dev.windstream.com/ext/oauth/x509/kid",              // cert end point
		MyUserInfoEndPoint: "https://login-dev.windstream.com/idp/userinfo.openid",             // user info end point
		MyAccessToken:      "",                                                                 // this must be an empty string
		MyAccessTokenExp:   0,                                                                  // this must be zero
		MyCerts:            make(map[string]oauthhelper.Certs),                                 // this must be make(map[string]oauthhelper.Certs)
		MyUsers:            make(map[string]oauthhelper.Users),                                 // this must be make(map[string]oauthhelper.Users)
	}

	fmt.Printf("ClientID: %v\n", oauth.MyClientID)
	fmt.Printf("ClientSecret: %v\n", oauth.MyClientSecret)
	fmt.Printf("TokenEndPoint: %v\n", oauth.MyTokenEndPoint)
	fmt.Printf("CertEndPoint: %v\n", oauth.MyCertEndPoint)
	fmt.Printf("UserInfoEndPoint: %v\n", oauth.MyUserInfoEndPoint)
	accesstoken, err := oauth.GetMyAccessToken()
	if err != nil {
		fmt.Println("error getting access token")
	} else {
		fmt.Printf("AccessToken: %v\n", accesstoken)
	}
	ok := oauth.IsValid("Bearer " + accesstoken)
	fmt.Println(ok)
	myClaims, ok := oauth.GetMyAccessTokenClaims("Bearer " + accesstoken)
	fmt.Println(myClaims.ClientID)
	accesstoken, err = oauth.GetMyAccessToken()
	if err != nil {
		fmt.Println("error getting access token")
	} else {
		fmt.Printf("AccessToken: %v\n", accesstoken)
	}
	ok = oauth.IsValid("Bearer " + accesstoken)
	fmt.Println(ok)
	myClaims, ok = oauth.GetMyAccessTokenClaims("Bearer " + accesstoken)
	fmt.Println(myClaims.Expiry.Time())
}
