package oauthhelper

/*******************************************************************************
 *
 * @author Karl Renaut
 * @version 0.6
 *
 * This is a Windstream specific security package.  It should be used by
 * goLang micro service programmers using our consolidated micro service
 * platform in order to comply with Windstream security requirements.
 *
 * This version supports client to client authenticate via oAuth 2.0 utilizing
 * our Ping IDP
 *
 * It also supports getting userInfo (security Groups) for an OpenID Connect
 * SSO authenticated user
 *
 * TODO - add support for caching userInfo
 *
 ******************************************************************************/
import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"gopkg.in/square/go-jose.v2/jwt"
)

// WindstreamClaims defines windstream specific claims
type WindstreamClaims struct {
	*jwt.Claims
	ClientID          string `json:"client_id"`
	AddressLocality   string `json:"address.locality"`
	PreferredUsername string `json:"preferred_username"`
	GivenName         string `json:"given_name"`
	Title             string `json:"title"`
	UserID            string `json:"userId"`
	AddressPostalCode string `json:"address.postal_code"`
	AddressRegion     string `json:"address.region"`
	PhoneNumber       string `json:"phone_number"`
	Sip               string `json:"sip"`
	Department        string `json:"department"`
	FamilyName        string `json:"family_name"`
	Email             string `json:"email"`
	Username          string `json:"username"`
}

// Oauthhelper object and methods
type Oauthhelper struct {
	sync.Mutex
	MyClientID         string
	MyClientSecret     string
	MyTokenEndPoint    string
	MyCertEndPoint     string
	MyUserInfoEndPoint string
	MyAccessToken      string
	MyAccessTokenExp   int64
	MyCerts            map[string]Certs
	MyUsers            map[string]Users
}

// Certs structure that is used to cache signing certificates from ping
type Certs struct {
	cert []byte
	exp  int64
}

// Users structure that is used to cache ping userInfo for securtity groups
type Users struct {
	userInfo []byte
	accessed int64
}

var purgeRunning bool = false

// PingResponse this defines the expected response when getting an access token from Ping
type PingResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   string `json:"expires_in"`
}

// GetMyAccessToken returns myAccessToken
/*******************************************************************************
 *	oauthhelper.GetMyAccessToken() (AccessToken string)
 *
 *	The client application must call this every time they are building a request
 *	that required them to provide an authorization request header with a bearer
 *	token.  The first time the function is called, it will fetch an access token
 *	from the IDP.  This access token will then be cached until 5 minutes before
 *	it expires.  Subsequent calls to this function will return the cached access
 *	token.  If the cached token will expire within 5 minutes or if the token has
 *	already expired then a new access token will be fetched  and replace the token
 *	that previously cached.
 *
 *	@return AccessToken string
 *
 ******************************************************************************/
func (o *Oauthhelper) GetMyAccessToken() (string, error) {
	now := time.Now().Add(time.Minute * 5).Unix()

	if now > o.MyAccessTokenExp { // if token is expired get a new one
		var err error
		o.MyAccessToken, o.MyAccessTokenExp, err = getPingAccessToken(o)
		if err != nil {
			return "", err
		}
	}
	return o.MyAccessToken, nil
}

// getPingAccessToken gets a fresh access token from ping
/*******************************************************************************
 *	getPingAccessToken((o *Oauthhelper) (accessToken string, expDateTime int64))
 *
 *	@param o *Oauthhelper	This is a pointer to the oauthhelper object that
 *							the client application created via the NewOauthHelper
 *							function.
 *
 *	@return accessToken string, expDateTime int64
 *
 *****************************************************************************/
func getPingAccessToken(o *Oauthhelper) (string, int64, error) {

	// configure a network transport object with timeout options
	// for the http client that we are about to create
	var netTransport = &http.Transport{
		Dial: (&net.Dialer{
			Timeout: 5 * time.Second,
		}).Dial,
		TLSHandshakeTimeout: 5 * time.Second,
	}

	// create a http client with timeout settings and the network transport
	// settings that we just defined in netTransport
	var netClient = &http.Client{
		Timeout:   time.Second * 60,
		Transport: netTransport,
	}

	// create an https post request to obtain an access token from the IDP
	request, err := http.NewRequest(http.MethodPost, o.MyTokenEndPoint+"?grant_type=client_credentials", nil)
	if err != nil {
		log.Printf("Error while creating request to obtain access token from Ping: %v\n", err.Error())
		return "", 0, err
	}

	// format and set the request headers
	usrpwd := fmt.Sprintf("%v:%v", o.MyClientID, o.MyClientSecret)
	credentials := base64.StdEncoding.EncodeToString([]byte(usrpwd))
	request.Header.Set("Authorization", fmt.Sprintf("Basic %v", credentials))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// post the request to the IDP
	response, err := netClient.Do(request)
	if err != nil {
		log.Printf("Error while communicating with Ping: %v\n", err.Error())
		return "", 0, err
	}

	// read and parse the response and return the results to the caller
	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	Token := PingResponse{}
	err = json.Unmarshal(body, &Token)
	dur, _ := time.ParseDuration(Token.ExpiresIn + "s")
	exp := time.Now().Add(dur).Unix()
	return Token.AccessToken, exp, nil
}

// getSigningCert uses the supplied keyid to obtain signing certificate from Ping
/*******************************************************************************
 *	getSigningCert(o *Oauthhelper, keyid string) (certificate []bye, error)
 *
 *	@param o *Oauthhelper		This is a pointer to the oauthhelper object
 *	@param keyid string			This is the "kid" header claim from the access
 *								token that needs to be validated
 *
 *  @return certificate []byte, error
 *								If an error occurs the certificate will be nil
 *								and the error will be set based on the failing
 *								sub function
 ******************************************************************************/
func getSigningCert(o *Oauthhelper, keyid string) ([]byte, error) {

	// get the current time with 5 minute leeway
	now := time.Now().Add(time.Minute * 5).Unix()

	// try to get the certificate from our cache
	o.Lock()
	c, ok := o.MyCerts[keyid]
	o.Unlock()
	if ok { // is the cert cached?
		if now < c.exp { // if cert is cached return it if it is not expired
			return c.cert, nil
		}
	}

	// configure a network transport object with timeout options
	// for the http client that we are about to create
	var netTransport = &http.Transport{
		Dial: (&net.Dialer{
			Timeout: 5 * time.Second,
		}).Dial,
		TLSHandshakeTimeout: 5 * time.Second,
	}

	// create a http client with timeout settings and the network transport
	// settings that we just defined in netTransport
	var netClient = &http.Client{
		Timeout:   time.Second * 60,
		Transport: netTransport,
	}

	// create an https get request to obtain the certificate from the IDP
	request, err := http.NewRequest(http.MethodGet, o.MyCertEndPoint+"?v="+keyid, nil)
	if err != nil {
		log.Printf("error constructing Ping request: %v\n", err.Error())
		return nil, err
	}

	// try to get the certificate from Ping
	response, err := netClient.Do(request)
	if err != nil {
		log.Printf("Error communicating with Ping: %v\n", err.Error())
		return nil, err
	}

	// read the response from Png
	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Printf("Error communicating with Ping: %v\n", err.Error())
		return nil, err
	}

	// calculate when we want this certificate to expire out of the cache
	// then store it into the cache and return it to the calling application
	exp := time.Now().Add(time.Hour * 24).Unix()
	cNew := Certs{body, exp}
	o.Lock()
	o.MyCerts[keyid] = cNew
	o.Unlock()
	return body, nil
}

// IsValid returns true if the authorization header contains a valid bearer token
/*******************************************************************************
 *	returns the claims from the token body and validates the signature
 *	if the signature is valid then the boolean flag will be set to true
 ******************************************************************************/
func (o *Oauthhelper) IsValid(authHdr string) bool {
	_, ok := getAccessTokenClaims(o, authHdr)
	return ok
}

// GetMyAccessTokenClaims returns claims from an access token (this is not the same as user info)
func (o *Oauthhelper) GetMyAccessTokenClaims(authHdr string) (WindstreamClaims, bool) {
	claims, ok := getAccessTokenClaims(o, authHdr)
	return claims, ok
}

// getAccessTokennClaims returns true if the authorization header contains a valid bearer token
/*******************************************************************************
 *	returns the claims from the token body and validates the signature
 *	if the signature is valid then the boolean flag will be set to true
 ******************************************************************************/
func getAccessTokenClaims(o *Oauthhelper, authHdr string) (WindstreamClaims, bool) {
	// create an empty WinstreamClaims object to parse into
	claims := WindstreamClaims{}

	// parse the authorization header value into token type and token
	splitToken := strings.Fields(authHdr)
	tokenType := strings.ToUpper(splitToken[0])

	// if the token type is not bearer then deny access
	if tokenType != "BEARER" {
		log.Printf("Invalid token type: %v\n", tokenType)
		return claims, false
	}

	// parse the raw access token into a JWT object
	accessToken := splitToken[1]
	parsedJWT, err := jwt.ParseSigned(accessToken)

	// deny access if we can't parse the access token properly
	if err != nil {
		log.Printf("parse JWT failed %v\n", err)
		return claims, false
	}

	// get the "kid" from the token header, this identifies the certificate need to validate the token
	hdrs := parsedJWT.Headers
	kid := hdrs[0].KeyID

	// get the certificate, we are expecting a PEM certificate
	pemCert, err := getSigningCert(o, kid)

	// deny access if we cannot obtain the signing certificated required to validate the access token
	if err != nil {
		log.Printf("Error getting cert to validate sig from ping: %v\n", err.Error())
		return claims, false
	}

	// decode the PEM certificate and extract the RSA Public Key
	block, _ := pem.Decode(pemCert)
	var cert *x509.Certificate
	cert, _ = x509.ParseCertificate(block.Bytes)
	rsaPublicKey := cert.PublicKey.(*rsa.PublicKey)

	// validate the access token signature and extract all of the claims
	err = parsedJWT.Claims(rsaPublicKey, &claims)

	// deny access if the signature is not valid or if any other error occured
	if err != nil {
		log.Printf("Failed to get claims JWT:%+v\n", err.Error())
		return claims, false
	}

	// return the claims and assert that the access token was valid
	return claims, true
}

// GetUserInfo uses the supplied authHdr to obtain userInfo from Ping
/*******************************************************************************
 *	getUserInfo(o *Oauthhelper, authHdr string) (securityGroups []string, error)
 *
 *	@param o *Oauthhelper		This is a pointer to the oauthhelper object
 *	@param authHdr string		This is the authorization header from the request
 *								being processed
 *
 *  @return securityGroups []string, error
 *								If an error occurs the securityGroups array will be nil
 *								and the error will be set based on the failing
 *								sub function
 ******************************************************************************/
func (o *Oauthhelper) GetUserInfo(authHdr string) ([]string, error) {
	var body []byte
	var err error
	var u Users
	var ok bool
	var memberOf []string

	if !purgeRunning {
		purgeRunning = true
		go purgeCache(o)
	}
	o.Lock()
	u, ok = o.MyUsers[authHdr]
	if ok {
		log.Println("cache hit on Users")
		u.accessed = time.Now().Unix() // update last access time
		o.MyUsers[authHdr] = u         // update cache
		body = u.userInfo
	}
	o.Unlock()
	if !ok {
		log.Println("cache miss on Users, fetching userinfo from Ping")
		// configure a network transport object with timeout options
		// for the http client that we are about to create
		var netTransport = &http.Transport{
			Dial: (&net.Dialer{
				Timeout: 5 * time.Second,
			}).Dial,
			TLSHandshakeTimeout: 5 * time.Second,
		}

		// create a http client with timeout settings and the network transport
		// settings that we just defined in netTransport
		var netClient = &http.Client{
			Timeout:   time.Second * 60,
			Transport: netTransport,
		}

		// create an https get request to obtain the userInfo from the IDP
		request, err := http.NewRequest(http.MethodGet, o.MyUserInfoEndPoint, nil)
		if err != nil {
			log.Printf("error constructing Ping request: %v\n", err.Error())
			return nil, err
		}
		request.Header.Set("Authorization", authHdr)

		// try to get the userInf from Ping
		response, err := netClient.Do(request)
		if err != nil {
			log.Printf("Error communicating with Ping while requesting userInfo: %v\n", err.Error())
			return nil, err
		}

		// read the response from Png
		defer response.Body.Close()
		body, err := ioutil.ReadAll(response.Body)
		if err != nil {
			log.Printf("Error communicating with Ping while reading userInfo: %v\n", err.Error())
			return nil, err
		}
		log.Printf("userInfo from Ping: %v\n", string(body))
		u.userInfo = body
		u.accessed = time.Now().Unix()
		o.Lock()
		o.MyUsers[authHdr] = u // add to cache
		o.Unlock()
	}

	err = json.Unmarshal(body, &memberOf)
	if err != nil {
		log.Printf("Error parsing security groups from userInfo: %v\n", err)
		return nil, err
	}
	return memberOf, nil
}

func purgeCache(o *Oauthhelper) {
	var now int64
	var accessLimit int64 = 60 * 60
	for true {
		time.Sleep(time.Hour) // purge user cache once per hour
		// get the current time
		now = time.Now().Unix()
		o.Lock()
		for k, v := range o.MyUsers {
			if now > v.accessed+accessLimit {
				delete(o.MyUsers, k) // delete cache entries that have not been accessed for 1 hr
			}
		}
		o.Unlock()
		log.Printf("User cache purged, %v entries remain\n", len(o.MyUsers))
	}
}
