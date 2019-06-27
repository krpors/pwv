package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// caTime is a struct with only one member (time.Time) with an additional
// UnmarshalJSON function so we can handle the two ways the CyberArk API
// denotes time: with quotes such as "1543600800", or without, such as
// 1543600800.
type caTime struct {
	time.Time
}

func (m *caTime) UnmarshalJSON(b []byte) error {
	s := string(b)
	// remove double quotes, if any.
	s = strings.TrimLeft(s, "\"")
	s = strings.TrimRight(s, "\"")
	i, err := strconv.Atoi(s)
	if err != nil {
		return err
	}
	m.Time = time.Unix(int64(i), 0)
	return nil
}

// caLogonResponse contains the information after a successful login.
type caLogonResponse struct {
	CyberArkLogonResult string `json:"CyberArkLogonResult"`
	ErrorCode           string
	ErrorMessage        string
}

// caLogonRequest contains the payload for logging in.
type caLogonRequest struct {
	Username                string `json:"username"`
	Password                string `json:"password"`
	UseRadiusAuthentication bool   `json:"useRadiusAuthentication"`
	ConnectionNumber        int    `json:"connectionNumber"`
}

// caIncomingRequestsResponse will be returned by caApi.IncomingRequests().
type caIncomingRequestsResponse struct {
	IncomingRequests []caIncomingRequest
	Total            int
}

// caIncomingRequest contains response information for a single specific
// incoming request.
type caIncomingRequest struct {
	RequestID         string
	RequestorUserName string
	UserReason        string
	Operation         string
	AccessFrom        caTime
	AccessTo          caTime

	AccountDetails struct {
		Properties struct {
			Address      string
			Safe         string
			Name         string
			LastUsedDate caTime
			LastUsedBy   string
			Username     string
		}
	}
}

// caConfirmRequest is request payload for the caAPI.Confirm() function.
type caConfirmRequest struct {
	Reason string
}

type caConfirmResponse struct {
	ErrorCode    string
	ErrorMessage string
}

type caMyRequestsResponse struct {
	errorCode    string `json:"ErrorCode"`
	errorMessage string `json:"ErrorMessage"`
	MyRequests   []caMyRequest
}

type caMyRequest struct {
	Status         int
	StatusTitle    string
	AccountDetails struct {
		AccountID  string
		Properties struct {
			Name string
		}
	}
}

// caAPI is the struct containing the state and functions for interacting with
// a CyberArk password vault API.
type caAPI struct {
	Client   http.Client // The HTTP client
	Base     string      // Base URL of the PWV.
	LogonKey string      // The Logon key, a long random string. Non empty if logged in.
}

// Login logs the user in into the password vault given the username and password.
// Internally - when succesful that is - the LogonKey will be set. The key will
// be used to pass as Authorization header into subsequent requests.
func (api *caAPI) Login(username, password string) error {
	url := api.Base + "/PasswordVault/WebServices/auth/Cyberark/CyberArkAuthenticationService.svc/Logon"

	// Create the request as a struct, plus JSON marshaling.
	p := caLogonRequest{
		Username:                username,
		Password:                password,
		UseRadiusAuthentication: false,
		ConnectionNumber:        1,
	}

	b, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("unable to unmarshal login request: %s", err)
	}

	httpResponse, err := api.Client.Post(url, "application/json", bytes.NewBuffer(b))
	if err != nil {
		return fmt.Errorf("unable to create a POST request to '%s': %s", url, err)
	}
	defer httpResponse.Body.Close()

	// Read the response into a byte slice
	body, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		return fmt.Errorf("whoops")
	}

	// Unmarshal the response.
	logonResult := caLogonResponse{}
	err = json.Unmarshal(body, &logonResult)
	if err != nil {
		return err
	}

	if logonResult.ErrorCode != "" {
		return fmt.Errorf("%s (%s)", logonResult.ErrorCode, logonResult.ErrorMessage)
	}

	api.LogonKey = logonResult.CyberArkLogonResult

	return nil
}

// Logout will log the user out. All that is required is the API LogonKey.
// If no LogonKey exists (as in: it's an empty string), this function will
// return an error.
func (api *caAPI) Logout() error {
	if api.LogonKey == "" {
		return fmt.Errorf("no logon key exists - unable to logout")
	}

	logoff := api.Base + "/PasswordVault/WebServices/auth/Cyberark/CyberArkAuthenticationService.svc/Logoff"

	req, err := http.NewRequest("POST", logoff, nil)
	if err != nil {
		return err
	}

	// The response is not used when logging off.
	req.Header.Add("Authorization", api.LogonKey)
	_, err = api.Client.Do(req)
	if err != nil {
		return err
	}

	return nil
}

// IncomingRequests will fetch the incoming requests which can be approved by
// the logged in user.
func (api *caAPI) IncomingRequests() (caIncomingRequestsResponse, error) {
	response := caIncomingRequestsResponse{}

	if api.LogonKey == "" {
		return response, fmt.Errorf("no logon key exists")
	}

	url := api.Base + "/PasswordVault/API/IncomingRequests"
	httpReq, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return response, err
	}

	httpReq.Header.Add("Authorization", api.LogonKey)

	query := httpReq.URL.Query()
	query.Add("onlywaiting", "true")
	query.Add("expired", "false")
	httpReq.URL.RawQuery = query.Encode()

	httpResponse, err := api.Client.Do(httpReq)
	if err != nil {
		return response, err
	}
	defer httpResponse.Body.Close()

	bytes, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		return response, err
	}

	err = json.Unmarshal(bytes, &response)
	if err != nil {
		return response, err
	}

	return response, nil
}

// ConfirmRequest will attempt to confirm the given request. The RequestID
// is used for uniquely identifying the request for approval.
func (api *caAPI) ConfirmRequest(r caIncomingRequest, reason string) error {
	url := api.Base + "/PasswordVault/API/IncomingRequests/" + r.RequestID + "/Confirm"

	payload := caConfirmRequest{
		Reason: reason,
	}

	b, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("unable to unmarshal confirm request: %s", err)
	}

	httpReq, err := http.NewRequest("POST", url, bytes.NewBuffer(b))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Authorization", api.LogonKey)
	httpReq.Header.Set("Content-Type", "application/json")
	httpResp, err := api.Client.Do(httpReq)
	if err != nil {
		return err
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode == 200 {
		return nil
	}

	respBody, err := ioutil.ReadAll(httpResp.Body)
	if err != nil {
		return err
	}

	confirmResponse := caConfirmResponse{}
	err = json.Unmarshal(respBody, &confirmResponse)
	if err != nil {
		return err
	}
	if confirmResponse.ErrorCode != "" {
		return fmt.Errorf("%s (%s)", confirmResponse.ErrorCode, confirmResponse.ErrorMessage)
	}

	return nil
}

func (api *caAPI) MyRequests() (caMyRequestsResponse, error) {
	url := api.Base + "/PasswordVault/API/MyRequests"

	httpReq, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return caMyRequestsResponse{}, err
	}
	httpReq.Header.Set("Authorization", api.LogonKey)

	query := httpReq.URL.Query()
	query.Add("onlywaiting", "false")
	query.Add("expired", "false")
	httpReq.URL.RawQuery = query.Encode()

	httpResponse, err := api.Client.Do(httpReq)
	if err != nil {
		return caMyRequestsResponse{}, err
	}
	defer httpResponse.Body.Close()

	respBody, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		return caMyRequestsResponse{}, err
	}

	myReqs := caMyRequestsResponse{}
	err = json.Unmarshal(respBody, &myReqs)
	if err != nil {
		return caMyRequestsResponse{}, err
	}
	if myReqs.errorCode != "" {
		return caMyRequestsResponse{}, fmt.Errorf("%s (%s)", myReqs.errorCode, myReqs.errorMessage)
	}

	return myReqs, nil
}

func (api *caAPI) GetPassword(req caMyRequest) (string, error) {
	accID := req.AccountDetails.AccountID
	url := api.Base + "/PasswordVault/WebServices/PIMServices.svc/Accounts/" + accID + "/Credentials"

	httpReq, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("Authorization", api.LogonKey)

	httpResponse, err := api.Client.Do(httpReq)
	if err != nil {
		return "", err
	}
	defer httpResponse.Body.Close()

	bytes, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		return "", err
	}

	return string(bytes), nil
}
