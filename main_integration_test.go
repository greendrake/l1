package main_test

import (
	// "fmt"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"

	// "strconv"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson"

	"github.com/joho/godotenv"

	"greendrake/l1/internal/models" // Import models
	"greendrake/l1/internal/utils"  // Import utils for SixID

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	testAppBinary         = "./l1_test_app" // Name for the test binary
	testAppPort           = "8089"                  // Port for the test server
	testServiceApiPortApi = "8091"                  // Port for Service API run by API process
	testServiceApiPortBg  = "8092"                  // Port for Service API run by BG process (if any)
	testAppURL            = "http://localhost:" + testAppPort
	testServiceApiURL     = "http://localhost:" + testServiceApiPortApi // Use API process's service port
	startupTimeout        = 15 * time.Second                            // Slightly increased timeout
	pingEndpoint          = testAppURL + "/v1/ping"
)

// TestMain manages the setup and teardown of the integration test environment.
func TestMain(m *testing.M) {
	// Defer cleanup actions to ensure they run even if setup fails
	defer func() {
		log.Println("Integration Test Teardown: Cleaning up test binary...")
		// Attempt to remove the binary, ignore error if it doesn't exist
		_ = os.Remove(testAppBinary)
	}()

	log.Println("Integration Test Setup: Building application...")
	godotenv.Load()
	// Build the application binary specifically for testing
	buildCmd := exec.Command("go", "build", "-o", testAppBinary, ".")
	buildOutput, err := buildCmd.CombinedOutput()
	if err != nil {
		// Log error and exit, allowing deferred cleanup to run
		log.Printf("Failed to build application: %v\nOutput:\n%s", err, string(buildOutput))
		os.Exit(1)
	}
	log.Printf("Integration Test Setup: Build successful: %s", testAppBinary)

	// --- Seed required data ---
	seedErr := seedTestData()
	if seedErr != nil {
		log.Printf("Failed to seed test data: %v", seedErr)
		os.Exit(1)
	}
	// Ensure seed data is cleaned up
	defer cleanupTestData()

	// --- Start API Process ---
	apiCmd := exec.Command(testAppBinary, "-m", "api")
	apiCmd.Env = append(os.Environ(),
		"API_PORT="+testAppPort,
		"SERVICE_API_PORT="+testServiceApiPortApi, // Use specific port
		"JWT_SECRET=integration-test-secret",
		"GIN_MODE=release",
		"MOCK_SERVICES=true",
		"RATE_LIMIT_SOFT_BUCKET_SIZE=10",
		"RATE_LIMIT_SOFT_REFILL_RATE=10",
		"RATE_LIMIT_HARD_BUCKET_SIZE=20",
		"RATE_LIMIT_HARD_REFILL_RATE=20",
		"REDIS_ADDR=localhost:6379",
		"SMTP_FROM_ADDRESS=test@example.com", // Needed by mock sender
	)
	apiCmd.Stderr = os.Stderr
	apiCmd.Stdout = os.Stdout

	log.Println("Integration Test Setup: Starting API process...")
	err = apiCmd.Start()
	if err != nil {
		log.Printf("Failed to start API process: %v", err)
		os.Exit(1)
	}
	log.Printf("Integration Test Setup: API process started (PID: %d)...", apiCmd.Process.Pid)

	// --- Start Background Worker Process ---
	bgCmd := exec.Command(testAppBinary, "-m", "bg") // Run in background mode
	bgCmd.Env = append(os.Environ(),
		"SERVICE_API_PORT="+testServiceApiPortBg,
		"JWT_SECRET=integration-test-secret", // Needs JWT secret for potential internal calls?
		"GIN_MODE=release",                   // Keep logs clean
		"MOCK_SERVICES=true",                 // Essential for Redis email
		"REDIS_ADDR=localhost:6379",
		"SMTP_FROM_ADDRESS=test@example.com", // Needed by RedisSender
	)
	bgCmd.Stderr = os.Stderr
	bgCmd.Stdout = os.Stdout

	log.Println("Integration Test Setup: Starting Background Worker process...")
	err = bgCmd.Start()
	if err != nil {
		// Attempt to kill API process before exiting if BG process fails to start
		_ = apiCmd.Process.Kill()
		log.Printf("Failed to start Background Worker process: %v", err)
		os.Exit(1)
	}
	log.Printf("Integration Test Setup: Background Worker process started (PID: %d)...", bgCmd.Process.Pid)

	// Defer shutdown logic for BOTH processes
	defer func() {
		log.Println("Integration Test Teardown: Shutting down application processes...")
		// Shutdown BG worker first
		log.Println("Sending SIGTERM to Background Worker...")
		if processErr := bgCmd.Process.Signal(syscall.SIGTERM); processErr != nil {
			log.Printf("Integration Test Teardown: Failed to send SIGTERM to BG Worker: %v. Killing.", processErr)
			_ = bgCmd.Process.Kill()
		} else {
			_, waitErr := bgCmd.Process.Wait()
			if waitErr != nil && waitErr.Error() != "signal: killed" && waitErr.Error() != "exit status 1" {
				log.Printf("Integration Test Teardown: Error waiting for BG Worker exit: %v", waitErr)
			}
		}
		// Shutdown API process
		log.Println("Sending SIGTERM to API Process...")
		if processErr := apiCmd.Process.Signal(syscall.SIGTERM); processErr != nil {
			log.Printf("Integration Test Teardown: Failed to send SIGTERM to API Process: %v. Killing.", processErr)
			_ = apiCmd.Process.Kill()
		} else {
			_, waitErr := apiCmd.Process.Wait()
			if waitErr != nil && waitErr.Error() != "signal: killed" && waitErr.Error() != "exit status 1" {
				log.Printf("Integration Test Teardown: Error waiting for API Process exit: %v", waitErr)
			}
		}
		log.Println("Integration Test Teardown: Application processes stopped.")
	}()

	// Wait for the API application to be ready by polling the ping endpoint
	log.Printf("Integration Test Setup: Waiting for API application to become ready at %s...", pingEndpoint)
	startTime := time.Now()
	ready := false
	for time.Since(startTime) < startupTimeout {
		resp, err := http.Get(pingEndpoint)
		if err == nil && resp.StatusCode == http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if string(bodyBytes) == "pong" {
				log.Println("Integration Test Setup: Application is ready!")
				ready = true
				break
			}
		}
		if resp != nil {
			resp.Body.Close() // Ensure body is closed even on non-200 status
		}
		time.Sleep(200 * time.Millisecond) // Poll interval
	}

	if !ready {
		// Log error and exit, allowing deferred cleanup to run
		log.Printf("Application failed to start within %v", startupTimeout)
		os.Exit(1)
	}

	// Add a small pause to allow the background worker to initialize
	// This is a simplification; ideally, the worker might have a health check endpoint.
	log.Println("Integration Test Setup: Pausing briefly for background worker startup...")
	time.Sleep(2 * time.Second)

	// Run the actual tests
	log.Println("Integration Test Setup: Running tests...")
	exitCode := m.Run()
	log.Printf("Integration Test Teardown: Tests finished with exit code %d.", exitCode)
	// os.Exit(exitCode) // DO NOT call os.Exit here; it prevents deferred functions from running.
	// Let TestMain return normally. The test runner will handle the exit code.
}

// TestIntegration_Ping tests the /v1/ping endpoint of the running application.
func TestIntegration_Ping(t *testing.T) {
	// Arrange: TestMain has already started the server. We just need the URL.

	// Act: Make request to the ping endpoint of the running server
	resp, err := http.Get(pingEndpoint)
	assert.NoError(t, err, "Request to %s should not fail", pingEndpoint)
	if err != nil {
		t.FailNow() // Cannot proceed if request failed
	}
	defer resp.Body.Close()

	// Assert: Check status code and body
	assert.Equal(t, http.StatusOK, resp.StatusCode, "Expected status code OK (200)")

	bodyBytes, err := io.ReadAll(resp.Body)
	assert.NoError(t, err, "Should be able to read response body")

	expectedBody := "pong"
	assert.Equal(t, expectedBody, string(bodyBytes), "Response body should be 'pong'")
}

// TestIntegration_JsonApiPing tests the `ping` method of the custom JSON API.
func TestIntegration_JsonApiPing(t *testing.T) {
	// Arrange: TestMain has started the server. We need the URL and the request body.
	apiEndpoint := testAppURL + "/v1/api"
	requestBody := `{"method": "ping"}`

	// Act: Make POST request to the JSON API endpoint
	reqBodyReader := bytes.NewReader([]byte(requestBody))
	resp, err := http.Post(apiEndpoint, "application/json", reqBodyReader)
	assert.NoError(t, err, "Request to %s should not fail", apiEndpoint)
	if err != nil {
		t.FailNow() // Cannot proceed if request failed
	}
	defer resp.Body.Close()

	// Assert: Check status code and response body structure/content
	assert.Equal(t, http.StatusOK, resp.StatusCode, "Expected status code OK (200)")

	bodyBytes, err := io.ReadAll(resp.Body)
	assert.NoError(t, err, "Should be able to read response body")

	// Unmarshal the JSON response
	var respBody map[string]interface{}
	err = json.Unmarshal(bodyBytes, &respBody)
	assert.NoError(t, err, "Should be able to unmarshal JSON response body")

	// Check the response content
	expectedResp := map[string]interface{}{
		"success": true,
		"data":    "pong",
	}
	assert.Equal(t, expectedResp, respBody, "Response body should match expected JSON")
}

// TestIntegration_LocationSearch_Nightcaps tests the location search endpoint.
func TestIntegration_LocationSearch_Nightcaps(t *testing.T) {
	// Arrange: Endpoint URL with query parameter
	searchQuery := "Nightcaps"
	searchURL := fmt.Sprintf("%s/v1/location/search?q=%s", testAppURL, url.QueryEscape(searchQuery))

	// Act: Make GET request
	resp, err := http.Get(searchURL)
	assert.NoError(t, err, "Request to %s should not fail", searchURL)
	if err != nil {
		t.FailNow()
	}
	defer resp.Body.Close()

	// Assert: Check status code
	assert.Equal(t, http.StatusOK, resp.StatusCode, "Expected status code OK (200)")

	// Assert: Check response body content
	bodyBytes, err := io.ReadAll(resp.Body)
	assert.NoError(t, err, "Should be able to read response body")

	// Unmarshal the JSON response (expecting an array of location objects)
	// Using a specific struct slice based on handler definition
	var results []struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Context     string `json:"context,omitempty"`
		CountryCode string `json:"country_code"`
	}
	err = json.Unmarshal(bodyBytes, &results)
	assert.NoError(t, err, "Should be able to unmarshal JSON response body into results slice")

	// Check if "Nightcaps" is found in the results
	found := false
	for _, loc := range results {
		if loc.Name == searchQuery {
			found = true
			log.Printf("Found location: %+v", loc) // Log the found location for info
			break
		}
	}
	assert.True(t, found, "Expected to find location '%s' in the search results", searchQuery)
}

// Helper to make JSON API requests
func makeJsonApiRequest(t *testing.T, method string, args []interface{}) (map[string]interface{}, *http.Response, error) {
	t.Helper()
	payload := map[string]interface{}{
		"method":    method,
		"arguments": args,
	}
	return makeJsonApiRequestManual(t, payload, "")
}

const IDPattern = `([0-9A-Z]{10})`

// setupLoggedInUser performs sign-up/login using the Service API for email retrieval.
func setupLoggedInUser(t *testing.T) (email, password, jwtToken string) {
	t.Helper()
	email = fmt.Sprintf("testuser_%d@example.com", time.Now().UnixNano())
	password = "StrongP@ssw0rd123"
	log.Printf("Setting up logged-in user: %s", email)

	// Step 1: Initial signInOrUp
	respBody1, resp1, err1 := makeJsonApiRequest(t, "signInOrUp", []interface{}{email})
	require.NoError(t, err1, "setupLoggedInUser: signInOrUp (initial) request failed")
	defer resp1.Body.Close()
	require.Equal(t, http.StatusOK, resp1.StatusCode, "setupLoggedInUser: signInOrUp (initial) status code")
	require.Equal(t, map[string]interface{}{"success": true, "data": "created"}, respBody1, "setupLoggedInUser: signInOrUp (initial) response body")

	// Step 2: Fetch activation email via Service API & Extract ID
	emailData := getEmailFromServiceAPI(t, models.ActionLoginToSetupAccount, email)
	activateActionID := extractActionIDFromEmailBody(t, emailData, `/la/`+IDPattern)

	// Step 3: setCredentials
	setCredsPayload := map[string]interface{}{
		"method": "setCredentials",
		"arguments": []interface{}{
			map[string]interface{}{
				"linked_action_id": activateActionID,
				"auth_type":        "password_only",
				"secrets":          []string{password},
			},
		},
	}
	respBody3, resp3, err3 := makeJsonApiRequestManual(t, setCredsPayload, "")
	require.NoError(t, err3, "setupLoggedInUser: setCredentials request failed")
	defer resp3.Body.Close()
	require.Equal(t, http.StatusOK, resp3.StatusCode, "setupLoggedInUser: setCredentials status code")
	success3, _ := respBody3["success"].(bool)
	require.True(t, success3, "setupLoggedInUser: setCredentials response body success field was not true")
	authData3, ok := respBody3["data"].(map[string]interface{})
	require.True(t, ok, "setupLoggedInUser: setCredentials response data is not a map")
	require.Equal(t, email, authData3["email"], "setupLoggedInUser: setCredentials response email mismatch")
	require.NotEmpty(t, authData3["id"], "setupLoggedInUser: setCredentials response ID should not be empty")
	require.NotEmpty(t, authData3["token"], "setupLoggedInUser: setCredentials response token should not be empty")

	// Step 4: login
	loginPayload := map[string]interface{}{
		"method": "login",
		"arguments": []interface{}{
			map[string]interface{}{
				"email":          email,
				"challenge_type": "password",
				"secret":         password,
			},
		},
	}
	respBody4, resp4, err4 := makeJsonApiRequestManual(t, loginPayload, "")
	require.NoError(t, err4, "setupLoggedInUser: login request failed")
	defer resp4.Body.Close()
	require.Equal(t, http.StatusOK, resp4.StatusCode, "setupLoggedInUser: login status code")
	success4, _ := respBody4["success"].(bool)
	require.True(t, success4, "setupLoggedInUser: login response body success field was not true")
	authData4, ok := respBody4["data"].(map[string]interface{})
	require.True(t, ok, "setupLoggedInUser: login response data is not a map")
	require.Equal(t, email, authData4["email"], "setupLoggedInUser: login response email mismatch")
	require.NotEmpty(t, authData4["id"], "setupLoggedInUser: login response ID should not be empty")
	require.NotEmpty(t, authData4["token"], "setupLoggedInUser: login response token should not be empty")
	jwtToken = authData4["token"].(string)

	log.Printf("Setup complete for logged-in user: %s", email)
	return email, password, jwtToken
}

// makeJsonApiRequestManual is a helper for requests where args is an object
// Accepts an optional jwtToken to add the Authorization header.
func makeJsonApiRequestManual(t *testing.T, payload map[string]interface{}, jwtToken string) (map[string]interface{}, *http.Response, error) {
	t.Helper()
	apiEndpoint := testAppURL + "/v1/api"
	bodyBytes, err := json.Marshal(payload)
	require.NoError(t, err, "Failed to marshal manual request payload")

	bodyReader := bytes.NewReader(bodyBytes)
	// Use http.NewRequest to allow setting headers
	req, err := http.NewRequest("POST", apiEndpoint, bodyReader)
	require.NoError(t, err, "Failed to create manual HTTP request")
	req.Header.Set("Content-Type", "application/json")

	// Add Authorization header if token is provided
	if jwtToken != "" {
		req.Header.Set("Authorization", "Bearer "+jwtToken)
	}

	// Send the request using the default client
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, resp, err
	}

	respBodyBytes, readErr := io.ReadAll(resp.Body)
	require.NoError(t, readErr, "Failed to read manual response body")

	var respBody map[string]interface{}
	unmarshalErr := json.Unmarshal(respBodyBytes, &respBody)
	if unmarshalErr != nil {
		log.Printf("Failed to unmarshal manual response: %v. Body: %s", unmarshalErr, string(respBodyBytes))
		respBody = map[string]interface{}{"raw_body": string(respBodyBytes)}
	}
	return respBody, resp, nil
}

// TestIntegration_SignUpAndLogin tests the basic sign up and login flow using the helper.
func TestIntegration_SignUpAndLogin(t *testing.T) {
	_, _, jwtToken := setupLoggedInUser(t)
	assert.NotEmpty(t, jwtToken, "SignUpAndLogin helper should return a JWT")
}

// TestIntegration_EmailChange tests the email change flow.
func TestIntegration_EmailChange(t *testing.T) {
	// Arrange: Get logged-in user details
	oldEmail, oldPassword, jwtToken := setupLoggedInUser(t)
	newEmail := fmt.Sprintf("new_email_%d@example.com", time.Now().UnixNano())
	log.Printf("Starting email change test from %s to %s", oldEmail, newEmail)

	// Step 1: Call startChangingEmail (authenticated)
	startPayload := map[string]interface{}{
		"method":    "startChangingEmail",
		"arguments": []interface{}{newEmail}, // Wrapped in an array
	}
	_, startResp, err := makeJsonApiRequestManual(t, startPayload, jwtToken)
	require.NoError(t, err, "startChangingEmail request failed")
	defer startResp.Body.Close()
	require.Equal(t, http.StatusOK, startResp.StatusCode, "startChangingEmail status code")

	// Step 2: Fetch confirmation emails via Service API
	approveEmailData := getEmailFromServiceAPI(t, models.ActionEmailChangeOldApprove, oldEmail)
	approveActionID := extractActionIDFromEmailBody(t, approveEmailData, `/la/`+IDPattern)

	confirmEmailData := getEmailFromServiceAPI(t, models.ActionEmailChangeNewConfirm, newEmail)
	confirmActionID := extractActionIDFromEmailBody(t, confirmEmailData, `/la/`+IDPattern)

	// Step 3: Invoke 'approve' action
	approvePayload := map[string]interface{}{
		"method":    "invokeLinkedAction",
		"arguments": []interface{}{approveActionID},
	}
	approveRespBody, approveResp, approveErr := makeJsonApiRequestManual(t, approvePayload, jwtToken)
	require.NoError(t, approveErr, "invokeLinkedAction (approve) request failed")
	require.Equal(t, http.StatusOK, approveResp.StatusCode, "invokeLinkedAction (approve) status code")
	successApprove, ok := approveRespBody["success"].(bool)
	require.True(t, ok && successApprove, "invokeLinkedAction (approve) response should be success")
	dataApprove, ok := approveRespBody["data"].(map[string]interface{})
	require.True(t, ok, "invokeLinkedAction (approve) response data should be a map")
	require.Equal(t, "email_change_old_approve", dataApprove["type"], "invokeLinkedAction (approve) response should include correct action type")

	// Step 4: Invoke 'confirm' action
	confirmPayload := map[string]interface{}{
		"method":    "invokeLinkedAction",
		"arguments": []interface{}{confirmActionID},
	}
	confirmRespBody, confirmResp, confirmErr := makeJsonApiRequestManual(t, confirmPayload, jwtToken)
	require.NoError(t, confirmErr, "invokeLinkedAction (confirm) request failed")
	require.Equal(t, http.StatusOK, confirmResp.StatusCode, "invokeLinkedAction (confirm) status code")
	successConfirm, ok := confirmRespBody["success"].(bool)
	require.True(t, ok && successConfirm, "invokeLinkedAction (confirm) response should be success")
	dataConfirm, ok := confirmRespBody["data"].(map[string]interface{})
	require.True(t, ok, "invokeLinkedAction (confirm) response data should be a map")
	require.Equal(t, "email_change_new_confirm", dataConfirm["type"], "invokeLinkedAction (confirm) response should include correct action type")

	// Step 5: Attempt login with NEW email and OLD password
	loginPayloadAfterChange := map[string]interface{}{ // Renamed to avoid conflict
		"method": "login",
		"arguments": []interface{}{ // Wrapped in an array
			map[string]interface{}{ // Corrected map literal
				"email":          newEmail,
				"challenge_type": "password",
				"secret":         oldPassword,
			},
		},
	}
	loginRespBody, loginResp, loginErr := makeJsonApiRequestManual(t, loginPayloadAfterChange, "")
	require.NoError(t, loginErr, "Login attempt with new email failed")
	defer loginResp.Body.Close()
	require.Equal(t, http.StatusOK, loginResp.StatusCode, "Login with new email status code")
	successLogin, _ := loginRespBody["success"].(bool)
	require.True(t, successLogin, "Login with new email should succeed")
	authData, ok := loginRespBody["data"].(map[string]interface{})
	require.True(t, ok, "Login with new email response data is not a map")
	require.Equal(t, newEmail, authData["email"], "Login with new email response email mismatch")
	require.NotEmpty(t, authData["id"], "Login with new email response ID should not be empty")
	require.NotEmpty(t, authData["token"], "Login with new email response token should not be empty")

	log.Printf("Email change successful: %s -> %s", oldEmail, newEmail)
}

// TestIntegration_EmailChange_ToExistingUserEmail tests the scenario where a user tries to change their email to an email address that is already in use by another existing user.
func TestIntegration_EmailChange_ToExistingUserEmail(t *testing.T) {
	// Arrange: Set up User A
	_, _, userAJwtToken := setupLoggedInUser(t) // userAEmail and userAPassword are not needed for this specific test logic for User A

	// Arrange: Set up User B with a distinct email
	userBEmail, _, _ := setupLoggedInUser(t) // userBPassword and userBJwtToken are not needed for User B

	log.Printf("Testing email change attempt to an existing email: User A attempts to change to User B\\'s email (%s)", userBEmail)

	// Act: User A attempts to change their email to userBEmail
	startPayload := map[string]interface{}{
		"method":    "startChangingEmail",
		"arguments": []interface{}{userBEmail}, // User A tries to change to User B's email
	}
	respBody, httpResp, err := makeJsonApiRequestManual(t, startPayload, userAJwtToken) // Use User A's token
	require.NoError(t, err, "startChangingEmail request to existing email failed")
	defer httpResp.Body.Close()

	// Assert: Check the response
	require.Equal(t, http.StatusOK, httpResp.StatusCode, "startChangingEmail to existing email should return HTTP 200")

	success, ok := respBody["success"].(bool)
	require.True(t, ok, "Response 'success' field should be a boolean")
	require.True(t, success, "Response 'success' field should be true")

	data, ok := respBody["data"].(string)
	require.True(t, ok, "Response 'data' field should be a string")
	require.Equal(t, "exists", data, "Response 'data' field should be 'exists' when email is already in use")

	log.Printf("Successfully verified that attempting to change email to an existing one returns 'exists'.")
}

// TestIntegration_SignUpAndLogin_EmailCodeOnly tests email-only auth flow.
func TestIntegration_SignUpAndLogin_EmailCodeOnly(t *testing.T) {
	// Arrange: Generate unique email
	email := fmt.Sprintf("test_email_only_%d@example.com", time.Now().UnixNano())
	log.Printf("Testing email-only sign-up/login for: %s", email)

	// 1. Initial signInOrUp (sends activation email)
	respBody1, resp1, err1 := makeJsonApiRequest(t, "signInOrUp", []interface{}{email})
	require.NoError(t, err1, "signInOrUp (initial) request failed")
	defer resp1.Body.Close()
	require.Equal(t, http.StatusOK, resp1.StatusCode, "signInOrUp (initial) status code")
	require.Equal(t, map[string]interface{}{"success": true, "data": "created"}, respBody1, "signInOrUp (initial) response body")

	// 2. Fetch activation email via Service API
	activateEmailData := getEmailFromServiceAPI(t, models.ActionLoginToSetupAccount, email)
	activateActionID := extractActionIDFromEmailBody(t, activateEmailData, `/la/`+IDPattern)

	// 3. Set Credentials (email_login_code_only, no secrets)
	setCredsPayloadEmailOnly := map[string]interface{}{ // Renamed
		"method": "setCredentials",
		"arguments": []interface{}{ // Wrapped
			map[string]interface{}{ // Corrected map literal
				"linked_action_id": activateActionID,
				"auth_type":        models.AuthTypeEmailLoginCodeOnly,
				"secrets":          []string{},
			},
		},
	}
	_, resp3SetCredsEmailOnly, err3SetCredsEmailOnly := makeJsonApiRequestManual(t, setCredsPayloadEmailOnly, "") // Renamed resp and err
	require.NoError(t, err3SetCredsEmailOnly, "setCredentials request failed")
	defer resp3SetCredsEmailOnly.Body.Close()
	require.Equal(t, http.StatusOK, resp3SetCredsEmailOnly.StatusCode, "setCredentials status code")

	// 4. signIn (should return email_code and send login code email)
	respBody4, resp4, err4 := makeJsonApiRequest(t, "signIn", []interface{}{email})
	require.NoError(t, err4, "signIn request failed")
	defer resp4.Body.Close()
	require.Equal(t, http.StatusOK, resp4.StatusCode, "signIn status code")
	require.Equal(t, map[string]interface{}{"success": true, "data": "email_code"}, respBody4, "signIn response body")

	// 5. Fetch login code email via Service API
	loginCodeEmailData := getEmailFromServiceAPI(t, models.ActionEmailLoginCode, email)
	loginActionID := extractActionIDFromEmailBody(t, loginCodeEmailData, `/la/`+IDPattern)

	// 6. login with email code
	loginEmailCodePayload := map[string]interface{}{ // Renamed
		"method": "login",
		"arguments": []interface{}{ // Wrapped
			map[string]interface{}{ // Corrected map literal
				"email":          email,
				"challenge_type": "email_code",
				"secret":         loginActionID,
			},
		},
	}
	respBody6, resp6, err6 := makeJsonApiRequestManual(t, loginEmailCodePayload, "")
	require.NoError(t, err6, "login request failed")
	defer resp6.Body.Close()
	require.Equal(t, http.StatusOK, resp6.StatusCode, "login status code")
	success6, _ := respBody6["success"].(bool)
	require.True(t, success6, "login response body success field was not true")
	authData6, ok := respBody6["data"].(map[string]interface{})
	require.True(t, ok, "login response data is not a map")
	require.Equal(t, email, authData6["email"], "login response email mismatch")
	require.NotEmpty(t, authData6["id"], "login response ID should not be empty")
	require.NotEmpty(t, authData6["token"], "login response token should not be empty")

	log.Printf("Successfully signed up and logged in via email code only for %s", email)
}

// TestIntegration_SignUpAndLogin_PasswordAndEmailCode tests password+email 2FA flow.
func TestIntegration_SignUpAndLogin_PasswordAndEmailCode(t *testing.T) {
	// Arrange: Generate unique email and password
	email := fmt.Sprintf("test_pw_email_%d@example.com", time.Now().UnixNano())
	password := "StrongP@ssw0rd123"
	log.Printf("Testing password+email sign-up/login for: %s", email)

	// 1. Initial signInOrUp (sends activation email)
	respBody1, resp1, err1 := makeJsonApiRequest(t, "signInOrUp", []interface{}{email})
	require.NoError(t, err1, "signInOrUp (initial) request failed")
	defer resp1.Body.Close()
	require.Equal(t, http.StatusOK, resp1.StatusCode, "signInOrUp (initial) status code")
	require.Equal(t, map[string]interface{}{"success": true, "data": "created"}, respBody1, "signInOrUp (initial) response body")

	// 2. Fetch activation email via Service API
	activateEmailData := getEmailFromServiceAPI(t, models.ActionLoginToSetupAccount, email)
	activateActionID := extractActionIDFromEmailBody(t, activateEmailData, `/la/`+IDPattern)

	// 3. Set Credentials (password_and_email_login_code)
	setCredsPwEmailPayload := map[string]interface{}{ // Renamed
		"method": "setCredentials",
		"arguments": []interface{}{ // Wrapped
			map[string]interface{}{ // Ensured keys are inside braces
				"linked_action_id": activateActionID,
				"auth_type":        models.AuthTypePasswordAndEmailLoginCode,
				"secrets":          []string{password},
			},
		},
	}
	_, resp3SetCredsPwEmail, err3SetCredsPwEmail := makeJsonApiRequestManual(t, setCredsPwEmailPayload, "") // Renamed resp and err
	require.NoError(t, err3SetCredsPwEmail, "setCredentials request failed")
	defer resp3SetCredsPwEmail.Body.Close()
	require.Equal(t, http.StatusOK, resp3SetCredsPwEmail.StatusCode, "setCredentials status code")

	// 4. signIn (should return password)
	respBody4, resp4, err4 := makeJsonApiRequest(t, "signIn", []interface{}{email})
	require.NoError(t, err4, "signIn request failed")
	defer resp4.Body.Close()
	require.Equal(t, http.StatusOK, resp4.StatusCode, "signIn status code")
	require.Equal(t, map[string]interface{}{"success": true, "data": "password"}, respBody4, "signIn response body")

	// 5. login with password (should return email_code and send email)
	loginPwPayload := map[string]interface{}{ // Ensured keys are inside braces
		"method": "login",
		"arguments": []interface{}{ // Wrapped
			map[string]interface{}{ // Ensured keys are inside braces
				"email":          email,
				"challenge_type": "password",
				"secret":         password,
			},
		},
	}
	respBody5, resp5, err5 := makeJsonApiRequestManual(t, loginPwPayload, "")
	require.NoError(t, err5, "login (password) request failed")
	defer resp5.Body.Close()
	require.Equal(t, http.StatusOK, resp5.StatusCode, "login (password) status code")
	require.Equal(t, map[string]interface{}{"success": true, "data": "email_code"}, respBody5, "login (password) response body")

	// 6. Fetch login code email via Service API
	loginCodeEmailData := getEmailFromServiceAPI(t, models.ActionEmailLoginCode, email)
	loginActionID := extractActionIDFromEmailBody(t, loginCodeEmailData, `/la/`+IDPattern)

	// 7. login with email code
	loginCodePayloadPwEmail := map[string]interface{}{
		"method": "login",
		"arguments": []interface{}{
			map[string]interface{}{
				"email":          email,
				"challenge_type": "email_code",
				"secret":         loginActionID,
			},
		},
	}
	respBody7, resp7, err7 := makeJsonApiRequestManual(t, loginCodePayloadPwEmail, "")
	require.NoError(t, err7, "login (email_code) request failed")
	defer resp7.Body.Close()
	require.Equal(t, http.StatusOK, resp7.StatusCode, "login (email_code) status code")
	success7, _ := respBody7["success"].(bool)
	require.True(t, success7, "login (email_code) response body success field was not true")
	authData7, ok := respBody7["data"].(map[string]interface{})
	require.True(t, ok, "login (email_code) response data is not a map")
	require.Equal(t, email, authData7["email"], "login (email_code) response email mismatch")
	require.NotEmpty(t, authData7["id"], "login (email_code) response ID should not be empty")
	require.NotEmpty(t, authData7["token"], "login (email_code) response token should not be empty")

	log.Printf("Successfully signed up and logged in via password+email for %s", email)
}

// TestIntegration_AccountDeletion tests the account deletion flow.
func TestIntegration_AccountDeletion(t *testing.T) {
	// Arrange: Get logged-in user details
	email, _, jwtToken := setupLoggedInUser(t)
	log.Printf("Testing account deletion for: %s", email)

	// 1. Call requestAccountDeletion
	requestPayload := map[string]interface{}{
		"method": "requestAccountDeletion",
	}
	_, reqResp, reqErr := makeJsonApiRequestManual(t, requestPayload, jwtToken)
	require.NoError(t, reqErr, "requestAccountDeletion request failed")
	defer reqResp.Body.Close()
	require.Equal(t, http.StatusOK, reqResp.StatusCode, "requestAccountDeletion status code")

	// 2. Fetch deletion confirmation email via Service API
	deleteEmailData := getEmailFromServiceAPI(t, "confirm_account_deletion", email)
	deleteActionID := extractActionIDFromEmailBody(t, deleteEmailData, `/la/`+IDPattern)

	// 3. Invoke deletion action
	invokePayload := map[string]interface{}{
		"method":    "invokeLinkedAction",
		"arguments": []interface{}{deleteActionID},
	}
	invokeRespBody, invokeResp, invokeErr := makeJsonApiRequestManual(t, invokePayload, jwtToken)
	require.NoError(t, invokeErr, "invokeLinkedAction (delete) request failed")
	require.Equal(t, http.StatusOK, invokeResp.StatusCode, "invokeLinkedAction (delete) status code")
	successInvoke, ok := invokeRespBody["success"].(bool)
	require.True(t, ok && successInvoke, "invokeLinkedAction (delete) response should be success")
	dataInvoke, ok := invokeRespBody["data"].(map[string]interface{})
	require.True(t, ok, "invokeLinkedAction (delete) response data should be a map")
	require.Equal(t, "confirm_account_deletion", dataInvoke["type"], "invokeLinkedAction (delete) response should include correct action type")

	// 4. Attempt signInOrUp with the SAME email (should act as new user)
	reqBody2, resp2, err2 := makeJsonApiRequest(t, "signInOrUp", []interface{}{email})
	require.NoError(t, err2, "signInOrUp (after delete) request failed")
	defer resp2.Body.Close()
	require.Equal(t, http.StatusOK, resp2.StatusCode, "signInOrUp (after delete) status code")
	require.Equal(t, map[string]interface{}{"success": true, "data": "created"}, reqBody2, "signInOrUp (after delete) response body should be 'created'")

	log.Printf("Account deletion and re-signup check successful for %s", email)
}

// TestIntegration_GetLocationByCoords_Nightcaps tests the getLocationByCoords JSON API method.
func TestIntegration_GetLocationByCoords_Nightcaps(t *testing.T) {
	// Arrange: API endpoint and request payload
	apiEndpoint := testAppURL + "/v1/api"
	payload := map[string]interface{}{ // Corrected: Ensure this is not an empty map literal if keys follow
		"method": "getLocationByCoords",
		"arguments": []interface{}{ // Wrapped in an array
			map[string]interface{}{ // Ensured keys are inside braces
				"latitude":  -45.970,
				"longitude": 168.028,
			},
		},
	}

	// Act: Make POST request to the JSON API endpoint
	respBody, resp, err := makeJsonApiRequestManual(t, payload, "") // No JWT needed for public endpoint
	require.NoError(t, err, "Request to %s with method getLocationByCoords should not fail", apiEndpoint)
	if err != nil {
		t.FailNow()
	}
	defer resp.Body.Close()

	// Assert: Check status code
	assert.Equal(t, http.StatusOK, resp.StatusCode, "Expected status code OK (200)")

	// Assert: Check response body structure/content
	require.True(t, respBody["success"].(bool), "Expected success to be true")

	dataResult, ok := respBody["data"].(map[string]interface{})
	require.True(t, ok, "Expected data to be a map")

	// Check the name field in the data
	expectedName := "Nightcaps"
	actualName, nameOk := dataResult["name"].(string)
	require.True(t, nameOk, "Expected name to be a string in the data")
	assert.Equal(t, expectedName, actualName, "Expected location name to be '%s'", expectedName)

	// Optionally, log the full data for inspection
	log.Printf("GetLocationByCoords data for Nightcaps: %+v", dataResult)
}

// seedTestData connects to MongoDB and inserts necessary test data.
func seedTestData() error {
	log.Println("Seeding test data...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	mongoURI := os.Getenv("MONGO_URI")
	dbName := os.Getenv("MONGO_DB_NAME")

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(mongoURI))
	if err != nil {
		return fmt.Errorf("failed to connect to MongoDB for seeding: %w", err)
	}
	defer func() {
		if err := client.Disconnect(ctx); err != nil {
			log.Printf("Error disconnecting seeding client: %v", err)
		}
	}()

	db := client.Database(dbName)
	templateCollection := db.Collection("email_templates")

	// Use the default templates from the email template service
	templatesToSeed := []models.EmailTemplate{
		{
			ID:         utils.NewSixID(),
			TemplateID: "activate_account",
			Locale:     "en-US",
			Subject:    "Activate your L1 Account",
			Body:       "Welcome! Please click here to activate: /la/{{.action_id}}",
		},
		{
			ID:         utils.NewSixID(),
			TemplateID: "email_change_approve",
			Locale:     "en-US",
			Subject:    "Approve Email Change Request",
			Body:       "Request to change email. Please click to approve from old address: /la/{{.action_id}}",
		},
		{
			ID:         utils.NewSixID(),
			TemplateID: "email_change_confirm",
			Locale:     "en-US",
			Subject:    "Confirm New Email Address",
			Body:       "Please click here to confirm your new email address: /la/{{.action_id}}",
		},
		{
			ID:         utils.NewSixID(),
			TemplateID: "email_login_code",
			Locale:     "en-US",
			Subject:    "Your L1 Login Code",
			Body:       "Here is your login code: {{.action_id}}. It will expire shortly. Alternatively, click /la/{{.action_id}}",
		},
		{
			ID:         utils.NewSixID(),
			TemplateID: "confirm_account_deletion",
			Locale:     "en-US",
			Subject:    "Confirm Account Deletion",
			Body:       "Click here to confirm permanent deletion of your account: /la/{{.action_id}}",
		},
	}

	for _, template := range templatesToSeed {
		// Delete existing template by template_id and locale first to avoid immutable _id update errors
		delFilter := bson.M{"template_id": template.TemplateID, "locale": template.Locale}
		_, err = templateCollection.DeleteOne(ctx, delFilter)
		if err != nil {
			return fmt.Errorf("failed to delete existing '%s' template: %w", template.TemplateID, err)
		}

		// Insert new template with assigned SixID _id
		_, err = templateCollection.InsertOne(ctx, template)
		if err != nil {
			return fmt.Errorf("failed to seed '%s' template: %w", template.TemplateID, err)
		}
		log.Printf("Successfully seeded '%s' email template.", template.TemplateID)
	}

	// Seed test location data for getLocationByCoords test
	locationCollection := db.Collection("locations")

	// Ensure indexes exist
	indexes := []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "parent_id", Value: 1}},
			Options: options.Index().SetName("parent_id_1"),
		},
		{
			Keys: bson.D{
				{Key: "_fts", Value: "text"},
				{Key: "_ftsx", Value: 1},
			},
			Options: options.Index().
				SetName("LocationTextIndex").
				SetWeights(bson.M{"alt_names": 1, "name": 2}).
				SetDefaultLanguage("english").
				SetLanguageOverride("language").
				SetTextVersion(3),
		},
		{
			Keys:    bson.D{{Key: "location", Value: "2dsphere"}},
			Options: options.Index().SetName("location_2dsphere").SetSphereVersion(3),
		},
	}

	_, err = locationCollection.Indexes().CreateMany(ctx, indexes)
	if err != nil {
		return fmt.Errorf("failed to create indexes for 'locations' collection: %w", err)
	}
	log.Println("Successfully ensured indexes for 'locations' collection.")

	// Delete any existing Nightcaps location
	_, err = locationCollection.DeleteMany(ctx, bson.M{"name": "Nightcaps"})
	if err != nil {
		return fmt.Errorf("failed to delete existing 'Nightcaps' location: %w", err)
	}
	// Insert test location for Nightcaps
	nightcaps := models.Location{
		ID:          10000,
		Name:        "Nightcaps",
		CountryCode: "NZ",
		Context:     []string{"Southland", "New Zealand"},
		Location: &models.GeoJSON{
			Type:        "Point",
			Coordinates: []float64{168.028, -45.97},
		},
	}
	_, err = locationCollection.InsertOne(ctx, nightcaps)
	if err != nil {
		return fmt.Errorf("failed to seed 'Nightcaps' location: %w", err)
	}
	log.Println("Successfully seeded 'Nightcaps' location.")

	return nil
}

// cleanupTestData removes seeded test data.
func cleanupTestData() {
	log.Println("Cleaning up seeded test data...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	mongoURI := os.Getenv("MONGO_URI")
	dbName := os.Getenv("MONGO_DB_NAME")

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(mongoURI))
	if err != nil {
		log.Printf("Failed to connect to MongoDB for cleanup: %v", err)
		return
	}
	defer func() {
		if err := client.Disconnect(ctx); err != nil {
			log.Printf("Error disconnecting cleanup client: %v", err)
		}
	}()

	db := client.Database(dbName)
	templateCollection := db.Collection("email_templates")

	// Delete the seeded templates
	templateIDs := []string{"activate_account", "email_change_approve", "email_change_confirm", "email_login_code", "confirm_account_deletion"} // Added confirm_account_deletion
	filter := bson.M{
		"template_id": bson.M{"$in": templateIDs},
		"locale":      "en-US",
	}
	deleteResult, err := templateCollection.DeleteMany(ctx, filter)
	if err != nil {
		log.Printf("Failed to delete seeded templates during cleanup: %v", err)
	} else {
		log.Printf("Deleted %d seeded templates during cleanup.", deleteResult.DeletedCount)
	}

	// Delete seeded test location 'Nightcaps'
	locColl := db.Collection("locations")
	if delRes, delErr := locColl.DeleteMany(ctx, bson.M{"name": "Nightcaps"}); delErr != nil {
		log.Printf("Failed to delete seeded test location 'Nightcaps': %v", delErr)
	} else {
		log.Printf("Deleted %d seeded test locations during cleanup.", delRes.DeletedCount)
	}

	log.Println("Finished cleaning up seeded data.")
}

// --- Service API Helper ---

// callServiceAPI makes a request to the Service API.
func callServiceAPI(t *testing.T, method string, args []interface{}) (map[string]interface{}, *http.Response, error) {
	t.Helper()
	payload := map[string]interface{}{
		"method":    method,
		"arguments": args,
	}
	bodyBytes, err := json.Marshal(payload)
	require.NoError(t, err, "Failed to marshal service API payload")

	req, err := http.NewRequest("POST", testServiceApiURL+"/api", bytes.NewReader(bodyBytes))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)

	var respBodyBytes []byte
	if resp != nil && resp.Body != nil {
		respBodyBytes, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
	}

	if err != nil {
		return nil, resp, err
	}

	var respBody map[string]interface{}
	unmarshalErr := json.Unmarshal(respBodyBytes, &respBody)
	if unmarshalErr != nil {
		log.Printf("Failed to unmarshal service API response: %v. Body: %s", unmarshalErr, string(respBodyBytes))
		respBody = map[string]interface{}{"raw_body": string(respBodyBytes)}
	}

	return respBody, resp, nil
}

// --- Refactored Helpers ---

// getEmailFromServiceAPI polls the service API to retrieve mock email data.
func getEmailFromServiceAPI(t *testing.T, actionType models.LinkedActionType, emailAddr string) map[string]interface{} {
	t.Helper()
	var emailData map[string]interface{}
	found := false
	pollTimeout := time.After(10 * time.Second)
	pollTicker := time.NewTicker(500 * time.Millisecond)
	defer pollTicker.Stop()

	log.Printf("Polling Service API for email: Type=%s, Email=%s", actionType, emailAddr)

	for !found {
		select {
		case <-pollTimeout:
			t.Fatalf("Timeout waiting for email via Service API (Type: %s, Email: %s)", actionType, emailAddr)
		case <-pollTicker.C:
			respBody, resp, err := callServiceAPI(t, "getTestEmail", []interface{}{string(actionType), emailAddr})
			if err != nil {
				log.Printf("Error calling getTestEmail Service API: %v", err)
				continue
			}
			if resp.StatusCode == http.StatusOK {
				success, _ := respBody["success"].(bool)
				if success {
					// Service API (mock email endpoint) now also uses "data"
					actualEmailPayload, ok := respBody["data"].(map[string]interface{}) // Changed back to "data"
					if ok {
						log.Printf("Found email via Service API: %+v", actualEmailPayload)
						emailData = actualEmailPayload
						found = true
					} else {
						log.Printf("Service API returned success but 'data' field was not a map[string]interface{}: %+v", respBody["data"]) // Changed back to "data"
					}
				} else {
					log.Printf("getTestEmail unsuccessful (Code: %d): %s. Polling...", resp.StatusCode, respBody["error"])
				}
			} else if resp.StatusCode != http.StatusNotFound {
				log.Printf("getTestEmail returned status %d. Polling...", resp.StatusCode)
			}
		}
	}
	require.True(t, found, "Failed to find email via Service API")
	return emailData
}

// extractActionIDFromEmailBody parses the email body for the action ID.
func extractActionIDFromEmailBody(t *testing.T, emailData map[string]interface{}, linkRegexPattern string) string {
	t.Helper()
	bodyStr, ok := emailData["body"].(string)
	require.True(t, ok, "Email body not found or not a string in fetched data: %+v", emailData)

	re := regexp.MustCompile(linkRegexPattern)
	matches := re.FindStringSubmatch(bodyStr)
	require.Lenf(t, matches, 2, "Could not find action link matching %s in email body. Body:\n%s", linkRegexPattern, bodyStr)
	actionID := matches[1]
	log.Printf("Extracted Action ID: %s (Crockford Base32)", actionID)
	return actionID
}
