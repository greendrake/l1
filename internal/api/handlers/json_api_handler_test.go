package handlers_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/hibiken/asynq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.mongodb.org/mongo-driver/mongo"
	"greendrake/l1/internal/utils"

	"greendrake/l1/internal/api/handlers"
	"greendrake/l1/internal/auth"
	"greendrake/l1/internal/config"
	"greendrake/l1/internal/models"
	"greendrake/l1/internal/services"
	"greendrake/l1/internal/storage"
	"greendrake/l1/internal/tasks"
)

// --- Mocks Removed (Now in mocks_test.go) ---

// --- Test Setup ---

func setupTestRouter(userService services.IUserService, linkedActionService services.ILinkedActionService, listingService services.IListingService, storageService storage.IS3Storage, enquiryService services.IEnquiryService, userValidationService services.IUserValidationService, emailTemplateService services.IEmailTemplateService, taskClient handlers.IAsynqClient, billingService services.IBillingService) (*gin.Engine, *config.Config) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{
		JwtSecret:       "testsecret",
		JwtTTL:          time.Hour,
		LoginToSetupTTL: 24 * time.Hour,
		AppName:         "TestApp",
	}
	handler := handlers.NewJsonApiHandler(cfg, nil, nil, taskClient, userService, linkedActionService, listingService, storageService, enquiryService, userValidationService, billingService)
	r := gin.New()
	r.POST("/v1/api", handler.HandleRequest)
	return r, cfg
}

// --- Tests ---

func TestJsonApiHandler_Ping(t *testing.T) {
	mockUserSvc := new(MockUserService)
	mockLinkedActionSvc := new(MockLinkedActionService)
	mockListingSvc := new(MockListingService)
	mockStorageSvc := new(MockS3Storage)
	mockEnquirySvc := new(MockEnquiryService)
	mockValidationSvc := new(MockUserValidationService)
	mockEmailTemplateSvc := new(MockEmailTemplateService)
	mockTaskClient := new(MockAsynqClient)
	router, _ := setupTestRouter(mockUserSvc, mockLinkedActionSvc, mockListingSvc, mockStorageSvc, mockEnquirySvc, mockValidationSvc, mockEmailTemplateSvc, mockTaskClient, nil)

	reqBody := handlers.JsonApiRequest{Method: "ping"}
	jsonBody, _ := json.Marshal(reqBody)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/v1/api", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	var resp handlers.JsonApiResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.True(t, resp.Success)
	assert.Equal(t, "pong", resp.Data)
	assert.Empty(t, resp.Error)
}

func TestJsonApiHandler_SignInOrUp_NewUser(t *testing.T) {
	mockUserSvc := new(MockUserService)
	mockLinkedActionSvc := new(MockLinkedActionService)
	mockListingSvc := new(MockListingService)
	mockStorageSvc := new(MockS3Storage)
	mockEnquirySvc := new(MockEnquiryService)
	mockValidationSvc := new(MockUserValidationService)
	mockEmailTemplateSvc := new(MockEmailTemplateService)
	mockTaskClient := new(MockAsynqClient)
	router, _ := setupTestRouter(mockUserSvc, mockLinkedActionSvc, mockListingSvc, mockStorageSvc, mockEnquirySvc, mockValidationSvc, mockEmailTemplateSvc, mockTaskClient, nil)
	newEmail := "test@example.com"
	newUserID := utils.NewSixID()
	mockUserSvc.On("FindByEmail", mock.Anything, newEmail).Return(nil, mongo.ErrNoDocuments)
	mockUserSvc.On("CreatePhantomUser", mock.Anything, newEmail).Return(&models.User{ID: newUserID, Email: newEmail}, nil)
	mockLinkedActionSvc.On("CreateLoginToSetupAction", mock.Anything, newUserID).Return(&models.LinkedAction{ID: utils.SixID{}, UserID: newUserID, Type: models.ActionLoginToSetupAccount}, nil)
	mockTaskClient.On("EnqueueContext", mock.Anything, mock.MatchedBy(func(task *asynq.Task) bool {
		if task.Type() != tasks.TypeEmailDelivery {
			return false
		}
		var p tasks.EmailTaskPayload
		e := json.Unmarshal(task.Payload(), &p)
		return e == nil && p.To == newEmail && p.TemplateID == "activate_account" // Now using Crockford Base32 for action_id
	}), mock.Anything).Return(&asynq.TaskInfo{}, nil)
	argsJSON := fmt.Sprintf(`["%s"]`, newEmail)
	reqBody := handlers.JsonApiRequest{Method: "signInOrUp", Arguments: json.RawMessage(argsJSON)}
	jsonBody, _ := json.Marshal(reqBody)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/v1/api", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code, "Response code should be OK")
	var resp handlers.JsonApiResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err, "Should unmarshal response")
	assert.True(t, resp.Success, "Success should be true")
	assert.Equal(t, "created", resp.Data, "Result should be 'created'")
	assert.Empty(t, resp.Error, "Error should be empty")
	mockUserSvc.AssertExpectations(t)
	mockLinkedActionSvc.AssertExpectations(t)
	mockTaskClient.AssertExpectations(t)
}

func TestJsonApiHandler_Login_Success_PasswordOnly(t *testing.T) {
	mockUserSvc := new(MockUserService)
	mockLinkedActionSvc := new(MockLinkedActionService)
	mockListingSvc := new(MockListingService)
	mockStorageSvc := new(MockS3Storage)
	mockEnquirySvc := new(MockEnquiryService)
	mockValidationSvc := new(MockUserValidationService)
	mockEmailTemplateSvc := new(MockEmailTemplateService)
	mockTaskClient := new(MockAsynqClient)
	router, cfg := setupTestRouter(mockUserSvc, mockLinkedActionSvc, mockListingSvc, mockStorageSvc, mockEnquirySvc, mockValidationSvc, mockEmailTemplateSvc, mockTaskClient, nil)
	userEmail := "test@example.com"
	userPassword := "password123"
	userID := utils.NewSixID()
	hashedPassword, _ := auth.HashPassword(userPassword)
	mockUserSvc.On("FindByEmail", mock.Anything, userEmail).Return(&models.User{ID: userID, Email: userEmail, Activated: true, Suspended: false, PasswordHash: hashedPassword, AuthType: models.AuthTypePasswordOnly}, nil)
	loginArgsStruct := handlers.LoginArgs{Email: userEmail, ChallengeType: "password", Secret: userPassword}
	argsContainer := []interface{}{loginArgsStruct}
	argsBytes, _ := json.Marshal(argsContainer)
	reqBody := handlers.JsonApiRequest{Method: "login", Arguments: json.RawMessage(argsBytes)}
	jsonBody, _ := json.Marshal(reqBody)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/v1/api", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	var resp handlers.JsonApiResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.True(t, resp.Success)
	assert.NotEmpty(t, resp.Data, "Auth response should be returned")

	// Check that Data is a map with the expected fields
	authData, ok := resp.Data.(map[string]interface{})
	assert.True(t, ok, "Response data should be a map")
	assert.NotEmpty(t, authData["token"], "JWT token should be present")
	assert.Equal(t, userEmail, authData["email"], "Email should match")
	assert.Equal(t, userID.String(), authData["id"], "User ID should match")

	tokenString := authData["token"].(string)
	claims, jwtErr := auth.ValidateJWT(tokenString, cfg.JwtSecret)
	assert.NoError(t, jwtErr)
	assert.Equal(t, userID.String(), claims.UserID)
	mockUserSvc.AssertExpectations(t)
	mockLinkedActionSvc.AssertNotCalled(t, "FindAndValidateAction")
}

func TestJsonApiHandler_Login_Fail_WrongPassword(t *testing.T) {
	mockUserSvc := new(MockUserService)
	mockLinkedActionSvc := new(MockLinkedActionService)
	mockListingSvc := new(MockListingService)
	mockStorageSvc := new(MockS3Storage)
	mockEnquirySvc := new(MockEnquiryService)
	mockValidationSvc := new(MockUserValidationService)
	mockEmailTemplateSvc := new(MockEmailTemplateService)
	mockTaskClient := new(MockAsynqClient)
	router, _ := setupTestRouter(mockUserSvc, mockLinkedActionSvc, mockListingSvc, mockStorageSvc, mockEnquirySvc, mockValidationSvc, mockEmailTemplateSvc, mockTaskClient, nil)

	userEmail := "test@example.com"
	correctPassword := "password123"
	wrongPassword := "wrongpass"
	userID := utils.NewSixID()
	hashedPassword, _ := auth.HashPassword(correctPassword)
	mockUserSvc.On("FindByEmail", mock.Anything, userEmail).Return(&models.User{ID: userID, Email: userEmail, Activated: true, Suspended: false, PasswordHash: hashedPassword, AuthType: models.AuthTypePasswordOnly}, nil)

	loginArgsStruct := handlers.LoginArgs{Email: userEmail, ChallengeType: "password", Secret: wrongPassword}
	argsContainer := []interface{}{loginArgsStruct}
	argsBytes, _ := json.Marshal(argsContainer)

	reqBody := handlers.JsonApiRequest{Method: "login", Arguments: json.RawMessage(argsBytes)}
	jsonBody, _ := json.Marshal(reqBody)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/v1/api", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp handlers.JsonApiResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.True(t, resp.Success)
	assert.Equal(t, false, resp.Data)
	assert.Empty(t, resp.Error)
	mockUserSvc.AssertExpectations(t)
}

func TestJsonApiHandler_Login_Fail_UserNotFound(t *testing.T) {
	mockUserSvc := new(MockUserService)
	mockLinkedActionSvc := new(MockLinkedActionService)
	mockListingSvc := new(MockListingService)
	mockStorageSvc := new(MockS3Storage)
	mockEnquirySvc := new(MockEnquiryService)
	mockValidationSvc := new(MockUserValidationService)
	mockEmailTemplateSvc := new(MockEmailTemplateService)
	mockTaskClient := new(MockAsynqClient)
	router, _ := setupTestRouter(mockUserSvc, mockLinkedActionSvc, mockListingSvc, mockStorageSvc, mockEnquirySvc, mockValidationSvc, mockEmailTemplateSvc, mockTaskClient, nil)

	userEmail := "notfound@example.com"
	mockUserSvc.On("FindByEmail", mock.Anything, userEmail).Return(nil, mongo.ErrNoDocuments)

	loginArgsStruct := handlers.LoginArgs{Email: userEmail, ChallengeType: "password", Secret: "anypassword"}
	argsContainer := []interface{}{loginArgsStruct}
	argsBytes, _ := json.Marshal(argsContainer)
	reqBody := handlers.JsonApiRequest{Method: "login", Arguments: json.RawMessage(argsBytes)}
	jsonBody, _ := json.Marshal(reqBody)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/v1/api", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp handlers.JsonApiResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.True(t, resp.Success)
	assert.Equal(t, false, resp.Data)
	assert.Empty(t, resp.Error)
	mockUserSvc.AssertExpectations(t)
}

func TestJsonApiHandler_SignIn_UserNotFound(t *testing.T) {
	mockUserSvc := new(MockUserService)
	mockLinkedActionSvc := new(MockLinkedActionService)
	mockListingSvc := new(MockListingService)
	mockStorageSvc := new(MockS3Storage)
	mockEnquirySvc := new(MockEnquiryService)
	mockValidationSvc := new(MockUserValidationService)
	mockEmailTemplateSvc := new(MockEmailTemplateService)
	mockTaskClient := new(MockAsynqClient)
	router, _ := setupTestRouter(mockUserSvc, mockLinkedActionSvc, mockListingSvc, mockStorageSvc, mockEnquirySvc, mockValidationSvc, mockEmailTemplateSvc, mockTaskClient, nil)
	userEmail := "notfound@example.com"
	mockUserSvc.On("FindByEmail", mock.Anything, userEmail).Return(nil, mongo.ErrNoDocuments)
	argsJSON := fmt.Sprintf(`["%s"]`, userEmail)
	reqBody := handlers.JsonApiRequest{Method: "signIn", Arguments: json.RawMessage(argsJSON)}
	jsonBody, _ := json.Marshal(reqBody)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/v1/api", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	var resp handlers.JsonApiResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.True(t, resp.Success)
	assert.Equal(t, "email_login_code_only", resp.Data)
	assert.Empty(t, resp.Error)
	mockUserSvc.AssertExpectations(t)
}

func TestJsonApiHandler_SignIn_ActivatedUser_Password(t *testing.T) {
	mockUserSvc := new(MockUserService)
	mockLinkedActionSvc := new(MockLinkedActionService)
	mockListingSvc := new(MockListingService)
	mockStorageSvc := new(MockS3Storage)
	mockEnquirySvc := new(MockEnquiryService)
	mockValidationSvc := new(MockUserValidationService)
	mockEmailTemplateSvc := new(MockEmailTemplateService)
	mockTaskClient := new(MockAsynqClient)
	router, _ := setupTestRouter(mockUserSvc, mockLinkedActionSvc, mockListingSvc, mockStorageSvc, mockEnquirySvc, mockValidationSvc, mockEmailTemplateSvc, mockTaskClient, nil)
	userEmail := "activated@example.com"
	userID := utils.NewSixID()
	mockUserSvc.On("FindByEmail", mock.Anything, userEmail).Return(&models.User{ID: userID, Email: userEmail, Activated: true, AuthType: models.AuthTypePasswordOnly}, nil)
	argsJSON := fmt.Sprintf(`["%s"]`, userEmail)
	reqBody := handlers.JsonApiRequest{Method: "signIn", Arguments: json.RawMessage(argsJSON)}
	jsonBody, _ := json.Marshal(reqBody)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/v1/api", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	var resp handlers.JsonApiResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.True(t, resp.Success)
	assert.Equal(t, "password", resp.Data)
	assert.Empty(t, resp.Error)
	mockUserSvc.AssertExpectations(t)
}

func TestJsonApiHandler_SignIn_UnactivatedUser(t *testing.T) {
	mockUserSvc := new(MockUserService)
	mockLinkedActionSvc := new(MockLinkedActionService)
	mockListingSvc := new(MockListingService)
	mockStorageSvc := new(MockS3Storage)
	mockEnquirySvc := new(MockEnquiryService)
	mockValidationSvc := new(MockUserValidationService)
	mockEmailTemplateSvc := new(MockEmailTemplateService)
	mockTaskClient := new(MockAsynqClient)
	router, _ := setupTestRouter(mockUserSvc, mockLinkedActionSvc, mockListingSvc, mockStorageSvc, mockEnquirySvc, mockValidationSvc, mockEmailTemplateSvc, mockTaskClient, nil)
	userEmail := "unactivated@example.com"
	userID := utils.NewSixID()
	mockUserSvc.On("FindByEmail", mock.Anything, userEmail).Return(&models.User{ID: userID, Email: userEmail, Activated: false}, nil)
	argsJSON := fmt.Sprintf(`["%s"]`, userEmail)
	reqBody := handlers.JsonApiRequest{Method: "signIn", Arguments: json.RawMessage(argsJSON)}
	jsonBody, _ := json.Marshal(reqBody)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/v1/api", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	var resp handlers.JsonApiResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.True(t, resp.Success)
	assert.Equal(t, "see_email", resp.Data)
	assert.Empty(t, resp.Error)
	mockUserSvc.AssertExpectations(t)
}

func TestJsonApiHandler_ResetAccess_Success(t *testing.T) {
	mockUserSvc := new(MockUserService)
	mockLinkedActionSvc := new(MockLinkedActionService)
	mockListingSvc := new(MockListingService)
	mockStorageSvc := new(MockS3Storage)
	mockEnquirySvc := new(MockEnquiryService)
	mockValidationSvc := new(MockUserValidationService)
	mockEmailTemplateSvc := new(MockEmailTemplateService)
	mockTaskClient := new(MockAsynqClient)
	router, _ := setupTestRouter(mockUserSvc, mockLinkedActionSvc, mockListingSvc, mockStorageSvc, mockEnquirySvc, mockValidationSvc, mockEmailTemplateSvc, mockTaskClient, nil)
	userEmail := "activated@example.com"
	userID := utils.NewSixID()
	mockUserSvc.On("FindByEmail", mock.Anything, userEmail).Return(&models.User{ID: userID, Email: userEmail, Activated: true}, nil)
	mockLinkedActionSvc.On("CreateResetAccessAction", mock.Anything, userID).Return(&models.LinkedAction{ID: utils.SixID{}, UserID: userID}, nil)
	mockTaskClient.On("EnqueueContext", mock.Anything, mock.AnythingOfType("*asynq.Task"), mock.Anything).Return(&asynq.TaskInfo{}, nil).Run(func(args mock.Arguments) { /* ... */ })
	argsJSON := fmt.Sprintf(`["%s"]`, userEmail)
	reqBody := handlers.JsonApiRequest{Method: "resetAccess", Arguments: json.RawMessage(argsJSON)}
	jsonBody, _ := json.Marshal(reqBody)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/v1/api", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	var resp handlers.JsonApiResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.True(t, resp.Success)
	assert.Nil(t, resp.Data)
	assert.Empty(t, resp.Error)
	mockUserSvc.AssertExpectations(t)
	mockLinkedActionSvc.AssertExpectations(t)
	mockTaskClient.AssertExpectations(t)
}

func TestJsonApiHandler_ResetAccess_UserNotFoundOrNotActivated(t *testing.T) {
	mockUserSvc := new(MockUserService)
	mockLinkedActionSvc := new(MockLinkedActionService)
	mockListingSvc := new(MockListingService)
	mockStorageSvc := new(MockS3Storage)
	mockEnquirySvc := new(MockEnquiryService)
	mockValidationSvc := new(MockUserValidationService)
	mockEmailTemplateSvc := new(MockEmailTemplateService)
	mockTaskClient := new(MockAsynqClient)
	router, _ := setupTestRouter(mockUserSvc, mockLinkedActionSvc, mockListingSvc, mockStorageSvc, mockEnquirySvc, mockValidationSvc, mockEmailTemplateSvc, mockTaskClient, nil)
	userEmail := "notfound@example.com"
	mockUserSvc.On("FindByEmail", mock.Anything, userEmail).Return(nil, mongo.ErrNoDocuments)
	argsJSON := fmt.Sprintf(`["%s"]`, userEmail)
	reqBody := handlers.JsonApiRequest{Method: "resetAccess", Arguments: json.RawMessage(argsJSON)}
	jsonBody, _ := json.Marshal(reqBody)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/v1/api", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	var resp handlers.JsonApiResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.True(t, resp.Success)
	assert.Nil(t, resp.Data)
	assert.Empty(t, resp.Error)
	mockUserSvc.AssertExpectations(t)
	mockLinkedActionSvc.AssertNotCalled(t, "CreateResetAccessAction")
	mockTaskClient.AssertNotCalled(t, "EnqueueContext")
}

func TestJsonApiHandler_RefreshToken_Success(t *testing.T) {
	mockUserSvc := new(MockUserService)
	mockLinkedActionSvc := new(MockLinkedActionService)
	mockListingSvc := new(MockListingService)
	mockStorageSvc := new(MockS3Storage)
	mockEnquirySvc := new(MockEnquiryService)
	mockValidationSvc := new(MockUserValidationService)
	mockEmailTemplateSvc := new(MockEmailTemplateService)
	mockTaskClient := new(MockAsynqClient)
	router, cfg := setupTestRouter(mockUserSvc, mockLinkedActionSvc, mockListingSvc, mockStorageSvc, mockEnquirySvc, mockValidationSvc, mockEmailTemplateSvc, mockTaskClient, nil)
	userID := utils.NewSixID()
	isAdmin := false
	initialToken, err := auth.GenerateJWT(userID, isAdmin, cfg.JwtSecret, cfg.JwtTTL)
	assert.NoError(t, err)
	initialClaims, err := auth.ValidateJWT(initialToken, cfg.JwtSecret)
	assert.NoError(t, err)
	time.Sleep(1 * time.Second)
	reqBody := handlers.JsonApiRequest{Method: "refreshToken"}
	jsonBody, _ := json.Marshal(reqBody)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/v1/api", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+initialToken)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	var resp handlers.JsonApiResponse
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.True(t, resp.Success)
	assert.NotEmpty(t, resp.Data, "New JWT token should be returned")
	assert.IsType(t, "", resp.Data)
	assert.Empty(t, resp.Error)
	newTokenString := resp.Data.(string)
	newClaims, newJwtErr := auth.ValidateJWT(newTokenString, cfg.JwtSecret)
	assert.NoError(t, newJwtErr)
	assert.Equal(t, userID.String(), newClaims.UserID)
	assert.Equal(t, isAdmin, newClaims.IsAdmin)
	assert.True(t, newClaims.ExpiresAt.Time.After(initialClaims.ExpiresAt.Time), "New token expiration should be after initial token expiration")
}

func TestJsonApiHandler_RefreshToken_NoAuthHeader(t *testing.T) {
	mockUserSvc := new(MockUserService)
	mockLinkedActionSvc := new(MockLinkedActionService)
	mockListingSvc := new(MockListingService)
	mockStorageSvc := new(MockS3Storage)
	mockEnquirySvc := new(MockEnquiryService)
	mockValidationSvc := new(MockUserValidationService)
	mockEmailTemplateSvc := new(MockEmailTemplateService)
	mockTaskClient := new(MockAsynqClient)
	router, _ := setupTestRouter(mockUserSvc, mockLinkedActionSvc, mockListingSvc, mockStorageSvc, mockEnquirySvc, mockValidationSvc, mockEmailTemplateSvc, mockTaskClient, nil)

	reqBody := handlers.JsonApiRequest{Method: "refreshToken"}
	jsonBody, _ := json.Marshal(reqBody)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/v1/api", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	// No Authorization header

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp handlers.JsonApiResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.False(t, resp.Success)
	assert.Equal(t, "Authorization header required", resp.Error)
	assert.Nil(t, resp.Data)
}

func TestJsonApiHandler_RefreshToken_InvalidToken(t *testing.T) {
	mockUserSvc := new(MockUserService)
	mockLinkedActionSvc := new(MockLinkedActionService)
	mockListingSvc := new(MockListingService)
	mockStorageSvc := new(MockS3Storage)
	mockEnquirySvc := new(MockEnquiryService)
	mockValidationSvc := new(MockUserValidationService)
	mockEmailTemplateSvc := new(MockEmailTemplateService)
	mockTaskClient := new(MockAsynqClient)
	router, _ := setupTestRouter(mockUserSvc, mockLinkedActionSvc, mockListingSvc, mockStorageSvc, mockEnquirySvc, mockValidationSvc, mockEmailTemplateSvc, mockTaskClient, nil)

	reqBody := handlers.JsonApiRequest{Method: "refreshToken"}
	jsonBody, _ := json.Marshal(reqBody)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/v1/api", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer invalidtoken")

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp handlers.JsonApiResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.False(t, resp.Success)
	assert.Contains(t, resp.Error, "Invalid or expired token", "Error message should indicate invalid token")
	assert.Nil(t, resp.Data)
}

func TestJsonApiHandler_CreateListing_Success(t *testing.T) {
	mockUserSvc := new(MockUserService)
	mockLinkedActionSvc := new(MockLinkedActionService)
	mockListingSvc := new(MockListingService)
	mockStorageSvc := new(MockS3Storage)
	mockEnquirySvc := new(MockEnquiryService)
	mockValidationSvc := new(MockUserValidationService)
	mockEmailTemplateSvc := new(MockEmailTemplateService)
	mockTaskClient := new(MockAsynqClient)
	router, cfg := setupTestRouter(mockUserSvc, mockLinkedActionSvc, mockListingSvc, mockStorageSvc, mockEnquirySvc, mockValidationSvc, mockEmailTemplateSvc, mockTaskClient, nil)
	userID := utils.NewSixID()
	locationID := 1
	listingID := utils.NewSixID()
	isAdmin := false
	token, _ := auth.GenerateJWT(userID, isAdmin, cfg.JwtSecret, cfg.JwtTTL)
	createArgsStruct := handlers.CreateListingArgs{Title: "Test Listing", Body: "Test Body", Tags: []string{"test", "go"}, LocationID: locationID, CountryCode: "US", Shipping: "pickup_only", AskingPrice: &models.AskingPrice{Value: 10.99, CurrencyCode: "USD"}}
	expectedListing := &models.Listing{ID: listingID, UserID: userID, Title: createArgsStruct.Title, Body: createArgsStruct.Body, Tags: createArgsStruct.Tags, LocationID: locationID, CountryCode: createArgsStruct.CountryCode, Shipping: createArgsStruct.Shipping, AskingPrice: createArgsStruct.AskingPrice, IsDraft: true}
	mockListingSvc.On("CreateListing", mock.Anything, userID, createArgsStruct.Title, createArgsStruct.Body, createArgsStruct.Tags, locationID, createArgsStruct.CountryCode, createArgsStruct.Shipping, createArgsStruct.AskingPrice).Return(expectedListing, nil)
	argsContainer := []interface{}{createArgsStruct}
	argsBytes, _ := json.Marshal(argsContainer)
	reqBody := handlers.JsonApiRequest{Method: "createListing", Arguments: json.RawMessage(argsBytes)}
	jsonBody, _ := json.Marshal(reqBody)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/v1/api", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	var resp handlers.JsonApiResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.True(t, resp.Success)
	assert.NotEmpty(t, resp.Data)
	assert.Empty(t, resp.Error)
	resultMap, ok := resp.Data.(map[string]interface{})
	assert.True(t, ok)
	assert.Equal(t, listingID.String(), resultMap["id"])
	assert.Equal(t, userID.String(), resultMap["user_id"])
	assert.Equal(t, createArgsStruct.Title, resultMap["title"])
	assert.True(t, resultMap["is_draft"].(bool))
	mockListingSvc.AssertExpectations(t)
}

func TestJsonApiHandler_UpdateListing_Success(t *testing.T) {
	mockUserSvc := new(MockUserService)
	mockLinkedActionSvc := new(MockLinkedActionService)
	mockListingSvc := new(MockListingService)
	mockStorageSvc := new(MockS3Storage)
	mockEnquirySvc := new(MockEnquiryService)
	mockValidationSvc := new(MockUserValidationService)
	mockEmailTemplateSvc := new(MockEmailTemplateService)
	mockTaskClient := new(MockAsynqClient)
	router, cfg := setupTestRouter(mockUserSvc, mockLinkedActionSvc, mockListingSvc, mockStorageSvc, mockEnquirySvc, mockValidationSvc, mockEmailTemplateSvc, mockTaskClient, nil)
	userID := utils.NewSixID()
	listingID := utils.NewSixID()
	token, _ := auth.GenerateJWT(userID, false, cfg.JwtSecret, cfg.JwtTTL)
	updates := map[string]interface{}{"title": "Updated Title", "body": "Updated Body"}
	expectedListing := &models.Listing{ID: listingID, UserID: userID, Title: "Updated Title", Body: "Updated Body"}
	mockListingSvc.On("UpdateListing", mock.Anything, listingID, userID, updates).Return(expectedListing, nil)
	updateArgsStruct := handlers.UpdateListingArgs{ListingID: listingID.String(), Updates: updates}
	argsContainer := []interface{}{updateArgsStruct}
	argsBytes, _ := json.Marshal(argsContainer)
	reqBody := handlers.JsonApiRequest{Method: "updateListing", Arguments: json.RawMessage(argsBytes)}
	jsonBody, _ := json.Marshal(reqBody)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/v1/api", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	var resp handlers.JsonApiResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.True(t, resp.Success)
	assert.NotEmpty(t, resp.Data)
	resultMap, ok := resp.Data.(map[string]interface{})
	assert.True(t, ok)
	assert.Equal(t, "Updated Title", resultMap["title"])
	mockListingSvc.AssertExpectations(t)
}

func TestJsonApiHandler_PublishListing_Success(t *testing.T) {
	mockUserSvc := new(MockUserService)
	mockLinkedActionSvc := new(MockLinkedActionService)
	mockListingSvc := new(MockListingService)
	mockStorageSvc := new(MockS3Storage)
	mockEnquirySvc := new(MockEnquiryService)
	mockValidationSvc := new(MockUserValidationService)
	mockEmailTemplateSvc := new(MockEmailTemplateService)
	mockTaskClient := new(MockAsynqClient)
	router, cfg := setupTestRouter(mockUserSvc, mockLinkedActionSvc, mockListingSvc, mockStorageSvc, mockEnquirySvc, mockValidationSvc, mockEmailTemplateSvc, mockTaskClient, nil)
	userID := utils.NewSixID()
	listingID := utils.NewSixID()
	token, _ := auth.GenerateJWT(userID, false, cfg.JwtSecret, cfg.JwtTTL)
	mockListingSvc.On("PublishListing", mock.Anything, listingID, userID).Return(nil)

	// Arguments field must now be an array, with the actual argument (listingID.String()) as its first element.
	argsContainer := []interface{}{listingID.String()}
	argsBytes, _ := json.Marshal(argsContainer)

	reqBody := handlers.JsonApiRequest{Method: "publishListing", Arguments: json.RawMessage(argsBytes)}
	jsonBody, _ := json.Marshal(reqBody)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/v1/api", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	var resp handlers.JsonApiResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.True(t, resp.Success)
	assert.Nil(t, resp.Data)
	assert.Empty(t, resp.Error)
	mockListingSvc.AssertExpectations(t)
}

// Helper for testing Hide/Unhide/Delete
func testListingStatusChange(t *testing.T, method string, mockSetup func(*MockListingService, utils.SixID, utils.SixID)) {
	mockUserSvc := new(MockUserService)
	mockLinkedActionSvc := new(MockLinkedActionService)
	mockListingSvc := new(MockListingService)
	mockStorageSvc := new(MockS3Storage)
	mockEnquirySvc := new(MockEnquiryService)
	mockValidationSvc := new(MockUserValidationService)
	mockEmailTemplateSvc := new(MockEmailTemplateService)
	mockTaskClient := new(MockAsynqClient)
	router, cfg := setupTestRouter(mockUserSvc, mockLinkedActionSvc, mockListingSvc, mockStorageSvc, mockEnquirySvc, mockValidationSvc, mockEmailTemplateSvc, mockTaskClient, nil)
	userID := utils.NewSixID()
	listingID := utils.NewSixID()
	token, _ := auth.GenerateJWT(userID, false, cfg.JwtSecret, cfg.JwtTTL)
	mockSetup(mockListingSvc, listingID, userID)
	argsContainer := []interface{}{listingID.String()}
	argsBytes, _ := json.Marshal(argsContainer)
	reqBody := handlers.JsonApiRequest{Method: method, Arguments: json.RawMessage(argsBytes)}
	jsonBody, _ := json.Marshal(reqBody)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/v1/api", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	var resp handlers.JsonApiResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.True(t, resp.Success)
	assert.Nil(t, resp.Data)
	assert.Empty(t, resp.Error)
	mockListingSvc.AssertExpectations(t)
}

func TestJsonApiHandler_HideListing_Success(t *testing.T) {
	testListingStatusChange(t, "hideListing", func(m *MockListingService, lID, uID utils.SixID) {
		m.On("HideListing", mock.Anything, lID, uID).Return(nil)
	})
}

func TestJsonApiHandler_UnhideListing_Success(t *testing.T) {
	testListingStatusChange(t, "unhideListing", func(m *MockListingService, lID, uID utils.SixID) {
		m.On("UnhideListing", mock.Anything, lID, uID).Return(nil)
	})
}

func TestJsonApiHandler_DeleteListing_Success(t *testing.T) {
	testListingStatusChange(t, "deleteListing", func(m *MockListingService, lID, uID utils.SixID) {
		m.On("DeleteListing", mock.Anything, lID, uID).Return(nil)
	})
}

func TestJsonApiHandler_GetUploadURL_Success(t *testing.T) {
	mockUserSvc := new(MockUserService)
	mockLinkedActionSvc := new(MockLinkedActionService)
	mockListingSvc := new(MockListingService)
	mockStorageSvc := new(MockS3Storage)
	mockEnquirySvc := new(MockEnquiryService)
	mockValidationSvc := new(MockUserValidationService)
	mockEmailTemplateSvc := new(MockEmailTemplateService)
	mockTaskClient := new(MockAsynqClient)
	router, cfg := setupTestRouter(mockUserSvc, mockLinkedActionSvc, mockListingSvc, mockStorageSvc, mockEnquirySvc, mockValidationSvc, mockEmailTemplateSvc, mockTaskClient, nil)
	userID := utils.NewSixID()
	listingID := utils.NewSixID()
	token, _ := auth.GenerateJWT(userID, false, cfg.JwtSecret, cfg.JwtTTL)
	filename := "test_image.jpg"
	contentType := "image/jpeg"
	presignedURL := "https://example.s3.amazonaws.com/upload?sig=..."
	objectKey := fmt.Sprintf("uploads/%s/%s/%s_%s", userID.String(), listingID.String(), "some-uuid", filename)
	mockStorageSvc.On("GeneratePresignedPutURL", mock.Anything, userID.String(), listingID.String(), filename, contentType).Return(presignedURL, objectKey, nil)
	getURLArgs := handlers.GetUploadURLArgs{ListingID: listingID.String(), Filename: filename, ContentType: contentType}
	argsContainer := []interface{}{getURLArgs}
	argsBytes, _ := json.Marshal(argsContainer)
	reqBody := handlers.JsonApiRequest{Method: "getUploadURL", Arguments: json.RawMessage(argsBytes)}
	jsonBody, _ := json.Marshal(reqBody)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/v1/api", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	var resp handlers.JsonApiResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.True(t, resp.Success)
	assert.NotEmpty(t, resp.Data)
	assert.Empty(t, resp.Error)
	resultMap, ok := resp.Data.(map[string]interface{})
	assert.True(t, ok)
	assert.Equal(t, presignedURL, resultMap["upload_url"])
	assert.Equal(t, objectKey, resultMap["object_key"])
	mockStorageSvc.AssertExpectations(t)
}

func TestJsonApiHandler_ConfirmImageUpload_Success(t *testing.T) {
	mockUserSvc := new(MockUserService)
	mockLinkedActionSvc := new(MockLinkedActionService)
	mockListingSvc := new(MockListingService)
	mockStorageSvc := new(MockS3Storage)
	mockEnquirySvc := new(MockEnquiryService)
	mockValidationSvc := new(MockUserValidationService)
	mockEmailTemplateSvc := new(MockEmailTemplateService)
	mockTaskClient := new(MockAsynqClient)
	router, cfg := setupTestRouter(mockUserSvc, mockLinkedActionSvc, mockListingSvc, mockStorageSvc, mockEnquirySvc, mockValidationSvc, mockEmailTemplateSvc, mockTaskClient, nil)
	userID := utils.NewSixID()
	listingID := utils.NewSixID()
	token, _ := auth.GenerateJWT(userID, false, cfg.JwtSecret, cfg.JwtTTL)
	objectKey := "uploads/some/key.jpg"
	taskID := "task-" + uuid.NewString()
	mockTaskClient.On("EnqueueContext", mock.Anything, mock.MatchedBy(func(task *asynq.Task) bool {
		if task.Type() != tasks.TypeImageProcess {
			return false
		}
		var payload tasks.ImageTaskPayload
		err := json.Unmarshal(task.Payload(), &payload)
		return err == nil && payload.ListingID == listingID.String() && payload.S3Key == objectKey
	}), mock.Anything,
	).Return(&asynq.TaskInfo{ID: taskID}, nil)
	confirmArgs := handlers.ConfirmImageUploadArgs{ListingID: listingID.String(), ObjectKey: objectKey}
	argsContainer := []interface{}{confirmArgs}
	argsBytes, _ := json.Marshal(argsContainer)
	reqBody := handlers.JsonApiRequest{Method: "confirmImageUpload", Arguments: json.RawMessage(argsBytes)}
	jsonBody, _ := json.Marshal(reqBody)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/v1/api", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	var resp handlers.JsonApiResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.True(t, resp.Success)
	assert.NotEmpty(t, resp.Data)
	assert.Empty(t, resp.Error)
	resultMap, ok := resp.Data.(map[string]interface{})
	assert.True(t, ok)
	assert.Contains(t, resultMap["message"], "processing scheduled")
	assert.Equal(t, taskID, resultMap["task_id"])
	mockTaskClient.AssertExpectations(t)
}

func TestJsonApiHandler_SendEnquiry_Guest_Success(t *testing.T) {
	mockUserSvc := new(MockUserService)
	mockLinkedActionSvc := new(MockLinkedActionService)
	mockListingSvc := new(MockListingService)
	mockStorageSvc := new(MockS3Storage)
	mockEnquirySvc := new(MockEnquiryService)
	mockValidationSvc := new(MockUserValidationService)
	mockEmailTemplateSvc := new(MockEmailTemplateService)
	mockTaskClient := new(MockAsynqClient)
	router, _ := setupTestRouter(mockUserSvc, mockLinkedActionSvc, mockListingSvc, mockStorageSvc, mockEnquirySvc, mockValidationSvc, mockEmailTemplateSvc, mockTaskClient, nil)
	listingID := utils.NewSixID()
	ownerID := utils.NewSixID()
	enquiryID := utils.NewSixID()
	enquiryArgs := handlers.SendEnquiryArgs{ListingID: listingID.String(), UserEmail: "guest@example.com", Message: "Is this available?", Offer: nil}

	// Expect FindListingByID call
	mockListingSvc.On("FindListingByID", mock.Anything, listingID).Return(&models.Listing{ID: listingID, UserID: ownerID}, nil)
	// Expect CreateEnquiry call
	mockEnquirySvc.On("CreateEnquiry", mock.Anything, listingID, (*utils.SixID)(nil), enquiryArgs.UserEmail, enquiryArgs.Message, enquiryArgs.Offer).Return(&models.ListingEnquiry{ID: enquiryID}, nil)
	// Expect FindByID for owner (even for guest enquiry)
	mockUserSvc.On("FindByID", mock.Anything, ownerID).Return(&models.User{ID: ownerID, Email: "owner@example.com", NotificationPreferences: &models.NotificationPreferences{Enquiry: true, Offer: true}}, nil)
	// Expect email task enqueue
	mockTaskClient.On("EnqueueContext", mock.Anything, mock.AnythingOfType("*asynq.Task"), mock.Anything).Return(&asynq.TaskInfo{}, nil)

	argsContainer := []interface{}{enquiryArgs}
	argsBytes, _ := json.Marshal(argsContainer)
	reqBody := handlers.JsonApiRequest{Method: "sendEnquiry", Arguments: json.RawMessage(argsBytes)}
	jsonBody, _ := json.Marshal(reqBody)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/v1/api", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	var resp handlers.JsonApiResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.True(t, resp.Success)
	assert.NotEmpty(t, resp.Data)
	assert.Empty(t, resp.Error)
	resultMap, ok := resp.Data.(map[string]interface{})
	assert.True(t, ok)
	assert.Contains(t, resultMap["message"], "Enquiry sent successfully")
	mockListingSvc.AssertExpectations(t)
	mockEnquirySvc.AssertExpectations(t)
	mockUserSvc.AssertExpectations(t)
	mockTaskClient.AssertExpectations(t)
}

func TestJsonApiHandler_SendEnquiry_Authenticated_Success(t *testing.T) {
	mockUserSvc := new(MockUserService)
	mockLinkedActionSvc := new(MockLinkedActionService)
	mockListingSvc := new(MockListingService)
	mockStorageSvc := new(MockS3Storage)
	mockEnquirySvc := new(MockEnquiryService)
	mockValidationSvc := new(MockUserValidationService)
	mockEmailTemplateSvc := new(MockEmailTemplateService)
	mockTaskClient := new(MockAsynqClient)
	router, cfg := setupTestRouter(mockUserSvc, mockLinkedActionSvc, mockListingSvc, mockStorageSvc, mockEnquirySvc, mockValidationSvc, mockEmailTemplateSvc, mockTaskClient, nil)
	userID := utils.NewSixID()
	listingID := utils.NewSixID()
	ownerID := utils.NewSixID() // Different owner ID
	enquiryID := utils.NewSixID()
	token, _ := auth.GenerateJWT(userID, false, cfg.JwtSecret, cfg.JwtTTL)
	enquiryArgs := handlers.SendEnquiryArgs{ListingID: listingID.String(), UserEmail: "authuser@example.com", Message: "", Offer: &models.AskingPrice{Value: 50, CurrencyCode: "CAD"}}

	// Expect FindListingByID call
	mockListingSvc.On("FindListingByID", mock.Anything, listingID).Return(&models.Listing{ID: listingID, UserID: ownerID, Title: "Test"}, nil)
	// Expect CreateEnquiry call
	mockEnquirySvc.On("CreateEnquiry", mock.Anything, listingID, &userID, enquiryArgs.UserEmail, enquiryArgs.Message, enquiryArgs.Offer).Return(&models.ListingEnquiry{ID: enquiryID}, nil)
	// Expect FindByID for owner
	mockUserSvc.On("FindByID", mock.Anything, ownerID).Return(&models.User{ID: ownerID, Email: "owner@example.com", NotificationPreferences: &models.NotificationPreferences{Enquiry: true, Offer: true}}, nil)
	// Expect task enqueue
	mockTaskClient.On("EnqueueContext", mock.Anything, mock.AnythingOfType("*asynq.Task"), mock.Anything).Return(&asynq.TaskInfo{}, nil)

	argsContainer := []interface{}{enquiryArgs}
	argsBytes, _ := json.Marshal(argsContainer)
	reqBody := handlers.JsonApiRequest{Method: "sendEnquiry", Arguments: json.RawMessage(argsBytes)}
	jsonBody, _ := json.Marshal(reqBody)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/v1/api", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	var resp handlers.JsonApiResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.True(t, resp.Success)
	mockListingSvc.AssertExpectations(t)
	mockEnquirySvc.AssertExpectations(t)
	mockUserSvc.AssertExpectations(t)
	mockTaskClient.AssertExpectations(t)
}

func TestJsonApiHandler_ListValidationTypes_Success(t *testing.T) {
	mockUserSvc := new(MockUserService)
	mockLinkedActionSvc := new(MockLinkedActionService)
	mockListingSvc := new(MockListingService)
	mockStorageSvc := new(MockS3Storage)
	mockEnquirySvc := new(MockEnquiryService)
	mockValidationSvc := new(MockUserValidationService)
	mockEmailTemplateSvc := new(MockEmailTemplateService)
	mockTaskClient := new(MockAsynqClient)
	router, cfg := setupTestRouter(mockUserSvc, mockLinkedActionSvc, mockListingSvc, mockStorageSvc, mockEnquirySvc, mockValidationSvc, mockEmailTemplateSvc, mockTaskClient, nil)
	userID := utils.NewSixID()
	token, _ := auth.GenerateJWT(userID, false, cfg.JwtSecret, cfg.JwtTTL)
	expectedTypes := []models.UserValidationType{{ID: utils.NewSixID(), Key: "Domain Ownership", Type: models.ValidationTypeDomainOwnership}, {ID: utils.NewSixID(), Key: "Some Profile", Type: models.ValidationTypeOnlineProfile}}
	mockValidationSvc.On("GetValidationTypes", mock.Anything).Return(expectedTypes, nil)
	reqBody := handlers.JsonApiRequest{Method: "listValidationTypes"}
	jsonBody, _ := json.Marshal(reqBody)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/v1/api", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	var resp handlers.JsonApiResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.True(t, resp.Success)
	assert.NotEmpty(t, resp.Data)
	resultData, err := json.Marshal(resp.Data)
	assert.NoError(t, err)
	var resultTypes []models.UserValidationType
	err = json.Unmarshal(resultData, &resultTypes)
	assert.NoError(t, err)
	assert.Len(t, resultTypes, 2)
	assert.Equal(t, expectedTypes[0].Key, resultTypes[0].Key)
	mockValidationSvc.AssertExpectations(t)
}

func TestJsonApiHandler_StartDomainValidation_Success(t *testing.T) {
	mockUserSvc := new(MockUserService)
	mockLinkedActionSvc := new(MockLinkedActionService)
	mockListingSvc := new(MockListingService)
	mockStorageSvc := new(MockS3Storage)
	mockEnquirySvc := new(MockEnquiryService)
	mockValidationSvc := new(MockUserValidationService)
	mockEmailTemplateSvc := new(MockEmailTemplateService)
	mockTaskClient := new(MockAsynqClient)
	router, cfg := setupTestRouter(mockUserSvc, mockLinkedActionSvc, mockListingSvc, mockStorageSvc, mockEnquirySvc, mockValidationSvc, mockEmailTemplateSvc, mockTaskClient, nil)
	userID := utils.NewSixID()
	typeID := utils.NewSixID()
	validationID := utils.NewSixID()
	token, _ := auth.GenerateJWT(userID, false, cfg.JwtSecret, cfg.JwtTTL)
	domain := "example.com"
	valueToProve := fmt.Sprintf("%s:ACCOUNT_VALIDATION:%s", cfg.AppName, validationID.String())
	expectedValidation := &models.UserValidation{ID: validationID, UserID: userID, TypeID: typeID, Data: map[string]interface{}{"domain_name": domain}, ValueToProve: valueToProve}
	mockValidationSvc.On("CreateDomainValidation", mock.Anything, userID, typeID, domain).Return(expectedValidation, nil)
	startArgs := handlers.StartDomainValidationArgs{TypeID: typeID.String(), DomainName: domain}
	argsContainer := []interface{}{startArgs}
	argsBytes, _ := json.Marshal(argsContainer)
	reqBody := handlers.JsonApiRequest{Method: "startDomainValidation", Arguments: json.RawMessage(argsBytes)}
	jsonBody, _ := json.Marshal(reqBody)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/v1/api", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	var resp handlers.JsonApiResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.True(t, resp.Success)
	assert.NotEmpty(t, resp.Data)
	resultMap, ok := resp.Data.(map[string]interface{})
	assert.True(t, ok)
	assert.Equal(t, validationID.String(), resultMap["validation_id"])
	assert.Equal(t, valueToProve, resultMap["value_to_prove"])
	mockValidationSvc.AssertExpectations(t)
}

func TestJsonApiHandler_StartOnlineProfileValidation_Success(t *testing.T) {
	mockUserSvc := new(MockUserService)
	mockLinkedActionSvc := new(MockLinkedActionService)
	mockListingSvc := new(MockListingService)
	mockStorageSvc := new(MockS3Storage)
	mockEnquirySvc := new(MockEnquiryService)
	mockValidationSvc := new(MockUserValidationService)
	mockEmailTemplateSvc := new(MockEmailTemplateService)
	mockTaskClient := new(MockAsynqClient)
	router, cfg := setupTestRouter(mockUserSvc, mockLinkedActionSvc, mockListingSvc, mockStorageSvc, mockEnquirySvc, mockValidationSvc, mockEmailTemplateSvc, mockTaskClient, nil)
	userID := utils.NewSixID()
	typeID := utils.NewSixID()
	validationID := utils.NewSixID()
	token, _ := auth.GenerateJWT(userID, false, cfg.JwtSecret, cfg.JwtTTL)

	profileID := "testuser123"
	valueToProve := fmt.Sprintf("%s:ACCOUNT_VALIDATION:%s", cfg.AppName, validationID.String())
	instructions := "Put this value on your profile page."

	expectedValidation := &models.UserValidation{
		ID:             validationID,
		UserID:         userID,
		TypeID:         typeID,
		ValidationType: models.ValidationTypeOnlineProfile,
		Data:           map[string]interface{}{"profile_id": profileID},
		ValueToProve:   valueToProve,
	}
	mockValidationSvc.On("CreateOnlineProfileValidation", mock.Anything, userID, typeID, profileID).Return(expectedValidation, nil)
	mockValidationSvc.On("GetValidationTypeByID", mock.Anything, typeID).Return(&models.UserValidationType{
		ID:     typeID,
		Type:   models.ValidationTypeOnlineProfile,
		Config: map[string]interface{}{"user_instructions": instructions},
	}, nil)

	startArgs := handlers.StartOnlineProfileValidationArgs{
		TypeID:    typeID.String(),
		ProfileID: profileID,
	}
	argsContainer := []interface{}{startArgs}
	argsBytes, _ := json.Marshal(argsContainer)
	reqBody := handlers.JsonApiRequest{Method: "startOnlineProfileValidation", Arguments: json.RawMessage(argsBytes)}
	jsonBody, _ := json.Marshal(reqBody)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/v1/api", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp handlers.JsonApiResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.True(t, resp.Success)
	assert.NotEmpty(t, resp.Data)
	resultMap, ok := resp.Data.(map[string]interface{})
	assert.True(t, ok)
	assert.Equal(t, validationID.String(), resultMap["validation_id"])
	assert.Equal(t, valueToProve, resultMap["value_to_prove"])
	assert.Equal(t, instructions, resultMap["instructions"])
	mockValidationSvc.AssertExpectations(t)
}

// TODO: Add failure tests for validation methods

// --- Admin Method Tests ---

func TestJsonApiHandler_SuspendUser_Success(t *testing.T) {
	mockUserSvc := new(MockUserService)
	mockLinkedActionSvc := new(MockLinkedActionService)
	mockListingSvc := new(MockListingService)
	mockStorageSvc := new(MockS3Storage)
	mockEnquirySvc := new(MockEnquiryService)
	mockValidationSvc := new(MockUserValidationService)
	mockEmailTemplateSvc := new(MockEmailTemplateService)
	mockTaskClient := new(MockAsynqClient)
	router, cfg := setupTestRouter(mockUserSvc, mockLinkedActionSvc, mockListingSvc, mockStorageSvc, mockEnquirySvc, mockValidationSvc, mockEmailTemplateSvc, mockTaskClient, nil)

	adminUserID := utils.NewSixID()
	userToSuspendID := utils.NewSixID()
	token, _ := auth.GenerateJWT(adminUserID, true, cfg.JwtSecret, cfg.JwtTTL) // Admin token

	mockUserSvc.On("SuspendUser", mock.Anything, userToSuspendID, adminUserID).Return(nil)

	// Correctly marshal the argument as a JSON string containing the ID
	argsContainer := []interface{}{userToSuspendID.String()}
	argsBytes, _ := json.Marshal(argsContainer)
	reqBody := handlers.JsonApiRequest{Method: "suspendUser", Arguments: json.RawMessage(argsBytes)}
	jsonBody, _ := json.Marshal(reqBody)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/v1/api", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp handlers.JsonApiResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.True(t, resp.Success)
	assert.Nil(t, resp.Data)
	assert.Empty(t, resp.Error)
	mockUserSvc.AssertExpectations(t)
}

func TestJsonApiHandler_SuspendUser_Fail_NotAdmin(t *testing.T) {
	mockUserSvc := new(MockUserService)
	mockLinkedActionSvc := new(MockLinkedActionService)
	mockListingSvc := new(MockListingService)
	mockStorageSvc := new(MockS3Storage)
	mockEnquirySvc := new(MockEnquiryService)
	mockValidationSvc := new(MockUserValidationService)
	mockEmailTemplateSvc := new(MockEmailTemplateService)
	mockTaskClient := new(MockAsynqClient)
	router, cfg := setupTestRouter(mockUserSvc, mockLinkedActionSvc, mockListingSvc, mockStorageSvc, mockEnquirySvc, mockValidationSvc, mockEmailTemplateSvc, mockTaskClient, nil)

	nonAdminUserID := utils.NewSixID()
	userToSuspendID := utils.NewSixID()
	token, _ := auth.GenerateJWT(nonAdminUserID, false, cfg.JwtSecret, cfg.JwtTTL) // Non-admin token

	// No service call expected
	argsContainer := []interface{}{userToSuspendID.String()}
	argsBytes, _ := json.Marshal(argsContainer)
	reqBody := handlers.JsonApiRequest{Method: "suspendUser", Arguments: json.RawMessage(argsBytes)}
	jsonBody, _ := json.Marshal(reqBody)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/v1/api", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp handlers.JsonApiResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.False(t, resp.Success)
	assert.Contains(t, resp.Error, "Administrator privileges required")
	mockUserSvc.AssertNotCalled(t, "SuspendUser")
}

func TestJsonApiHandler_SuspendUser_Fail_SuspendSelf(t *testing.T) {
	mockUserSvc := new(MockUserService)
	mockLinkedActionSvc := new(MockLinkedActionService)
	mockListingSvc := new(MockListingService)
	mockStorageSvc := new(MockS3Storage)
	mockEnquirySvc := new(MockEnquiryService)
	mockValidationSvc := new(MockUserValidationService)
	mockEmailTemplateSvc := new(MockEmailTemplateService)
	mockTaskClient := new(MockAsynqClient)
	router, cfg := setupTestRouter(mockUserSvc, mockLinkedActionSvc, mockListingSvc, mockStorageSvc, mockEnquirySvc, mockValidationSvc, mockEmailTemplateSvc, mockTaskClient, nil)

	adminUserID := utils.NewSixID()
	token, _ := auth.GenerateJWT(adminUserID, true, cfg.JwtSecret, cfg.JwtTTL) // Admin token

	// Expect service call to fail because admin is suspending self
	mockUserSvc.On("SuspendUser", mock.Anything, adminUserID, adminUserID).Return(fmt.Errorf("admin cannot suspend themselves"))

	// Correctly marshal the argument as a JSON string containing the ID
	argsContainer := []interface{}{adminUserID.String()}
	argsBytes, _ := json.Marshal(argsContainer)
	reqBody := handlers.JsonApiRequest{Method: "suspendUser", Arguments: json.RawMessage(argsBytes)}
	jsonBody, _ := json.Marshal(reqBody)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/v1/api", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp handlers.JsonApiResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.False(t, resp.Success)
	assert.Contains(t, resp.Error, "cannot suspend themselves")
	mockUserSvc.AssertExpectations(t)
}

// TODO: Add tests for unSuspendUser

func TestJsonApiHandler_ChangePassword_Success(t *testing.T) {
	mockUserSvc := new(MockUserService)
	mockLinkedActionSvc := new(MockLinkedActionService)
	mockListingSvc := new(MockListingService)
	mockStorageSvc := new(MockS3Storage)
	mockEnquirySvc := new(MockEnquiryService)
	mockValidationSvc := new(MockUserValidationService)
	mockEmailTemplateSvc := new(MockEmailTemplateService)
	mockTaskClient := new(MockAsynqClient)
	router, _ := setupTestRouter(mockUserSvc, mockLinkedActionSvc, mockListingSvc, mockStorageSvc, mockEnquirySvc, mockValidationSvc, mockEmailTemplateSvc, mockTaskClient, nil)

	// Setup test data
	userID := utils.NewSixID()
	currentPassword := "oldpass123"
	newPassword := "newpass456"
	hashedCurrentPassword, _ := auth.HashPassword(currentPassword)

	// Mock user service expectations
	mockUserSvc.On("FindByID", mock.Anything, userID).Return(&models.User{
		ID:           userID,
		Email:        "test@example.com",
		PasswordHash: hashedCurrentPassword,
		AuthType:     models.AuthTypePasswordOnly,
	}, nil)

	mockUserSvc.On("SetUserCredentials", mock.Anything, userID, models.AuthTypePasswordOnly, newPassword).Return(nil)

	// Create request with array of passwords
	argsBytes, _ := json.Marshal([]string{currentPassword, newPassword})
	reqBody := handlers.JsonApiRequest{
		Method:    "changePassword",
		Arguments: json.RawMessage(argsBytes),
	}
	jsonBody, _ := json.Marshal(reqBody)

	// Create JWT token for authentication
	token, _ := auth.GenerateJWT(userID, false, "testsecret", 24*time.Hour)

	// Make request
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/v1/api", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)

	// Assert response
	assert.Equal(t, http.StatusOK, w.Code)
	var resp handlers.JsonApiResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.True(t, resp.Success)
	assert.Equal(t, true, resp.Data)
	assert.Empty(t, resp.Error)

	mockUserSvc.AssertExpectations(t)
}

func TestJsonApiHandler_ChangePassword_WrongCurrentPassword(t *testing.T) {
	mockUserSvc := new(MockUserService)
	mockLinkedActionSvc := new(MockLinkedActionService)
	mockListingSvc := new(MockListingService)
	mockStorageSvc := new(MockS3Storage)
	mockEnquirySvc := new(MockEnquiryService)
	mockValidationSvc := new(MockUserValidationService)
	mockEmailTemplateSvc := new(MockEmailTemplateService)
	mockTaskClient := new(MockAsynqClient)
	router, _ := setupTestRouter(mockUserSvc, mockLinkedActionSvc, mockListingSvc, mockStorageSvc, mockEnquirySvc, mockValidationSvc, mockEmailTemplateSvc, mockTaskClient, nil)

	// Setup test data
	userID := utils.NewSixID()
	currentPassword := "oldpass123"
	wrongPassword := "wrongpass"
	newPassword := "newpass456"
	hashedCurrentPassword, _ := auth.HashPassword(currentPassword)

	// Mock user service expectations
	mockUserSvc.On("FindByID", mock.Anything, userID).Return(&models.User{
		ID:           userID,
		Email:        "test@example.com",
		PasswordHash: hashedCurrentPassword,
		AuthType:     models.AuthTypePasswordOnly,
	}, nil)

	// Create request with array of passwords
	argsBytes, _ := json.Marshal([]string{wrongPassword, newPassword})
	reqBody := handlers.JsonApiRequest{
		Method:    "changePassword",
		Arguments: json.RawMessage(argsBytes),
	}
	jsonBody, _ := json.Marshal(reqBody)

	// Create JWT token for authentication
	token, _ := auth.GenerateJWT(userID, false, "testsecret", 24*time.Hour)

	// Make request
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/v1/api", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)

	// Assert response
	assert.Equal(t, http.StatusOK, w.Code)
	var resp handlers.JsonApiResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.True(t, resp.Success)
	assert.Equal(t, false, resp.Data)
	assert.Empty(t, resp.Error)

	mockUserSvc.AssertExpectations(t)
}

func TestJsonApiHandler_ChangePassword_NoPasswordAuth(t *testing.T) {
	mockUserSvc := new(MockUserService)
	mockLinkedActionSvc := new(MockLinkedActionService)
	mockListingSvc := new(MockListingService)
	mockStorageSvc := new(MockS3Storage)
	mockEnquirySvc := new(MockEnquiryService)
	mockValidationSvc := new(MockUserValidationService)
	mockEmailTemplateSvc := new(MockEmailTemplateService)
	mockTaskClient := new(MockAsynqClient)
	router, _ := setupTestRouter(mockUserSvc, mockLinkedActionSvc, mockListingSvc, mockStorageSvc, mockEnquirySvc, mockValidationSvc, mockEmailTemplateSvc, mockTaskClient, nil)

	// Setup test data
	userID := utils.NewSixID()
	currentPassword := "oldpass123"
	newPassword := "newpass456"

	// Mock user service expectations
	mockUserSvc.On("FindByID", mock.Anything, userID).Return(&models.User{
		ID:       userID,
		Email:    "test@example.com",
		AuthType: models.AuthTypeEmailLoginCodeOnly, // User does not have password auth
	}, nil)

	// Create request with array of passwords
	argsBytes, _ := json.Marshal([]string{currentPassword, newPassword})
	reqBody := handlers.JsonApiRequest{
		Method:    "changePassword",
		Arguments: json.RawMessage(argsBytes),
	}
	jsonBody, _ := json.Marshal(reqBody)

	// Create JWT token for authentication
	token, _ := auth.GenerateJWT(userID, false, "testsecret", 24*time.Hour)

	// Make request
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/v1/api", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)

	// Assert response
	assert.Equal(t, http.StatusOK, w.Code)
	var resp handlers.JsonApiResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.False(t, resp.Success)
	assert.Nil(t, resp.Data)
	assert.Equal(t, "Password is not set for this account", resp.Error)

	mockUserSvc.AssertExpectations(t)
}
