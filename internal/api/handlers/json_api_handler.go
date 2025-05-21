package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"greendrake/l1/internal/utils"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/hibiken/asynq"
	"github.com/redis/go-redis/v9"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"greendrake/l1/internal/auth"
	"greendrake/l1/internal/config"
	"greendrake/l1/internal/models"
	"greendrake/l1/internal/services"
	"greendrake/l1/internal/storage"
	"greendrake/l1/internal/tasks"
	// Placeholder for coder etc.
)

// Context key type for AuthResult
type authContextKey string

const authResultKey authContextKey = "authResult"

// Helper to get AuthResult from context
func getAuthFromContext(ctx context.Context) (*AuthResult, bool) {
	val, ok := ctx.Value(authResultKey).(*AuthResult)
	return val, ok
}

// IAsynqClient defines the interface for the Asynq client methods used by the handler.
// This allows easier mocking than using the concrete asynq.Client.
type IAsynqClient interface {
	EnqueueContext(ctx context.Context, task *asynq.Task, opts ...asynq.Option) (*asynq.TaskInfo, error)
	// Add other methods if needed, e.g., Close()
}

// JsonApiRequest defines the expected structure for JSON API requests.
type JsonApiRequest struct {
	Method    string          `json:"method"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

// JsonApiResponse defines the structure for JSON API responses.
type JsonApiResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"` // Renamed from Result
	Error   string      `json:"error,omitempty"`
}

// apiMethodFunc defines the signature for handler methods.
type apiMethodFunc func(c *gin.Context, args json.RawMessage) (interface{}, *ApiError)

// JsonApiHandler holds dependencies for handling JSON API requests.
type JsonApiHandler struct {
	cfg                   *config.Config
	db                    *mongo.Database               // DB might still be needed for direct access in some handlers
	rdb                   *redis.Client                 // Cache client
	userService           services.IUserService         // Use interface
	linkedActionService   services.ILinkedActionService // Use interface
	listingService        services.IListingService      // Added
	storageService        storage.IS3Storage            // Added
	enquiryService        services.IEnquiryService
	taskClient            IAsynqClient                    // Use interface
	userValidationService services.IUserValidationService // Added
	billingService        services.IBillingService        // Added
	methods               map[string]apiMethodFunc        // Map for method dispatch
}

// NewJsonApiHandler creates a new handler for the JSON API endpoint.
// Accepts interfaces for dependencies.
func NewJsonApiHandler(
	cfg *config.Config,
	db *mongo.Database,
	rdb *redis.Client,
	taskClient IAsynqClient, // Accept interface
	userService services.IUserService, // Accept interface
	linkedActionService services.ILinkedActionService, // Accept interface
	listingService services.IListingService, // Added
	storageService storage.IS3Storage, // Added
	enquiryService services.IEnquiryService, // Added
	userValidationService services.IUserValidationService, // Added
	billingService services.IBillingService, // Added
) *JsonApiHandler {
	h := &JsonApiHandler{
		cfg:                   cfg,
		db:                    db,
		rdb:                   rdb,
		taskClient:            taskClient,
		userService:           userService,
		linkedActionService:   linkedActionService,
		listingService:        listingService,                 // Added
		storageService:        storageService,                 // Added
		enquiryService:        enquiryService,                 // Added
		userValidationService: userValidationService,          // Added
		billingService:        billingService,                 // Added
		methods:               make(map[string]apiMethodFunc), // Initialized by previous step
	}
	h.methods = map[string]apiMethodFunc{
		"ping":                         h.ping,
		"signInOrUp":                   h.signInOrUp,
		"invokeLinkedAction":           h.invokeLinkedAction,
		"setCredentials":               h.setCredentials,
		"login":                        h.login,
		"reSendActivationEmail":        h.reSendActivationEmail,
		"signIn":                       h.signIn,
		"resetAccess":                  h.resetAccess,
		"refreshToken":                 h.refreshToken,
		"createListing":                h.createListing,
		"updateListing":                h.updateListing,
		"publishListing":               h.publishListing,
		"hideListing":                  h.hideListing,
		"unhideListing":                h.unhideListing,
		"deleteListing":                h.deleteListing,
		"getUploadURL":                 h.getUploadURL,
		"confirmImageUpload":           h.confirmImageUpload,
		"sendEnquiry":                  h.sendEnquiry,
		"listValidationTypes":          h.listValidationTypes,
		"startDomainValidation":        h.startDomainValidation,
		"startOnlineProfileValidation": h.startOnlineProfileValidation,
		"suspendUser":                  h.suspendUser,
		"unSuspendUser":                h.unSuspendUser,
		"suspendListing":               h.suspendListing,
		"unsuspendListing":             h.unsuspendListing,
		"startChangingEmail":           h.startChangingEmail,
		"setOTPSecret":                 h.setOTPSecret,
		"addWebAuthnCredential":        h.addWebAuthnCredential,
		"removeWebAuthnCredential":     h.removeWebAuthnCredential,
		"getOutstandingCharges":        h.getOutstandingCharges,
		"generateInvoice":              h.generateInvoice,
		"listOverdueInvoices":          h.listOverdueInvoices,
		"markInvoiceOverdueNotified":   h.markInvoiceOverdueNotified,
		"requestAccountDeletion":       h.requestAccountDeletion,
		"getLocationByCoords":          h.getLocationByCoords,
		"changePassword":               h.changePassword,
	}
	return h
}

// HandleRequest is the main entry point for POST /v1/api
func (h *JsonApiHandler) HandleRequest(c *gin.Context) {
	bodyBytes, err := io.ReadAll(c.Request.Body)
	if err != nil {
		h.sendErrorResponse(c, "Failed to read request body")
		return
	}

	var req JsonApiRequest
	if err := json.Unmarshal(bodyBytes, &req); err != nil {
		h.sendErrorResponse(c, "Invalid JSON request format")
		return
	}

	authErr := h.checkAuthForMethod(c, req.Method)
	if authErr != nil {
		h.sendErrorResponse(c, authErr.Message)
		return
	}

	var result interface{}
	var apiErr *ApiError

	if handlerFunc, ok := h.methods[req.Method]; ok {
		result, apiErr = handlerFunc(c, req.Arguments)
	} else {
		h.sendErrorResponse(c, fmt.Sprintf("Unknown method: %s", req.Method))
		return
	}

	if apiErr != nil {
		h.sendErrorResponse(c, apiErr.Message)
		return
	}

	h.sendSuccessResponse(c, result)
}

// AuthResult holds optional authentication details
type AuthResult struct {
	UserID  *utils.SixID // Pointer to allow nil for guests
	IsAdmin bool
}

// checkAuthForMethod checks if auth is needed and validates/extracts details if so.
// It stores the AuthResult in c.Request.Context().
func (h *JsonApiHandler) checkAuthForMethod(c *gin.Context, method string) *ApiError {
	needsAuth := h.methodRequiresAuth(method)
	needsAdmin := h.methodRequiresAdmin(method)
	var authRes *AuthResult

	if !needsAuth && !needsAdmin {
		// If method is public, check if an optional Auth header is present anyway
		authHeader := c.GetHeader("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			tokenString := strings.TrimPrefix(authHeader, "Bearer ")
			claims, err := auth.ValidateJWT(tokenString, h.cfg.JwtSecret)
			if err == nil { // Token is valid
				userID, _ := utils.ParseSixID(claims.UserID)
				authRes = &AuthResult{UserID: &userID, IsAdmin: claims.IsAdmin}
			} else {
				// Invalid optional token? Log it but proceed as guest
				log.Printf("DEBUG: Invalid optional auth token provided for method %s: %v", method, err)
				authRes = &AuthResult{UserID: nil, IsAdmin: false} // Guest
			}
		} else {
			authRes = &AuthResult{UserID: nil, IsAdmin: false} // Guest
		}
		ctx := context.WithValue(c.Request.Context(), authResultKey, authRes)
		c.Request = c.Request.WithContext(ctx)
		return nil // Proceed as guest or with optional auth
	}

	// Auth is required
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		return NewApiError("Authorization header required")
	}
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return NewApiError("Authorization header format must be Bearer {token}")
	}
	tokenString := parts[1]
	claims, err := auth.ValidateJWT(tokenString, h.cfg.JwtSecret)
	if err != nil {
		log.Printf("DEBUG: Token validation failed for method %s: %v", method, err)
		return NewApiError(fmt.Sprintf("Invalid or expired token: %v", err))
	}

	userID, idErr := utils.ParseSixID(claims.UserID)
	if idErr != nil {
		log.Printf("ERROR: Invalid UserID (%s) in valid JWT for method %s", claims.UserID, method)
		return NewApiError("Internal error")
	}

	// Check admin privileges if required
	if needsAdmin && !claims.IsAdmin {
		log.Printf("DEBUG: Admin privileges required but not present for method %s", method)
		return NewApiError("Administrator privileges required")
	}

	authRes = &AuthResult{UserID: &userID, IsAdmin: claims.IsAdmin}
	ctx := context.WithValue(c.Request.Context(), authResultKey, authRes)
	c.Request = c.Request.WithContext(ctx)
	return nil
}

// methodRequiresAuth checks if a given API method requires authentication.
func (h *JsonApiHandler) methodRequiresAuth(method string) bool {
	switch method {
	// List authenticated methods
	case "refreshToken",
		"createListing",
		"updateListing",
		"publishListing",
		"hideListing",
		"unhideListing",
		"deleteListing",
		"startChangingEmail",
		"suspendUser",
		"unSuspendUser",
		"getUploadURL",
		"confirmImageUpload",
		// "listValidationTypes", // Now public
		"startDomainValidation",
		"startOnlineProfileValidation",
		"changePassword",
		"setOTPSecret",
		"addWebAuthnCredential",
		"removeWebAuthnCredential",
		"getOutstandingCharges",
		"generateInvoice",
		"listOverdueInvoices",        // Admin, so requires auth
		"markInvoiceOverdueNotified", // Admin, so requires auth
		"requestAccountDeletion",
		"suspendListing",   // Admin, requires auth
		"unsuspendListing": // Admin, requires auth
		return true // This applies to all preceding cases in this block

	// Public methods by default
	case "ping",
		"signInOrUp",
		"invokeLinkedAction",
		"setCredentials",
		"login",
		"reSendActivationEmail",
		"signIn",
		"resetAccess",
		"getLocationByCoords",
		"sendEnquiry",         // Now public, AuthResult is checked in handler
		"listValidationTypes": // Explicitly public
		return false // This applies to all preceding cases in this block

	default:
		log.Printf("Warning: methodRequiresAuth check for unlisted method '%s', defaulting to false (public)", method)
		return false
	}
}

// methodRequiresAdmin checks if a given API method requires admin privileges.
func (h *JsonApiHandler) methodRequiresAdmin(method string) bool {
	switch method {
	// List admin-only methods
	case "suspendUser",
		"unSuspendUser",
		"suspendListing",
		"unsuspendListing",
		"listOverdueInvoices",
		"markInvoiceOverdueNotified":
		return true
	default:
		return false
	}
}

// --- Private helper methods ---

func (h *JsonApiHandler) sendSuccessResponse(c *gin.Context, data interface{}) {
	resp := JsonApiResponse{Success: true, Data: data}
	c.JSON(http.StatusOK, resp)
}

func (h *JsonApiHandler) sendErrorResponse(c *gin.Context, message string) {
	resp := JsonApiResponse{Success: false, Error: message}
	c.JSON(http.StatusOK, resp)
}

// --- API Method Implementations ---

func (h *JsonApiHandler) ping(c *gin.Context, args json.RawMessage) (interface{}, *ApiError) {
	_ = args // Explicitly ignore unused args
	return "pong", nil
}

type ApiError struct {
	Message string
}

func (e *ApiError) Error() string {
	return e.Message
}

func NewApiError(message string) *ApiError {
	return &ApiError{Message: message}
}

var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

func (h *JsonApiHandler) signInOrUp(c *gin.Context, args json.RawMessage) (interface{}, *ApiError) {
	var email string
	if apiErr := h.parseRequiredSingleArgFromArray(args, &email); apiErr != nil {
		return nil, apiErr
	}

	if !emailRegex.MatchString(email) {
		return nil, NewApiError("invalid_email")
	}

	ctx := c.Request.Context()
	user, err := h.userService.FindByEmail(ctx, email)

	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			newUser, createErr := h.userService.CreatePhantomUser(ctx, email)
			if createErr != nil {
				log.Printf("Error creating phantom user %s: %v", email, createErr)
				return nil, NewApiError("Registration failed")
			}
			linkedAction, actionErr := h.linkedActionService.CreateLoginToSetupAction(ctx, newUser.ID)
			if actionErr != nil {
				log.Printf("Error creating linked action user %s: %v", newUser.ID.String(), actionErr)
				return nil, NewApiError("Activation link creation failed")
			}

			payloadBytes, _ := json.Marshal(tasks.EmailTaskPayload{
				To:         email,
				TemplateID: "activate_account",
				Data:       map[string]interface{}{"action_id": linkedAction.ID.String()}, // Using Crockford Base32
			})
			task := asynq.NewTask(tasks.TypeEmailDelivery, payloadBytes)
			if _, enqueueErr := h.taskClient.EnqueueContext(ctx, task); enqueueErr != nil {
				log.Printf("ERROR enqueuing activation email user %s: %v", newUser.ID.String(), enqueueErr)
			}

			log.Printf("ACTION_ID (testing): %s", linkedAction.ID.String()) // Now encoded as Crockford Base32
			return "created", nil
		}
		log.Printf("DB error finding user %s: %v", email, err)
		return nil, NewApiError("Database error")
	}

	if !user.Activated {
		return "see_email", nil
	}

	switch user.AuthType {
	case models.AuthTypePasswordOnly, models.AuthTypePasswordAndOTP, models.AuthTypePasswordAndEmailLoginCode:
		return "password", nil
	case models.AuthTypeEmailLoginCodeOnly, models.AuthTypeEmailLoginCodeAndOTP:
		return "email_code", nil
	case models.AuthTypeWebAuthn:
		return "webauthn", nil // Placeholder
	default:
		log.Printf("User %s has invalid auth type: %s", user.ID.String(), user.AuthType)
		return nil, NewApiError("Invalid auth type")
	}
}

func (h *JsonApiHandler) invokeLinkedAction(c *gin.Context, args json.RawMessage) (interface{}, *ApiError) {
	var actionIDHex string
	if apiErr := h.parseRequiredSingleArgFromArray(args, &actionIDHex); apiErr != nil {
		return nil, apiErr
	}

	ctx := c.Request.Context()
	// Find and validate action by ID only
	// Passing nil for expectedUserID allows any user to invoke if they have the ID (is this desired?)
	action, err := h.linkedActionService.FindAndValidateAction(ctx, actionIDHex, nil) // Parse Crockford Base32 SixID
	if err != nil {
		return nil, NewApiError(err.Error())
	}

	// --- Perform action-specific logic ---
	var result interface{} = gin.H{"type": action.Type} // Default result includes action type
	var serviceErr error

	switch action.Type {
	case models.ActionLoginToSetupAccount:
		// For setup/reset, just marking executed is enough.
		// The result 'true' might signify to the frontend that credential setting can proceed.
		result = gin.H{"type": action.Type} // Keep action type in response
		// Note: We don't mark this action as executed here anymore
	case models.ActionEmailChangeOldApprove:
		serviceErr = h.userService.ApproveEmailChangeOld(ctx, action.UserID)
		if serviceErr == nil {
			responseData := gin.H{
				"type": action.Type,
			}
			if oldEmail, ok := action.Data["old_email"].(string); ok {
				responseData["old_email"] = oldEmail
			}
			if newEmail, ok := action.Data["new_email"].(string); ok {
				responseData["new_email"] = newEmail
			}
			result = responseData
		}
	case models.ActionEmailChangeNewConfirm:
		serviceErr = h.userService.ConfirmEmailChangeNew(ctx, action.UserID)
		if serviceErr == nil {
			responseData := gin.H{
				"type": action.Type,
			}
			if oldEmail, ok := action.Data["old_email"].(string); ok {
				responseData["old_email"] = oldEmail
			}
			if newEmail, ok := action.Data["new_email"].(string); ok {
				responseData["new_email"] = newEmail
			}

			// Check if the corresponding old_approve action has been executed
			if oldActionIDHex, ok := action.Data["old_action_id"].(string); ok {
				oldActionID, idErr := utils.ParseSixID(oldActionIDHex)
				if idErr == nil {
					oldApproveAction, findErr := h.linkedActionService.FindByID(ctx, oldActionID) // Using Crockford Base32 SixID
					if findErr == nil {
						if oldApproveAction.Executed == nil { // nil means not executed
							responseData["approvalStillNeeded"] = true
						}
					} else {
						log.Printf("Error finding old_approve action %s for new_confirm action %s: %v", oldActionIDHex, action.ID.String(), findErr)
						// Decide if this should be an error to the user or just log
					}
				} else {
					log.Printf("Error parsing old_action_id %s from new_confirm action %s: %v", oldActionIDHex, action.ID.String(), idErr)
				}
			} else {
				log.Printf("Missing old_action_id in data for new_confirm action %s", action.ID.String())
			}
			result = responseData
		}
	// Add case for account deletion
	case models.ActionConfirmAccountDeletion:
		serviceErr = h.userService.DeleteUserAndListings(ctx, action.UserID)
		if serviceErr == nil {
			result = gin.H{
				"type":    action.Type,
				"message": "Account deleted successfully.",
			}
		}
	default:
		// Should not happen if FindAndValidateAction worked, but handle defensively
		log.Printf("ERROR: Valid linked action %s has unexpected type: %s", action.ID.String(), action.Type) // Crockford Base32 SixID
		return nil, NewApiError("Invalid action type encountered")
	}

	// Handle errors from service calls (Approve/Confirm)
	if serviceErr != nil {
		log.Printf("Error performing action type %s for action %s: %v", action.Type, action.ID.String(), serviceErr)
		// Map service error to appropriate API error
		if errors.Is(serviceErr, mongo.ErrNoDocuments) {
			return nil, NewApiError("User not found for action") // Should be rare if action was valid
		}
		return nil, NewApiError("Failed to process action")
	}

	// --- Mark action as executed (only after specific logic succeeds) ---
	// Skip marking as executed for ActionLoginToSetupAccount
	if action.Type != models.ActionLoginToSetupAccount {
		if err := h.linkedActionService.MarkActionExecuted(ctx, action.ID); err != nil {
			log.Printf("Error marking action %s executed: %v", action.ID.String(), err)
			return nil, NewApiError("Failed to finalize action state")
		}
	}

	// Return the result determined by the switch statement
	return result, nil
}

type SetCredentialsArgs struct {
	ActionID string          `json:"linked_action_id"`
	AuthType models.AuthType `json:"auth_type"`
	Secrets  []string        `json:"secrets"`
}

// AuthResponse defines the structure for authentication responses
type AuthResponse struct {
	Token string `json:"token"`
	Email string `json:"email"`
	ID    string `json:"id"`
}

func (h *JsonApiHandler) setCredentials(c *gin.Context, args json.RawMessage) (interface{}, *ApiError) {
	var reqArgs SetCredentialsArgs
	if apiErr := h.parseRequiredSingleArgFromArray(args, &reqArgs); apiErr != nil {
		return nil, apiErr
	}

	ctx := c.Request.Context()
	action, err := h.linkedActionService.FindAndValidateAction(ctx, reqArgs.ActionID, nil)
	if err != nil {
		return false, nil // Success: true, Result: false per blueprint
	}

	var password string
	switch reqArgs.AuthType {
	case models.AuthTypePasswordOnly:
		if len(reqArgs.Secrets) != 1 || reqArgs.Secrets[0] == "" {
			return nil, NewApiError("Password required")
		}
		password = reqArgs.Secrets[0]
	case models.AuthTypePasswordAndEmailLoginCode:
		if len(reqArgs.Secrets) != 1 || reqArgs.Secrets[0] == "" {
			return nil, NewApiError("Password required for this auth type")
		}
		password = reqArgs.Secrets[0]
	case models.AuthTypeEmailLoginCodeOnly:
		if len(reqArgs.Secrets) != 0 {
			return nil, NewApiError("Secrets not allowed")
		}
	default:
		return nil, NewApiError("Unsupported auth_type")
	}

	err = h.userService.SetUserCredentials(ctx, action.UserID, reqArgs.AuthType, password)
	if err != nil {
		log.Printf("Failed setting credentials user %s action %s: %v", action.UserID.String(), reqArgs.ActionID, err)
		return nil, NewApiError("Failed to update credentials")
	}

	// Mark the action as executed
	if err := h.linkedActionService.MarkActionExecuted(ctx, action.ID); err != nil {
		log.Printf("Error marking action %s executed: %v", action.ID.String(), err)
		return nil, NewApiError("Failed to finalize action state")
	}

	// Fetch user to get admin status for JWT
	user, err := h.userService.FindByID(ctx, action.UserID)
	if err != nil {
		log.Printf("Error fetching user %s for JWT generation: %v", action.UserID.String(), err)
		return nil, NewApiError("Failed to generate session token")
	}

	// Generate JWT
	token, err := auth.GenerateJWT(user.ID, user.IsAdmin, h.cfg.JwtSecret, h.cfg.JwtTTL)
	if err != nil {
		log.Printf("Failed to generate JWT for user %s: %v", user.ID.String(), err)
		return nil, NewApiError("Failed to generate session token")
	}

	log.Printf("Credentials set and JWT generated for user %s", user.ID.String())
	return AuthResponse{
		Token: token,
		Email: user.Email,
		ID:    user.ID.String(),
	}, nil
}

// Define structure for login arguments
type LoginArgs struct {
	Email         string `json:"email"`
	ChallengeType string `json:"challenge_type"` // e.g., "password", "email_code", "otp"
	Secret        string `json:"secret"`         // Password, email code, OTP code
}

func (h *JsonApiHandler) login(c *gin.Context, args json.RawMessage) (interface{}, *ApiError) {
	var reqArgs LoginArgs
	if apiErr := h.parseRequiredSingleArgFromArray(args, &reqArgs); apiErr != nil {
		return nil, apiErr
	}

	if !emailRegex.MatchString(reqArgs.Email) {
		return nil, NewApiError("invalid_email")
	}

	ctx := c.Request.Context()

	// 1. Find the activated user
	user, err := h.userService.FindByEmail(ctx, reqArgs.Email)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			// Do not reveal if user exists - return generic auth failed error
			log.Printf("Login attempt failed: user %s not found", reqArgs.Email)
			return false, nil // Return Data: false, Success: true
		}
		log.Printf("DB error finding user %s for login: %v", reqArgs.Email, err)
		return nil, NewApiError("Database error") // This remains a true API error
	}

	if !user.Activated {
		log.Printf("Login attempt failed: user %s (%s) not activated", user.ID.String(), reqArgs.Email)
		return false, nil // Return Data: false, Success: true
	}

	if user.Suspended {
		log.Printf("Login attempt failed: user %s (%s) is suspended", user.ID.String(), reqArgs.Email)
		return false, nil // Return Data: false, Success: true
	}

	// 2. Verify the provided secret against the challenge type and user's configured auth
	loginSuccessful := false
	remainingChallenge := "" // Track if further steps are needed (e.g., OTP after password)

	switch reqArgs.ChallengeType {
	case "password":
		if user.AuthType == models.AuthTypeEmailLoginCodeOnly {
			return false, nil // Return Data: false, Success: true
		}
		if !auth.CheckPasswordHash(reqArgs.Secret, user.PasswordHash) {
			log.Printf("Login attempt failed: invalid password for user %s (%s)", user.ID.String(), reqArgs.Email)
			return false, nil // Return Data: false, Success: true
		}
		// Password is correct. Check if further steps are needed.
		if user.AuthType == models.AuthTypePasswordAndOTP {
			remainingChallenge = "otp"
		} else if user.AuthType == models.AuthTypePasswordAndEmailLoginCode {
			// Generate and send email login code via task
			if err := h.sendLoginCodeEmail(ctx, user.ID, user.Email); err != nil {
				log.Printf("ERROR failed to send login code email during login step for user %s: %v", user.ID.String(), err)
				// Return internal error? Or proceed hoping user retries?
				return nil, NewApiError("Failed to send login code") // This remains a true API error
			}
			remainingChallenge = "email_code"
		} else {
			loginSuccessful = true
		}
	case "email_code":
		if user.AuthType == models.AuthTypePasswordOnly || user.AuthType == models.AuthTypePasswordAndOTP {
			return false, nil // Return Data: false, Success: true
		}
		// Call FindAndValidateAction without the type argument
		action, validationErr := h.linkedActionService.FindAndValidateAction(ctx, reqArgs.Secret, &user.ID)
		if validationErr != nil {
			log.Printf("Login attempt failed: invalid email_code '%s' for user %s (%s): %v", reqArgs.Secret, user.ID.String(), reqArgs.Email, validationErr)
			return false, nil // Return Data: false, Success: true
		}
		// Mark email code action as executed
		if err := h.linkedActionService.MarkActionExecuted(ctx, action.ID); err != nil {
			log.Printf("Error marking email_code action %s executed for user %s: %v", action.ID.String(), user.ID.String(), err)
			// Continue login, but log error
		}
		// Check if further steps are needed
		if user.AuthType == models.AuthTypeEmailLoginCodeAndOTP {
			remainingChallenge = "otp"
		} else {
			loginSuccessful = true
		}
	case "otp":
		if user.AuthType != models.AuthTypePasswordAndOTP && user.AuthType != models.AuthTypeEmailLoginCodeAndOTP {
			return false, nil // Return Data: false, Success: true
		}
		// TODO: Implement OTP validation using a library (e.g., github.com/pquerna/otp)
		// Requires storing OTP secret per user and validating reqArgs.Secret
		// isValidOtp := validateOtp(user.OtpSecret, reqArgs.Secret)
		// if !isValidOtp { ... return error ... }
		// For now, assume OTP validation placeholder
		log.Printf("OTP validation for user %s (%s) - NOT IMPLEMENTED", user.ID.String(), reqArgs.Email)
		// Assuming OTP is the final step if present
		loginSuccessful = true // Placeholder
	case "webauthn":
		// TODO: Implement WebAuthn assertion verification
		log.Printf("WebAuthn validation for user %s (%s) - NOT IMPLEMENTED", user.ID.String(), reqArgs.Email)
		loginSuccessful = true // Placeholder
	default:
		return nil, NewApiError(fmt.Sprintf("Unsupported challenge_type: %s", reqArgs.ChallengeType)) // This remains a true API error
	}

	// 3. Return result
	if loginSuccessful {
		// Generate JWT

		token, err := auth.GenerateJWT(user.ID, user.IsAdmin, h.cfg.JwtSecret, h.cfg.JwtTTL)
		if err != nil {
			log.Printf("Failed to generate JWT for user %s (%s): %v", user.ID.String(), reqArgs.Email, err)
			return nil, NewApiError("Failed to generate session token") // This remains a true API error
		}
		log.Printf("Login successful for user %s (%s)", user.ID.String(), reqArgs.Email)
		return AuthResponse{
			Token: token,
			Email: user.Email,
			ID:    user.ID.String(),
		}, nil
	} else if remainingChallenge != "" {
		// Return the next challenge required
		log.Printf("Login step successful for user %s (%s), next challenge: %s", user.ID.String(), reqArgs.Email, remainingChallenge)
		return remainingChallenge, nil
	} else {
		// Should not happen if logic is correct, but handle as generic failure
		log.Printf("Login failed unexpectedly for user %s (%s) after challenge '%s'", user.ID.String(), reqArgs.Email, reqArgs.ChallengeType)
		return false, nil // Return Data: false, Success: true
	}
}

func (h *JsonApiHandler) reSendActivationEmail(c *gin.Context, args json.RawMessage) (interface{}, *ApiError) {
	var email string
	if apiErr := h.parseRequiredSingleArgFromArray(args, &email); apiErr != nil {
		return nil, apiErr
	}
	if !emailRegex.MatchString(email) {
		return nil, NewApiError("invalid_email")
	}

	ctx := c.Request.Context()
	user, err := h.userService.FindByEmail(ctx, email)

	// Only proceed if user exists and is NOT activated
	if err != nil || user.Activated {
		if err != nil && !errors.Is(err, mongo.ErrNoDocuments) {
			log.Printf("DB error finding user %s for reSendActivationEmail: %v", email, err)
			// Don't reveal internal error, just return false
		}
		// User not found, already activated, or DB error -> return false as per blueprint
		return false, nil // Success: true, Result: false
	}

	// Find the existing login_to_setup_account action for the user
	// This requires adding a method to LinkedActionService
	// action, err := h.linkedActionService.FindPendingAction(ctx, user.ID, models.ActionLoginToSetupAccount)
	// if err != nil {
	// 	 log.Printf("Could not find pending activation action for user %s: %v", user.ID.String(), err)
	// 	 return false, nil // Treat as failure
	// }

	// Placeholder: Assume we found the action ID somehow (e.g., from user doc or new service method)
	actionIDPlaceholder := "dummyActionIDForResend" // Replace with actual logic
	log.Printf("[TODO] Found pending action for user %s. Need service method to get ID.", user.ID.String())

	// Enqueue email task
	payloadBytes, _ := json.Marshal(tasks.EmailTaskPayload{
		To:         email,
		TemplateID: "activate_account", // Reuse activation template
		Data: map[string]interface{}{
			"action_id": actionIDPlaceholder,
		},
	})
	task := asynq.NewTask(tasks.TypeEmailDelivery, payloadBytes)
	if _, enqueueErr := h.taskClient.EnqueueContext(ctx, task); enqueueErr != nil {
		log.Printf("ERROR enqueuing resend activation email task for user %s: %v", user.ID.String(), enqueueErr)
		// Return false on failure to enqueue?
		return false, nil
	}

	log.Printf("Resent activation email initiated for %s (User: %s)", email, user.ID.String())
	return true, nil // Success: true, Result: true
}

func (h *JsonApiHandler) signIn(c *gin.Context, args json.RawMessage) (interface{}, *ApiError) {
	var email string
	if apiErr := h.parseRequiredSingleArgFromArray(args, &email); apiErr != nil {
		return nil, apiErr
	}
	if !emailRegex.MatchString(email) {
		return nil, NewApiError("invalid_email")
	}

	ctx := c.Request.Context()
	user, err := h.userService.FindByEmail(ctx, email)

	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			// Blueprint: If email not found, return "email_login_code_only" to obscure existence.
			return "email_login_code_only", nil
		}
		// Other DB error
		log.Printf("DB error during signIn for %s: %v", email, err)
		return nil, NewApiError("Database error")
	}

	// User found, follow same logic as signInOrUp for existing users
	if !user.Activated {
		return "see_email", nil
	}

	switch user.AuthType {
	case models.AuthTypePasswordOnly, models.AuthTypePasswordAndOTP, models.AuthTypePasswordAndEmailLoginCode:
		return "password", nil
	case models.AuthTypeEmailLoginCodeOnly, models.AuthTypeEmailLoginCodeAndOTP:
		// Trigger email code task if this is the primary/only method
		if err := h.sendLoginCodeEmail(ctx, user.ID, user.Email); err != nil {
			// Log error but proceed to return "email_code" as the flow started
			log.Printf("ERROR failed to send login code email during signIn for user %s: %v", user.ID.String(), err)
		}
		return "email_code", nil // Still tell the user to check email
	case models.AuthTypeWebAuthn:
		// TODO: Initiate WebAuthn assertion
		return "webauthn", nil // Placeholder
	default:
		log.Printf("User %s has invalid auth type during signIn: %s", user.ID.String(), user.AuthType)
		return nil, NewApiError("Invalid auth type")
	}
}

func (h *JsonApiHandler) resetAccess(c *gin.Context, args json.RawMessage) (interface{}, *ApiError) {
	var email string
	if apiErr := h.parseRequiredSingleArgFromArray(args, &email); apiErr != nil {
		return nil, apiErr
	}
	if !emailRegex.MatchString(email) {
		return nil, NewApiError("invalid_email")
	}

	ctx := c.Request.Context()
	user, err := h.userService.FindByEmail(ctx, email)

	if err != nil || !user.Activated {
		if err != nil && !errors.Is(err, mongo.ErrNoDocuments) {
			log.Printf("DB error finding user %s for resetAccess: %v", email, err)
		}
		log.Printf("Access reset requested for non-existent or non-activated user %s. No action taken.", email)
		return nil, nil // Success: true, Result: null (no error, no confirmation)
	}

	// Use the new service method
	resetAction, err := h.linkedActionService.CreateResetAccessAction(ctx, user.ID)
	if err != nil {
		log.Printf("Failed to create reset access action for user %s: %v", user.ID.String(), err)
		return nil, NewApiError("Failed to initiate access reset")
	}

	// Enqueue email task
	payloadBytes, _ := json.Marshal(tasks.EmailTaskPayload{
		To:         email,
		TemplateID: "reset_access", // Needs template in DB
		Data: map[string]interface{}{
			"action_id": resetAction.ID.String(), // Use the actual action ID as Crockford Base32
		},
	})
	task := asynq.NewTask(tasks.TypeEmailDelivery, payloadBytes)
	if _, enqueueErr := h.taskClient.EnqueueContext(ctx, task); enqueueErr != nil {
		log.Printf("ERROR enqueuing reset access email task for user %s: %v", user.ID.String(), enqueueErr)
		// Still return success even if email fails?
	}

	log.Printf("Access reset initiated for user %s (%s)", user.ID.String(), email)
	return nil, nil // Success: true, Result: null
}

func (h *JsonApiHandler) refreshToken(c *gin.Context, args json.RawMessage) (interface{}, *ApiError) {
	_ = args // Explicitly ignore unused args
	authInfo, ok := getAuthFromContext(c.Request.Context())
	if !ok || authInfo.UserID == nil {
		// This should ideally be caught by methodRequiresAuth, but defensive check.
		return nil, NewApiError("Authentication required for refreshToken")
	}
	userIDHex := authInfo.UserID.String()

	// Generate a new token with the same claims but new expiration
	newToken, err := auth.GenerateJWT(*authInfo.UserID, authInfo.IsAdmin, h.cfg.JwtSecret, h.cfg.JwtTTL)
	if err != nil {
		log.Printf("Failed to generate refreshed JWT for user %s: %v", userIDHex, err)
		return nil, NewApiError("Failed to refresh session token")
	}

	log.Printf("Refreshed token for user %s", userIDHex)
	return newToken, nil
}

// Define structure for createListing arguments
type CreateListingArgs struct {
	Title       string              `json:"title"`
	Body        string              `json:"body"`
	Tags        []string            `json:"tags"`
	LocationID  int                 `json:"location_id"`
	CountryCode string              `json:"country_code"` // Should ideally be derived from LocationID server-side
	Shipping    string              `json:"shipping"`
	AskingPrice *models.AskingPrice `json:"asking_price"`
}

func (h *JsonApiHandler) createListing(c *gin.Context, args json.RawMessage) (interface{}, *ApiError) {
	authInfo, ok := getAuthFromContext(c.Request.Context())
	if !ok || authInfo.UserID == nil {
		return nil, NewApiError("Authentication required to create listing")
	}
	userIDHex := authInfo.UserID.String()

	var reqArgs CreateListingArgs
	if apiErr := h.parseRequiredSingleArgFromArray(args, &reqArgs); apiErr != nil {
		return nil, apiErr
	}

	// Basic Validation
	if strings.TrimSpace(reqArgs.Title) == "" {
		return nil, NewApiError("Title cannot be empty")
	}
	// TODO: Add more validation (body length, tag count/format, shipping values, location ID format/existence, price)

	// TODO: Consider fetching default location/shipping from user settings if not provided.
	// TODO: Server should ideally look up CountryCode from LocationID instead of trusting client.

	ctx := c.Request.Context()
	newListing, err := h.listingService.CreateListing(ctx,
		*authInfo.UserID,
		reqArgs.Title,
		reqArgs.Body,
		reqArgs.Tags,
		reqArgs.LocationID,
		reqArgs.CountryCode, // Pass client value for now
		reqArgs.Shipping,
		reqArgs.AskingPrice,
	)

	if err != nil {
		log.Printf("Error creating listing for user %s: %v", userIDHex, err)
		return nil, NewApiError("Failed to create listing")
	}

	log.Printf("Created new listing %s for user %s", newListing.ID.String(), userIDHex)
	// Return the newly created listing object (or just its ID?)
	// Blueprint doesn't specify return value, let's return the object.
	return newListing, nil
}

// Define structure for updateListing arguments
// Expects the listing ID and a map of fields to update.
type UpdateListingArgs struct {
	ListingID string                 `json:"listing_id"`
	Updates   map[string]interface{} `json:"updates"`
}

func (h *JsonApiHandler) updateListing(c *gin.Context, args json.RawMessage) (interface{}, *ApiError) {
	authInfo, ok := getAuthFromContext(c.Request.Context())
	if !ok || authInfo.UserID == nil {
		return nil, NewApiError("Authentication required to update listing")
	}
	userIDHex := authInfo.UserID.String()

	var reqArgs UpdateListingArgs
	if apiErr := h.parseRequiredSingleArgFromArray(args, &reqArgs); apiErr != nil {
		return nil, apiErr
	}

	listingID, err := utils.ParseSixID(reqArgs.ListingID)
	if err != nil {
		return nil, NewApiError("Invalid listing_id format")
	}

	if len(reqArgs.Updates) == 0 {
		return nil, NewApiError("No updates provided")
	}

	// TODO: Validate updates map contents further (e.g., data types)

	ctx := c.Request.Context()
	updatedListing, err := h.listingService.UpdateListing(ctx, listingID, *authInfo.UserID, reqArgs.Updates)
	if err != nil {
		log.Printf("Error updating listing %s for user %s: %v", reqArgs.ListingID, userIDHex, err)
		// Provide a more user-friendly error based on potential service errors
		if strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "not owned") {
			return nil, NewApiError("Listing not found or access denied")
		} else if strings.Contains(err.Error(), "cannot be updated") {
			return nil, NewApiError(err.Error()) // Pass specific field error
		}
		return nil, NewApiError("Failed to update listing")
	}

	return updatedListing, nil
}

// Helper to parse listing ID argument common to publish/hide/unhide/delete
func parseListingIDArg(args json.RawMessage) (utils.SixID, *ApiError) {
	var listingIDHex string
	if err := json.Unmarshal(args, &listingIDHex); err != nil {
		// This function is used when args is *just* the listingID string.
		// If parseRequiredSingleArgFromArray is used, it expects an array.
		// Let's adjust to use parseRequiredSingleArgFromArray for consistency.
		return utils.SixID{}, NewApiError("Invalid arguments: expected listing ID string")
	}
	listingID, err := utils.ParseSixID(listingIDHex)
	if err != nil {
		return utils.SixID{}, NewApiError("Invalid listing_id format")
	}
	return listingID, nil
}

func (h *JsonApiHandler) publishListing(c *gin.Context, args json.RawMessage) (interface{}, *ApiError) {
	authInfo, ok := getAuthFromContext(c.Request.Context())
	if !ok || authInfo.UserID == nil {
		return nil, NewApiError("Authentication required")
	}
	userIDHex := authInfo.UserID.String()

	var listingIDHex string
	if apiErr := h.parseRequiredSingleArgFromArray(args, &listingIDHex); apiErr != nil {
		return nil, apiErr
	}
	listingID, err := utils.ParseSixID(listingIDHex)
	if err != nil {
		return nil, NewApiError("Invalid listing_id format in argument")
	}

	ctx := c.Request.Context()
	err = h.listingService.PublishListing(ctx, listingID, *authInfo.UserID)
	if err != nil {
		log.Printf("Error publishing listing %s for user %s: %v", listingID.String(), userIDHex, err)
		if strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "not owned") {
			return nil, NewApiError("Listing not found or access denied")
		} else if strings.Contains(err.Error(), "already published") {
			return nil, NewApiError("Listing already published")
		}
		return nil, NewApiError("Failed to publish listing")
	}

	return nil, nil // Success, no result body
}

func (h *JsonApiHandler) hideListing(c *gin.Context, args json.RawMessage) (interface{}, *ApiError) {
	authInfo, ok := getAuthFromContext(c.Request.Context())
	if !ok || authInfo.UserID == nil {
		return nil, NewApiError("Authentication required")
	}
	userIDHex := authInfo.UserID.String()

	var listingIDHex string
	if apiErr := h.parseRequiredSingleArgFromArray(args, &listingIDHex); apiErr != nil {
		return nil, apiErr
	}
	listingID, err := utils.ParseSixID(listingIDHex)
	if err != nil {
		return nil, NewApiError("Invalid listing_id format in argument")
	}

	ctx := c.Request.Context()
	err = h.listingService.HideListing(ctx, listingID, *authInfo.UserID)
	if err != nil {
		log.Printf("Error hiding listing %s for user %s: %v", listingID.String(), userIDHex, err)
		if strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "not owned") || strings.Contains(err.Error(), "cannot be updated") {
			return nil, NewApiError("Listing not found or cannot be hidden")
		} else if strings.Contains(err.Error(), "already has hidden=true") {
			return nil, NewApiError("Listing already hidden")
		}
		return nil, NewApiError("Failed to hide listing")
	}
	return nil, nil // Success
}

func (h *JsonApiHandler) unhideListing(c *gin.Context, args json.RawMessage) (interface{}, *ApiError) {
	authInfo, ok := getAuthFromContext(c.Request.Context())
	if !ok || authInfo.UserID == nil {
		return nil, NewApiError("Authentication required")
	}
	userIDHex := authInfo.UserID.String()

	var listingIDHex string
	if apiErr := h.parseRequiredSingleArgFromArray(args, &listingIDHex); apiErr != nil {
		return nil, apiErr
	}
	listingID, err := utils.ParseSixID(listingIDHex)
	if err != nil {
		return nil, NewApiError("Invalid listing_id format in argument")
	}

	ctx := c.Request.Context()
	err = h.listingService.UnhideListing(ctx, listingID, *authInfo.UserID)
	if err != nil {
		log.Printf("Error unhiding listing %s for user %s: %v", listingID.String(), userIDHex, err)
		if strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "not owned") || strings.Contains(err.Error(), "cannot be updated") {
			return nil, NewApiError("Listing not found or cannot be unhidden")
		} else if strings.Contains(err.Error(), "already has hidden=false") {
			return nil, NewApiError("Listing already visible")
		}
		return nil, NewApiError("Failed to unhide listing")
	}
	return nil, nil // Success
}

func (h *JsonApiHandler) deleteListing(c *gin.Context, args json.RawMessage) (interface{}, *ApiError) {
	authInfo, ok := getAuthFromContext(c.Request.Context())
	if !ok || authInfo.UserID == nil {
		return nil, NewApiError("Authentication required")
	}
	userIDHex := authInfo.UserID.String()

	var listingIDHex string
	if apiErr := h.parseRequiredSingleArgFromArray(args, &listingIDHex); apiErr != nil {
		return nil, apiErr
	}
	listingID, err := utils.ParseSixID(listingIDHex)
	if err != nil {
		return nil, NewApiError("Invalid listing_id format in argument")
	}

	ctx := c.Request.Context()
	err = h.listingService.DeleteListing(ctx, listingID, *authInfo.UserID)
	if err != nil {
		log.Printf("Error deleting listing %s for user %s: %v", listingID.String(), userIDHex, err)
		if strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "not owned") || strings.Contains(err.Error(), "cannot be updated") {
			// Return Not Found even if already deleted, as it achieves the desired state
			return nil, NewApiError("Listing not found or cannot be deleted")
		} else if strings.Contains(err.Error(), "already has deleted=true") {
			// Already deleted, treat as success
			log.Printf("Attempted to delete already deleted listing %s", listingID.String())
			return nil, nil
		}
		return nil, NewApiError("Failed to delete listing")
	}
	return nil, nil // Success
}

// Define structure for getUploadURL arguments
type GetUploadURLArgs struct {
	ListingID   string `json:"listing_id"`
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
}

func (h *JsonApiHandler) getUploadURL(c *gin.Context, args json.RawMessage) (interface{}, *ApiError) {
	authInfo, ok := getAuthFromContext(c.Request.Context())
	if !ok || authInfo.UserID == nil {
		return nil, NewApiError("Authentication required")
	}
	userIDHex := authInfo.UserID.String()

	var reqArgs GetUploadURLArgs
	if apiErr := h.parseRequiredSingleArgFromArray(args, &reqArgs); apiErr != nil {
		return nil, apiErr
	}

	// Validate inputs
	if reqArgs.ListingID == "" || reqArgs.Filename == "" || reqArgs.ContentType == "" {
		return nil, NewApiError("Missing required arguments (listing_id, filename, content_type)")
	}
	// TODO: Add more robust validation (filename chars, content-type format/allowlist, check listing ownership?)

	// Note: We don't check listing ownership here, assuming the user provides an ID they own.
	// The generated key includes the userID, providing some namespacing.

	ctx := c.Request.Context()
	presignedURL, objectKey, err := h.storageService.GeneratePresignedPutURL(ctx,
		userIDHex,
		reqArgs.ListingID,
		reqArgs.Filename,
		reqArgs.ContentType,
	)
	if err != nil {
		log.Printf("Error generating presigned URL for user %s, listing %s: %v", userIDHex, reqArgs.ListingID, err)
		return nil, NewApiError("Failed to generate upload URL")
	}

	// Return the URL and the generated key (client needs key for confirmImageUpload)
	return gin.H{
		"upload_url": presignedURL,
		"object_key": objectKey,
	}, nil
}

// Define structure for confirmImageUpload arguments
type ConfirmImageUploadArgs struct {
	ListingID string `json:"listing_id"`
	ObjectKey string `json:"object_key"` // The key returned by getUploadURL
	// OriginalFilename string `json:"original_filename"` // Optional: Could be useful
}

func (h *JsonApiHandler) confirmImageUpload(c *gin.Context, args json.RawMessage) (interface{}, *ApiError) {
	authInfo, ok := getAuthFromContext(c.Request.Context())
	if !ok || authInfo.UserID == nil {
		return nil, NewApiError("Authentication required")
	}
	userIDHex := authInfo.UserID.String()

	var reqArgs ConfirmImageUploadArgs
	if apiErr := h.parseRequiredSingleArgFromArray(args, &reqArgs); apiErr != nil {
		return nil, apiErr
	}

	if reqArgs.ListingID == "" || reqArgs.ObjectKey == "" {
		return nil, NewApiError("Missing required arguments (listing_id, object_key)")
	}

	listingID, err := utils.ParseSixID(reqArgs.ListingID)
	if err != nil {
		return nil, NewApiError("Invalid listing_id format")
	}

	ctx := c.Request.Context()

	// 1. TODO: Verify user owns the listing
	log.Printf("[TODO] Need to verify user %s owns listing %s in confirmImageUpload", userIDHex, listingID.String())

	// 2. Optional: Check if objectKey seems valid / exists in S3 using HeadObject?

	// 3. Enqueue image processing task
	payloadBytes, _ := json.Marshal(tasks.ImageTaskPayload{
		S3Key:     reqArgs.ObjectKey,
		ListingID: reqArgs.ListingID, // Pass listing ID (as hex string) to task
	})
	task := asynq.NewTask(tasks.TypeImageProcess, payloadBytes, asynq.Queue("images")) // Use dedicated queue

	taskInfo, err := h.taskClient.EnqueueContext(ctx, task)
	if err != nil {
		log.Printf("ERROR enqueuing image processing task for key %s, listing %s: %v", reqArgs.ObjectKey, reqArgs.ListingID, err)
		return nil, NewApiError("Failed to schedule image processing")
	}

	log.Printf("Enqueued image processing task ID %s for key %s, listing %s", taskInfo.ID, reqArgs.ObjectKey, reqArgs.ListingID)

	// Return success (processing happens in background)
	return gin.H{
		"message": "Image upload confirmed, processing scheduled.",
		"task_id": taskInfo.ID, // Optionally return task ID for status checks
	}, nil
}

// TODO: Implement getImageStatus

// Define structure for sendEnquiry arguments
type SendEnquiryArgs struct {
	ListingID string              `json:"listing_id"`
	UserEmail string              `json:"user_email"` // Required reply-to
	Message   string              `json:"message"`
	Offer     *models.AskingPrice `json:"offer"`
}

func (h *JsonApiHandler) sendEnquiry(c *gin.Context, args json.RawMessage) (interface{}, *ApiError) {
	authInfo, _ := getAuthFromContext(c.Request.Context()) // Auth is optional for this method

	var reqArgs SendEnquiryArgs
	if apiErr := h.parseRequiredSingleArgFromArray(args, &reqArgs); apiErr != nil {
		return nil, apiErr
	}

	ctx := c.Request.Context() // Define ctx at the start

	// Validation
	listingID, err := utils.ParseSixID(reqArgs.ListingID)
	if err != nil {
		return nil, NewApiError("Invalid listing_id format")
	}
	if !emailRegex.MatchString(reqArgs.UserEmail) {
		return nil, NewApiError("Invalid user_email format")
	}
	if strings.TrimSpace(reqArgs.Message) == "" && reqArgs.Offer == nil {
		return nil, NewApiError("Enquiry must contain a message or an offer amount")
	}
	// TODO: More validation? Max message length? Offer amount > 0? Currency validation?

	// Check if listing exists and is active/visible
	listing, err := h.listingService.FindListingByID(ctx, listingID)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, NewApiError("Listing not found")
		}
		log.Printf("DB error finding listing %s for enquiry: %v", reqArgs.ListingID, err)
		return nil, NewApiError("Failed to retrieve listing")
	}

	var senderUserID *utils.SixID
	if authInfo != nil && authInfo.UserID != nil {
		senderUserID = authInfo.UserID
	}

	// Create the enquiry document
	newEnquiry, err := h.enquiryService.CreateEnquiry(ctx, listingID, senderUserID, reqArgs.UserEmail, reqArgs.Message, reqArgs.Offer)
	if err != nil {
		log.Printf("Error creating enquiry for listing %s: %v", reqArgs.ListingID, err)
		return nil, NewApiError("Failed to save enquiry")
	}

	// Enqueue task to send email to listing owner
	owner, err := h.userService.FindByID(ctx, listing.UserID)
	if err != nil {
		log.Printf("Error fetching owner %s for listing %s to send enquiry email: %v", listing.UserID.String(), listingID.String(), err)
		return gin.H{"message": "Enquiry saved, but notification could not be sent."}, nil
	}

	// 2. Check notification preferences
	sendEmail := false
	if owner.NotificationPreferences != nil {
		if reqArgs.Offer != nil && owner.NotificationPreferences.Offer {
			sendEmail = true
		} else if reqArgs.Offer == nil && owner.NotificationPreferences.Enquiry {
			sendEmail = true
		}
	}

	if sendEmail {
		// 3. Build email payload
		// TODO: Define specific fields needed by the "new_enquiry" template
		// Example data points:
		mailData := map[string]interface{}{
			"enquiry_id":      newEnquiry.ID.String(),
			"enquiry_message": newEnquiry.Message,
			"enquiry_email":   newEnquiry.UserEmail,
			"listing_id":      listing.ID.String(),
			"listing_title":   listing.Title,
			"listing_url":     fmt.Sprintf("/listings/%s", listing.ID.String()), // TODO: Use config for base URL?
			"owner_name":      owner.Name,
		}
		if newEnquiry.Offer != nil {
			mailData["offer_value"] = newEnquiry.Offer.Value
			mailData["offer_currency"] = newEnquiry.Offer.CurrencyCode
		}
		if senderUserID != nil {
			mailData["sender_user_id"] = senderUserID.String()
		}

		payloadBytes, _ := json.Marshal(tasks.EmailTaskPayload{
			To:         owner.Email,   // Send to listing owner
			TemplateID: "new_enquiry", // Needs template in DB
			Data:       mailData,
		})
		task := asynq.NewTask(tasks.TypeEmailDelivery, payloadBytes)
		if _, enqueueErr := h.taskClient.EnqueueContext(ctx, task); enqueueErr != nil {
			log.Printf("ERROR enqueuing new enquiry email task for listing %s, enquiry %s: %v", listingID.String(), newEnquiry.ID.String(), enqueueErr)
			// Don't fail request, enquiry is saved.
		} else {
			log.Printf("Enqueued new enquiry email task for listing %s", listingID.String())
		}
	}

	return gin.H{"message": "Enquiry sent successfully."}, nil
}

// Define structure for startDomainValidation arguments
type StartDomainValidationArgs struct {
	TypeID     string `json:"type_id"` // ID of the UserValidationType (must be domain type)
	DomainName string `json:"domain_name"`
}

func (h *JsonApiHandler) startDomainValidation(c *gin.Context, args json.RawMessage) (interface{}, *ApiError) {
	authInfo, ok := getAuthFromContext(c.Request.Context())
	if !ok || authInfo.UserID == nil {
		return nil, NewApiError("Authentication required")
	}

	var reqArgs StartDomainValidationArgs
	if apiErr := h.parseRequiredSingleArgFromArray(args, &reqArgs); apiErr != nil {
		return nil, apiErr
	}

	typeID, err := utils.ParseSixID(reqArgs.TypeID)
	if err != nil {
		return nil, NewApiError("Invalid type_id format")
	}
	if strings.TrimSpace(reqArgs.DomainName) == "" {
		return nil, NewApiError("domain_name cannot be empty")
	}
	// TODO: Add domain name format validation

	ctx := c.Request.Context()
	validation, err := h.userValidationService.CreateDomainValidation(ctx, *authInfo.UserID, typeID, reqArgs.DomainName)
	if err != nil {
		log.Printf("Error starting domain validation for user %s, domain %s: %v", authInfo.UserID.String(), reqArgs.DomainName, err)
		if strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "not for domain ownership") {
			return nil, NewApiError(err.Error())
		}
		return nil, NewApiError("Failed to start domain validation")
	}

	// Return the details needed by the user, specifically the value they need to prove
	return gin.H{
		"validation_id":  validation.ID.String(),
		"value_to_prove": validation.ValueToProve,
		"message":        "Validation started. Add the 'value_to_prove' as a TXT record to your domain.",
	}, nil
}

// Define structure for startOnlineProfileValidation arguments
type StartOnlineProfileValidationArgs struct {
	TypeID    string `json:"type_id"`    // ID of the UserValidationType (must be online_profile type)
	ProfileID string `json:"profile_id"` // User's ID on the external platform (e.g., username, numeric ID)
}

func (h *JsonApiHandler) startOnlineProfileValidation(c *gin.Context, args json.RawMessage) (interface{}, *ApiError) {
	authInfo, ok := getAuthFromContext(c.Request.Context())
	if !ok || authInfo.UserID == nil {
		return nil, NewApiError("Authentication required")
	}

	var reqArgs StartOnlineProfileValidationArgs
	if apiErr := h.parseRequiredSingleArgFromArray(args, &reqArgs); apiErr != nil {
		return nil, apiErr
	}

	typeID, err := utils.ParseSixID(reqArgs.TypeID)
	if err != nil {
		return nil, NewApiError("Invalid type_id format")
	}
	if strings.TrimSpace(reqArgs.ProfileID) == "" {
		return nil, NewApiError("profile_id cannot be empty")
	}

	ctx := c.Request.Context()
	validation, err := h.userValidationService.CreateOnlineProfileValidation(ctx, *authInfo.UserID, typeID, reqArgs.ProfileID)
	if err != nil {
		log.Printf("Error starting online profile validation for user %s, profile %s: %v", authInfo.UserID.String(), reqArgs.ProfileID, err)
		if strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "not for online profiles") {
			return nil, NewApiError(err.Error())
		}
		return nil, NewApiError("Failed to start profile validation")
	}

	// Fetch the type again to get instructions (or include instructions in Create result?)
	valType, _ := h.userValidationService.GetValidationTypeByID(ctx, typeID)
	instructions := "Place the value provided on your profile."
	if valType != nil && valType.Config != nil {
		if instr, ok := valType.Config["user_instructions"].(string); ok {
			// Basic replacement, consider safer templating
			instructions = strings.Replace(instr, "{profile_id}", reqArgs.ProfileID, -1)
		}
	}

	return gin.H{
		"validation_id":  validation.ID.String(),
		"value_to_prove": validation.ValueToProve,
		"instructions":   instructions,
	}, nil
}

func (h *JsonApiHandler) listValidationTypes(c *gin.Context, args json.RawMessage) (interface{}, *ApiError) {
	_ = args // Explicitly ignore unused args
	// Auth check for listValidationTypes should be configured in methodRequiresAuth
	// Assuming it's public or auth handled by checkAuthForMethod and result placed in context.
	// If it needs specific auth checks, they should be here or via methodRequiresAuth.
	ctx := c.Request.Context()
	types, err := h.userValidationService.GetValidationTypes(ctx)
	if err != nil {
		log.Printf("Error fetching validation types: %v", err)
		return nil, NewApiError("Failed to retrieve validation types")
	}
	// Return the list of types (consider filtering fields?)
	return types, nil
}

// --- Admin Methods ---

// Helper to parse User ID argument
func parseUserIDArg(args json.RawMessage) (utils.SixID, *ApiError) {
	var userIDHex string
	// This helper expects args to be the direct user ID string, not an array.
	// For methods using single arg from array, they call parseRequiredSingleArgFromArray directly.
	if err := json.Unmarshal(args, &userIDHex); err != nil {
		return utils.SixID{}, NewApiError("Invalid arguments: expected User ID string")
	}
	userID, err := utils.ParseSixID(userIDHex)
	if err != nil {
		return utils.SixID{}, NewApiError("Invalid user_id format")
	}
	return userID, nil
}

func (h *JsonApiHandler) suspendUser(c *gin.Context, args json.RawMessage) (interface{}, *ApiError) {
	authInfo, ok := getAuthFromContext(c.Request.Context())
	if !ok || authInfo.UserID == nil || !authInfo.IsAdmin {
		return nil, NewApiError("Administrator privileges required")
	}
	adminUserID := authInfo.UserID

	var userIDToSuspendHex string
	if apiErr := h.parseRequiredSingleArgFromArray(args, &userIDToSuspendHex); apiErr != nil {
		return nil, apiErr
	}
	userIDToSuspend, err := utils.ParseSixID(userIDToSuspendHex)
	if err != nil {
		return nil, NewApiError("Invalid user_id format in argument")
	}

	ctx := c.Request.Context()
	err = h.userService.SuspendUser(ctx, userIDToSuspend, *adminUserID)
	if err != nil {
		log.Printf("Error suspending user %s by admin %s: %v", userIDToSuspend.String(), adminUserID.String(), err)
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, NewApiError("User not found")
		} else if strings.Contains(err.Error(), "cannot suspend themselves") {
			return nil, NewApiError(err.Error())
		}
		return nil, NewApiError("Failed to suspend user")
	}
	return nil, nil // Success
}

func (h *JsonApiHandler) unSuspendUser(c *gin.Context, args json.RawMessage) (interface{}, *ApiError) {
	authInfo, ok := getAuthFromContext(c.Request.Context())
	if !ok || !authInfo.IsAdmin {
		return nil, NewApiError("Administrator privileges required")
	}

	var userIDToUnsuspendHex string
	if apiErr := h.parseRequiredSingleArgFromArray(args, &userIDToUnsuspendHex); apiErr != nil {
		return nil, apiErr
	}
	userIDToUnsuspend, err := utils.ParseSixID(userIDToUnsuspendHex)
	if err != nil {
		return nil, NewApiError("Invalid user_id format in argument")
	}

	ctx := c.Request.Context()
	err = h.userService.UnsuspendUser(ctx, userIDToUnsuspend)
	if err != nil {
		log.Printf("Error unsuspending user %s: %v", userIDToUnsuspend.String(), err)
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, NewApiError("User not found")
		}
		return nil, NewApiError("Failed to unsuspend user")
	}
	return nil, nil // Success
}

func (h *JsonApiHandler) suspendListing(c *gin.Context, args json.RawMessage) (interface{}, *ApiError) {
	authInfo, ok := getAuthFromContext(c.Request.Context())
	if !ok || !authInfo.IsAdmin || authInfo.UserID == nil {
		return nil, NewApiError("Administrator privileges required")
	}
	var input struct {
		ListingID string `json:"listing_id"`
		Reason    string `json:"reason"`
	}
	if apiErr := h.parseRequiredSingleArgFromArray(args, &input); apiErr != nil {
		return nil, apiErr
	}

	listingID, err := utils.ParseSixID(input.ListingID)
	if err != nil {
		return nil, NewApiError("Invalid listing_id format")
	}
	ctx := c.Request.Context()
	err = h.listingService.SuspendListing(ctx, listingID, *authInfo.UserID, input.Reason)
	if err != nil {
		return nil, NewApiError(err.Error())
	}
	return nil, nil
}

func (h *JsonApiHandler) unsuspendListing(c *gin.Context, args json.RawMessage) (interface{}, *ApiError) {
	authInfo, ok := getAuthFromContext(c.Request.Context())
	if !ok || !authInfo.IsAdmin || authInfo.UserID == nil {
		return nil, NewApiError("Administrator privileges required")
	}

	var listingIDHex string
	if apiErr := h.parseRequiredSingleArgFromArray(args, &listingIDHex); apiErr != nil {
		return nil, apiErr
	}
	listingID, err := utils.ParseSixID(listingIDHex)
	if err != nil {
		return nil, NewApiError("Invalid listing_id format in argument")
	}

	ctx := c.Request.Context()
	err = h.listingService.UnsuspendListing(ctx, listingID, *authInfo.UserID)
	if err != nil {
		return nil, NewApiError(err.Error())
	}
	return nil, nil
}

func (h *JsonApiHandler) startChangingEmail(c *gin.Context, args json.RawMessage) (interface{}, *ApiError) {
	authInfo, ok := getAuthFromContext(c.Request.Context())
	if !ok || authInfo.UserID == nil {
		return nil, NewApiError("Authentication required")
	}

	var newEmail string
	if apiErr := h.parseRequiredSingleArgFromArray(args, &newEmail); apiErr != nil {
		return nil, apiErr
	}
	if !emailRegex.MatchString(newEmail) {
		return nil, NewApiError("Invalid new email")
	}

	ctx := c.Request.Context()

	// 1. Fetch current user details to get the old email address and check if new email is the same
	currentUser, userErr := h.userService.FindByID(ctx, *authInfo.UserID)
	if userErr != nil {
		log.Printf("ERROR: Could not fetch user %s for starting email change: %v", authInfo.UserID.String(), userErr)
		return nil, NewApiError("Failed to retrieve user details") // Changed: Return error
	}

	// 3. Verify if the new email address is in fact the current one.
	if newEmail == currentUser.Email {
		return "same", nil // Return "same"
	}

	// 1. Call the service - it now returns the created actions
	oldAction, newAction, err := h.userService.RequestEmailChange(ctx, *authInfo.UserID, newEmail)
	if err != nil {
		log.Printf("Error requesting email change for user %s: %v", authInfo.UserID.String(), err)
		if errors.Is(err, services.ErrEmailExists) { // Changed to use errors.Is with the sentinel error
			return "exists", nil
		}
		return nil, NewApiError("Failed to start email change process")
	}

	// 3. Enqueue email task for old email (approve)
	payloadOldBytes, _ := json.Marshal(tasks.EmailTaskPayload{
		To:         currentUser.Email, // Send to OLD email
		TemplateID: "email_change_approve",
		Data:       map[string]interface{}{"action_id": oldAction.ID.String()}, // Crockford Base32
	})
	taskOld := asynq.NewTask(tasks.TypeEmailDelivery, payloadOldBytes)
	if _, enqueueErr := h.taskClient.EnqueueContext(ctx, taskOld); enqueueErr != nil {
		log.Printf("ERROR enqueuing email_change_approve email for user %s: %v", authInfo.UserID.String(), enqueueErr)
		// If email enqueue fails, should we roll back or still inform user?
		// For now, proceed and let user know, but log critical error.
		// Consider returning a more specific error or a partial success message.
	}

	// 4. Enqueue email task for new email (confirm)
	payloadNewBytes, _ := json.Marshal(tasks.EmailTaskPayload{
		To:         newEmail, // Send to NEW email
		TemplateID: "email_change_confirm",
		Data:       map[string]interface{}{"action_id": newAction.ID.String()}, // Crockford Base32
	})
	taskNew := asynq.NewTask(tasks.TypeEmailDelivery, payloadNewBytes)
	if _, enqueueErr := h.taskClient.EnqueueContext(ctx, taskNew); enqueueErr != nil {
		log.Printf("ERROR enqueuing email_change_confirm email for user %s: %v", authInfo.UserID.String(), enqueueErr)
	}

	return true, nil // Changed: Return true on success
}

func (h *JsonApiHandler) finalizeEmailChange(c *gin.Context) (interface{}, *ApiError) {
	authInfo, ok := getAuthFromContext(c.Request.Context())
	if !ok || authInfo.UserID == nil {
		return nil, NewApiError("Authentication required")
	}
	ctx := c.Request.Context()
	err := h.userService.FinalizeEmailChange(ctx, *authInfo.UserID)
	if err != nil {
		return nil, NewApiError("Failed to finalize email change")
	}
	return gin.H{"message": "Email change finalized"}, nil
}

func (h *JsonApiHandler) setOTPSecret(c *gin.Context, args json.RawMessage) (interface{}, *ApiError) {
	authInfo, ok := getAuthFromContext(c.Request.Context())
	if !ok || authInfo.UserID == nil {
		return nil, NewApiError("Authentication required")
	}

	var otpSecret string
	if apiErr := h.parseRequiredSingleArgFromArray(args, &otpSecret); apiErr != nil {
		return nil, apiErr
	}
	if otpSecret == "" {
		return nil, NewApiError("Invalid OTP secret: cannot be empty")
	}
	ctx := c.Request.Context()
	err := h.userService.SetOTPSecret(ctx, *authInfo.UserID, otpSecret)
	if err != nil {
		return nil, NewApiError("Failed to set OTP secret")
	}
	return gin.H{"message": "OTP secret set"}, nil
}

func (h *JsonApiHandler) addWebAuthnCredential(c *gin.Context, args json.RawMessage) (interface{}, *ApiError) {
	authInfo, ok := getAuthFromContext(c.Request.Context())
	if !ok || authInfo.UserID == nil {
		return nil, NewApiError("Authentication required")
	}

	var cred models.WebAuthnCredential
	if apiErr := h.parseRequiredSingleArgFromArray(args, &cred); apiErr != nil {
		return nil, apiErr
	}
	if cred.CredentialID == "" || cred.PublicKey == "" {
		return nil, NewApiError("Invalid WebAuthn credential: missing fields")
	}
	ctx := c.Request.Context()
	err := h.userService.AddWebAuthnCredential(ctx, *authInfo.UserID, cred)
	if err != nil {
		return nil, NewApiError("Failed to add WebAuthn credential")
	}
	return gin.H{"message": "WebAuthn credential added"}, nil
}

func (h *JsonApiHandler) removeWebAuthnCredential(c *gin.Context, args json.RawMessage) (interface{}, *ApiError) {
	authInfo, ok := getAuthFromContext(c.Request.Context())
	if !ok || authInfo.UserID == nil {
		return nil, NewApiError("Authentication required")
	}

	var credentialID string
	if apiErr := h.parseRequiredSingleArgFromArray(args, &credentialID); apiErr != nil {
		return nil, apiErr
	}
	if credentialID == "" {
		return nil, NewApiError("Invalid credential ID: cannot be empty")
	}
	ctx := c.Request.Context()
	err := h.userService.RemoveWebAuthnCredential(ctx, *authInfo.UserID, credentialID)
	if err != nil {
		return nil, NewApiError("Failed to remove WebAuthn credential")
	}
	return gin.H{"message": "WebAuthn credential removed"}, nil
}

// Handler for getOutstandingCharges
func (h *JsonApiHandler) getOutstandingCharges(c *gin.Context, args json.RawMessage) (interface{}, *ApiError) {
	authInfo, ok := getAuthFromContext(c.Request.Context())
	if !ok || authInfo.UserID == nil {
		return nil, NewApiError("Authentication required")
	}
	ctx := c.Request.Context()
	amount, lineItems, err := h.billingService.CalculateChargesForUser(ctx, *authInfo.UserID)
	if err != nil {
		return nil, NewApiError("Failed to calculate outstanding charges")
	}
	return map[string]interface{}{
		"amount":     amount,
		"line_items": lineItems,
	}, nil
}

// Handler for generateInvoice
func (h *JsonApiHandler) generateInvoice(c *gin.Context, args json.RawMessage) (interface{}, *ApiError) {
	authInfo, ok := getAuthFromContext(c.Request.Context())
	if !ok || authInfo.UserID == nil {
		return nil, NewApiError("Authentication required")
	}

	ctx := c.Request.Context()
	amount, lineItems, err := h.billingService.CalculateChargesForUser(ctx, *authInfo.UserID)
	if err != nil {
		return nil, NewApiError("Failed to calculate outstanding charges")
	}
	if amount == 0 || len(lineItems) == 0 {
		return nil, NewApiError("No outstanding charges to invoice")
	}
	invoice, err := h.billingService.GenerateInvoice(ctx, *authInfo.UserID, lineItems, amount, "USD") // TODO: currency
	if err != nil {
		return nil, NewApiError("Failed to generate invoice")
	}
	return invoice, nil
}

// Handler for listOverdueInvoices (admin only)
func (h *JsonApiHandler) listOverdueInvoices(c *gin.Context, args json.RawMessage) (interface{}, *ApiError) {
	_ = args // Explicitly ignore unused args
	authInfo, ok := getAuthFromContext(c.Request.Context())
	if !ok || !authInfo.IsAdmin {
		return nil, NewApiError("Admin privileges required")
	}

	ctx := c.Request.Context()
	invoices, err := h.billingService.FindOverdueInvoices(ctx)
	if err != nil {
		return nil, NewApiError("Failed to retrieve overdue invoices")
	}
	return invoices, nil
}

// Handler for markInvoiceOverdueNotified (admin only)
type MarkInvoiceOverdueNotifiedArgs struct {
	InvoiceID string `json:"invoice_id"`
}

func (h *JsonApiHandler) markInvoiceOverdueNotified(c *gin.Context, args json.RawMessage) (interface{}, *ApiError) {
	authInfo, ok := getAuthFromContext(c.Request.Context())
	if !ok || !authInfo.IsAdmin {
		return nil, NewApiError("Admin privileges required")
	}

	var reqArgs MarkInvoiceOverdueNotifiedArgs
	if apiErr := h.parseRequiredSingleArgFromArray(args, &reqArgs); apiErr != nil {
		return nil, apiErr
	}
	invoiceID, err := utils.ParseSixID(reqArgs.InvoiceID)
	if err != nil {
		return nil, NewApiError("Invalid invoice_id format")
	}
	ctx := c.Request.Context()
	err = h.billingService.MarkInvoiceOverdueNotified(ctx, invoiceID)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, NewApiError("Invoice not found")
		}
		return nil, NewApiError("Failed to mark invoice as notified")
	}
	return true, nil
}

// Helper function to create email login code action and enqueue email task
func (h *JsonApiHandler) sendLoginCodeEmail(ctx context.Context, userID utils.SixID, email string) error {
	// Create the specific action type for email login code
	// TODO: Need CreateEmailLoginCodeAction in ILinkedActionService. Using CreateLoginToSetupAction as placeholder.
	loginAction, err := h.linkedActionService.CreateLoginToSetupAction(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to create email login code action: %w", err)
	}

	// Enqueue the email
	payloadBytes, _ := json.Marshal(tasks.EmailTaskPayload{
		To:         email,
		TemplateID: "email_login_code",                                           // Needs template
		Data:       map[string]interface{}{"action_id": loginAction.ID.String()}, // Crockford Base32 SixID code
	})
	task := asynq.NewTask(tasks.TypeEmailDelivery, payloadBytes)
	if _, enqueueErr := h.taskClient.EnqueueContext(ctx, task); enqueueErr != nil {
		// Log error, but maybe don't fail the whole login step?
		return fmt.Errorf("failed to enqueue login code email task: %w", enqueueErr)
	}
	return nil
}

// requestAccountDeletion handles the request to start account deletion.
func (h *JsonApiHandler) requestAccountDeletion(c *gin.Context, args json.RawMessage) (interface{}, *ApiError) {
	_ = args // Explicitly ignore unused args
	authInfo, ok := getAuthFromContext(c.Request.Context())
	if !ok || authInfo.UserID == nil {
		return nil, NewApiError("Authentication required")
	}

	ctx := c.Request.Context()

	// 1. Create the confirmation linked action
	deletionAction, err := h.linkedActionService.CreateConfirmAccountDeletionAction(ctx, *authInfo.UserID)
	if err != nil {
		log.Printf("Error creating account deletion action for user %s: %v", authInfo.UserID.String(), err)
		return nil, NewApiError("Failed to start account deletion process")
	}

	// 2. Fetch user to get email address
	user, err := h.userService.FindByID(ctx, *authInfo.UserID)
	if err != nil {
		log.Printf("Error fetching user %s for account deletion email: %v", authInfo.UserID.String(), err)
		// Action created, but email failed. Return success? Or error?
		return gin.H{"message": "Account deletion process started, notification failed."}, nil
	}

	// 3. Enqueue email task
	payloadBytes, _ := json.Marshal(tasks.EmailTaskPayload{
		To:         user.Email,
		TemplateID: "confirm_account_deletion",
		Data:       map[string]interface{}{"action_id": deletionAction.ID.String()}, // Crockford Base32
	})
	task := asynq.NewTask(tasks.TypeEmailDelivery, payloadBytes)
	if _, enqueueErr := h.taskClient.EnqueueContext(ctx, task); enqueueErr != nil {
		log.Printf("ERROR enqueuing confirm_account_deletion email for user %s: %v", authInfo.UserID.String(), enqueueErr)
		// Return success anyway?
		return gin.H{"message": "Account deletion process started, notification failed."}, nil
	}

	log.Printf("Account deletion confirmation email enqueued for user %s", user.ID.String()) // Will use Crockford Base32 for action ID
	return gin.H{"message": "Confirmation email sent. Click the link to permanently delete your account."}, nil
}

// --- getLocationByCoords ---

// GetLocationByCoordsArgs defines the structure for getLocationByCoords arguments
type GetLocationByCoordsArgs struct {
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
}

// getLocationByCoords handles the "getLocationByCoords" API method.
// It fetches a location by geographic coordinates and returns it using the shared models.LocationAPIResponse.
func (h *JsonApiHandler) getLocationByCoords(c *gin.Context, args json.RawMessage) (interface{}, *ApiError) {
	var reqArgs GetLocationByCoordsArgs
	if apiErr := h.parseRequiredSingleArgFromArray(args, &reqArgs); apiErr != nil {
		return nil, apiErr
	}

	ctxReq := c.Request.Context() // Use a different name for clarity

	// Find the closest location using the location service
	// Assuming locationService has a method like FindLocationByCoords
	// This part of the logic might need adjustment based on actual service capabilities.
	// For now, let's assume it returns a *models.Location or an error.
	// The user's diff shows direct DB access here, so we'll keep that pattern.
	var dbLocation models.Location // Changed to models.Location to correctly unmarshal
	err := h.db.Collection("locations").FindOne(
		ctxReq, // Use the request context
		bson.M{
			"location": bson.M{
				"$nearSphere": bson.M{
					"$geometry": bson.M{
						"type":        "Point",
						"coordinates": []float64{reqArgs.Longitude, reqArgs.Latitude},
					},
					// "$maxDistance": // Optional: if you want to limit search radius
				},
			},
		},
		options.FindOne(), // Add options if needed, e.g., projection
	).Decode(&dbLocation) // Decode directly into models.Location

	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, NewApiError("No location found for the given coordinates")
		}
		log.Printf("Error finding location by coords (%f, %f): %v", reqArgs.Latitude, reqArgs.Longitude, err)
		return nil, NewApiError("Failed to search for location by coordinates")
	}

	// Format the result using the shared LocationAPIResponse struct
	apiResponse := models.LocationAPIResponse{
		ID:          fmt.Sprintf("%d", dbLocation.ID),
		Name:        dbLocation.Name,
		CountryCode: dbLocation.CountryCode,
		Context:     models.FormatContext(dbLocation.Context),
	}

	if dbLocation.Location != nil && len(dbLocation.Location.Coordinates) == 2 {
		apiResponse.Coordinates = dbLocation.Location.Coordinates
	}

	return apiResponse, nil
}

// parseRequiredSingleArgFromArray takes the raw JSON message for 'arguments',
// expects it to be a JSON array with at least one element,
// and unmarshals that first element into targetVarPtr.
func (h *JsonApiHandler) parseRequiredSingleArgFromArray(rawArgPayload json.RawMessage, targetVarPtr interface{}) *ApiError {
	var argArray []json.RawMessage
	if rawArgPayload == nil { // 'arguments' field was not provided
		return NewApiError("Missing 'arguments' field; expected a JSON array with one argument.")
	}

	if err := json.Unmarshal(rawArgPayload, &argArray); err != nil {
		// 'arguments' was present but wasn't a valid JSON array
		return NewApiError("Invalid 'arguments': expected a JSON array.")
	}

	if len(argArray) == 0 {
		// 'arguments' was '[]'
		return NewApiError("Invalid 'arguments': array is empty, but one argument is expected.")
	}

	actualArgData := argArray[0] // Get the first element
	if err := json.Unmarshal(actualArgData, targetVarPtr); err != nil {
		// The first element of the array was not of the expected type
		// Provide a more generic error as err.Error() might contain sensitive details or be too verbose for API response.
		return NewApiError("Invalid format for argument: the first element in 'arguments' array has unexpected structure.")
	}
	return nil
}

// ChangePasswordArgs defines the arguments for the changePassword method
type ChangePasswordArgs struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

// changePassword handles password changes for authenticated users
func (h *JsonApiHandler) changePassword(c *gin.Context, args json.RawMessage) (interface{}, *ApiError) {
	authInfo, ok := getAuthFromContext(c.Request.Context())
	if !ok || authInfo.UserID == nil {
		return nil, NewApiError("Authentication required to change password")
	}

	// Parse arguments as array of strings (as per previous implementation for this method)
	var passwords []string
	// The 'args' for changePassword is expected to be a direct JSON array of two strings,
	// not an array containing another array/object as the first element.
	if err := json.Unmarshal(args, &passwords); err != nil {
		// If args is `["old", "new"]`, this Unmarshal is correct.
		// If args is `[["old", "new"]]`, then parseRequiredSingleArgFromArray would be needed for the outer array,
		// and then another unmarshal for the inner `passwords` array.
		// Based on how other single-arg methods are handled, and the error messages,
		// it's likely the changePassword arguments are directly the array `["old", "new"]`.
		return nil, NewApiError("Invalid arguments: expected array of two strings [current_password, new_password]")
	}

	// Validate array length
	if len(passwords) != 2 {
		return nil, NewApiError("Expected array with exactly 2 elements: [current_password, new_password]")
	}

	currentPassword := passwords[0]
	newPassword := passwords[1]

	// Get user from database
	user, err := h.userService.FindByID(c.Request.Context(), *authInfo.UserID)
	if err != nil {
		return nil, NewApiError("Failed to retrieve user")
	}

	// Check if user has password-based auth
	if user.AuthType != models.AuthTypePasswordOnly &&
		user.AuthType != models.AuthTypePasswordAndOTP &&
		user.AuthType != models.AuthTypePasswordAndEmailLoginCode {
		return nil, NewApiError("Password is not set for this account")
	}

	// Verify current password
	if !auth.CheckPasswordHash(currentPassword, user.PasswordHash) {
		// According to common API practice, "false" indicates wrong current password.
		return false, nil // Success: true, Data: false
	}

	// Update password using SetUserCredentials
	err = h.userService.SetUserCredentials(c.Request.Context(), user.ID, user.AuthType, newPassword)
	if err != nil {
		return nil, NewApiError("Failed to update password")
	}

	return true, nil // Success: true, Data: true
}
