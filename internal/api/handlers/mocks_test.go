package handlers_test

import (
	"context"
	"github.com/hibiken/asynq"
	"github.com/stretchr/testify/mock"
	"greendrake/l1/internal/models"
	"greendrake/l1/internal/services"
	"greendrake/l1/internal/utils"
	"time"
)

// --- Mocks ---

// MockUserService
type MockUserService struct {
	mock.Mock
}

func (m *MockUserService) FindByEmail(ctx context.Context, email string) (*models.User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}
func (m *MockUserService) CreatePhantomUser(ctx context.Context, email string) (*models.User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}
func (m *MockUserService) SetUserCredentials(ctx context.Context, userID utils.SixID, authType models.AuthType, password string) error {
	args := m.Called(ctx, userID, authType, password)
	return args.Error(0)
}
func (m *MockUserService) FindByID(ctx context.Context, userID utils.SixID) (*models.User, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserService) GetAllActiveUserIDs(ctx context.Context) ([]utils.SixID, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]utils.SixID), args.Error(1)
}

func (m *MockUserService) GetAllPhantomUserIDs(ctx context.Context) ([]utils.SixID, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]utils.SixID), args.Error(1)
}

func (m *MockUserService) DeleteUserAndListings(ctx context.Context, userID utils.SixID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockUserService) SuspendUser(ctx context.Context, userIDToSuspend, adminUserID utils.SixID) error {
	args := m.Called(ctx, userIDToSuspend, adminUserID)
	return args.Error(0)
}

func (m *MockUserService) UnsuspendUser(ctx context.Context, userIDToUnsuspend utils.SixID) error {
	args := m.Called(ctx, userIDToUnsuspend)
	return args.Error(0)
}

func (m *MockUserService) RequestEmailChange(ctx context.Context, userID utils.SixID, newEmail string) (oldAction *models.LinkedAction, newAction *models.LinkedAction, err error) {
	args := m.Called(ctx, userID, newEmail)
	// Handle potential nil returns for actions
	if args.Get(0) != nil {
		oldAction = args.Get(0).(*models.LinkedAction)
	}
	if args.Get(1) != nil {
		newAction = args.Get(1).(*models.LinkedAction)
	}
	return oldAction, newAction, args.Error(2)
}

func (m *MockUserService) ApproveEmailChangeOld(ctx context.Context, userID utils.SixID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockUserService) ConfirmEmailChangeNew(ctx context.Context, userID utils.SixID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockUserService) FinalizeEmailChange(ctx context.Context, userID utils.SixID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockUserService) SetOTPSecret(ctx context.Context, userID utils.SixID, otpSecret string) error {
	args := m.Called(ctx, userID, otpSecret)
	return args.Error(0)
}

func (m *MockUserService) AddWebAuthnCredential(ctx context.Context, userID utils.SixID, cred models.WebAuthnCredential) error {
	args := m.Called(ctx, userID, cred)
	return args.Error(0)
}

func (m *MockUserService) RemoveWebAuthnCredential(ctx context.Context, userID utils.SixID, credentialID string) error {
	args := m.Called(ctx, userID, credentialID)
	return args.Error(0)
}

func (m *MockUserService) SetLinkedActionService(las services.ILinkedActionService) {
	m.Called(las)
	// This method is often used for setup and might not have a return value to assert against.
	// If it were to return an error or some other value, you'd handle it like other mock methods.
}

// MockLinkedActionService
type MockLinkedActionService struct {
	mock.Mock
}

func (m *MockLinkedActionService) CreateLoginToSetupAction(ctx context.Context, userID utils.SixID) (*models.LinkedAction, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.LinkedAction), args.Error(1)
}
func (m *MockLinkedActionService) CreateResetAccessAction(ctx context.Context, userID utils.SixID) (*models.LinkedAction, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.LinkedAction), args.Error(1)
}
func (m *MockLinkedActionService) FindAndValidateAction(ctx context.Context, actionIDStr string, expectedUserID *utils.SixID) (*models.LinkedAction, error) {
	args := m.Called(ctx, actionIDStr, expectedUserID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.LinkedAction), args.Error(1)
}
func (m *MockLinkedActionService) MarkActionExecuted(ctx context.Context, actionID utils.SixID) error {
	args := m.Called(ctx, actionID)
	return args.Error(0)
}
func (m *MockLinkedActionService) CreateEmailChangeActions(ctx context.Context, userID utils.SixID, oldEmail, newEmail string) (*models.LinkedAction, *models.LinkedAction, error) {
	args := m.Called(ctx, userID, oldEmail, newEmail)
	if args.Get(0) == nil || args.Get(1) == nil {
		return nil, nil, args.Error(2)
	}
	return args.Get(0).(*models.LinkedAction), args.Get(1).(*models.LinkedAction), args.Error(2)
}

// Added FindPendingEmailChangeActions mock
func (m *MockLinkedActionService) FindPendingEmailChangeActions(ctx context.Context, userID utils.SixID) (oldAction *models.LinkedAction, newAction *models.LinkedAction, err error) {
	args := m.Called(ctx, userID)
	if args.Get(0) != nil {
		oldAction = args.Get(0).(*models.LinkedAction)
	}
	if args.Get(1) != nil {
		newAction = args.Get(1).(*models.LinkedAction)
	}
	return oldAction, newAction, args.Error(2)
}

// Added CreateEmailLoginCodeAction mock
func (m *MockLinkedActionService) CreateEmailLoginCodeAction(ctx context.Context, userID utils.SixID) (*models.LinkedAction, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.LinkedAction), args.Error(1)
}

// Added CreateConfirmAccountDeletionAction mock
func (m *MockLinkedActionService) CreateConfirmAccountDeletionAction(ctx context.Context, userID utils.SixID) (*models.LinkedAction, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.LinkedAction), args.Error(1)
}

func (m *MockLinkedActionService) FindByID(ctx context.Context, actionID utils.SixID) (*models.LinkedAction, error) {
	args := m.Called(ctx, actionID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.LinkedAction), args.Error(1)
}

// MockListingService
type MockListingService struct {
	mock.Mock
	SearchListingsByUserFunc func(ctx context.Context, userID utils.SixID, query *string, tags []string, nearLocation *models.GeoJSON, maxDistanceKM *int, limit int, cursor *string, sortBy string) ([]*models.Listing, *string, error)
}

func (m *MockListingService) CreateListing(ctx context.Context, userID utils.SixID, title, body string, tags []string, locationID int, countryCode, shipping string, askingPrice *models.AskingPrice) (*models.Listing, error) {
	args := m.Called(ctx, userID, title, body, tags, locationID, countryCode, shipping, askingPrice)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Listing), args.Error(1)
}
func (m *MockListingService) FindListingByID(ctx context.Context, listingID utils.SixID) (*models.Listing, error) {
	args := m.Called(ctx, listingID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Listing), args.Error(1)
}
func (m *MockListingService) UpdateListing(ctx context.Context, listingID, userID utils.SixID, updates map[string]interface{}) (*models.Listing, error) {
	args := m.Called(ctx, listingID, userID, updates)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Listing), args.Error(1)
}
func (m *MockListingService) PublishListing(ctx context.Context, listingID, userID utils.SixID) error {
	args := m.Called(ctx, listingID, userID)
	return args.Error(0)
}
func (m *MockListingService) HideListing(ctx context.Context, listingID, userID utils.SixID) error {
	args := m.Called(ctx, listingID, userID)
	return args.Error(0)
}
func (m *MockListingService) UnhideListing(ctx context.Context, listingID, userID utils.SixID) error {
	args := m.Called(ctx, listingID, userID)
	return args.Error(0)
}
func (m *MockListingService) DeleteListing(ctx context.Context, listingID, userID utils.SixID) error {
	args := m.Called(ctx, listingID, userID)
	return args.Error(0)
}
func (m *MockListingService) SearchListings(ctx context.Context, query *string, countryCode *string, tags []string, nearLocation *models.GeoJSON, maxDistance *int, limit int, cursor *string, sortBy string) ([]models.Listing, string, error) {
	args := m.Called(ctx, query, countryCode, tags, nearLocation, maxDistance, limit, cursor, sortBy)
	if args.Get(0) == nil {
		return nil, args.String(1), args.Error(2)
	}
	return args.Get(0).([]models.Listing), args.String(1), args.Error(2)
}

func (m *MockListingService) AddImageToListing(ctx context.Context, listingID utils.SixID, imageKey string) error {
	args := m.Called(ctx, listingID, imageKey)
	return args.Error(0)
}

func (m *MockListingService) FindLatestListingByUserID(ctx context.Context, userID utils.SixID) (*models.Listing, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Listing), args.Error(1)
}

func (m *MockListingService) FindListingsByUserID(ctx context.Context, userID utils.SixID) ([]models.Listing, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.Listing), args.Error(1)
}

func (m *MockListingService) GetListingSuspension(ctx context.Context, listingID utils.SixID) (*models.ListingSuspension, error) {
	args := m.Called(ctx, listingID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.ListingSuspension), args.Error(1)
}

func (m *MockListingService) SuspendListing(ctx context.Context, listingID, adminUserID utils.SixID, reason string) error {
	args := m.Called(ctx, listingID, adminUserID, reason)
	return args.Error(0)
}

func (m *MockListingService) UnsuspendListing(ctx context.Context, listingID, adminUserID utils.SixID) error {
	args := m.Called(ctx, listingID, adminUserID)
	return args.Error(0)
}

func (m *MockListingService) ListSuspendedListings(ctx context.Context, limit int) ([]models.ListingSuspension, error) {
	args := m.Called(ctx, limit)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.ListingSuspension), args.Error(1)
}

func (m *MockListingService) SearchListingsByUser(ctx context.Context, userID utils.SixID, query *string, tags []string, nearLocation *models.GeoJSON, maxDistanceKM *int, limit int, cursor *string, sortBy string) ([]*models.Listing, *string, error) {
	if m.SearchListingsByUserFunc != nil {
		return m.SearchListingsByUserFunc(ctx, userID, query, tags, nearLocation, maxDistanceKM, limit, cursor, sortBy)
	}
	return nil, nil, nil
}

// MockS3Storage implements storage.IS3Storage
type MockS3Storage struct {
	mock.Mock
}

func (m *MockS3Storage) GeneratePresignedPutURL(ctx context.Context, userID, listingID, filename, contentType string) (string, string, error) {
	args := m.Called(ctx, userID, listingID, filename, contentType)
	return args.String(0), args.String(1), args.Error(2)
}

// MockEnquiryService implements services.IEnquiryService
type MockEnquiryService struct {
	mock.Mock
}

func (m *MockEnquiryService) CreateEnquiry(ctx context.Context, listingID utils.SixID, userID *utils.SixID, userEmail, message string, offer *models.AskingPrice) (*models.ListingEnquiry, error) {
	args := m.Called(ctx, listingID, userID, userEmail, message, offer)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.ListingEnquiry), args.Error(1)
}

// MockAsynqClient implements handlers.IAsynqClient
type MockAsynqClient struct {
	mock.Mock
}

func (m *MockAsynqClient) EnqueueContext(ctx context.Context, task *asynq.Task, opts ...asynq.Option) (*asynq.TaskInfo, error) {
	mockArgs := []interface{}{ctx, task}
	for _, opt := range opts {
		mockArgs = append(mockArgs, opt)
	}
	args := m.Called(mockArgs...)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*asynq.TaskInfo), args.Error(1)
}

// MockConfigService
type MockConfigService struct {
	mock.Mock
}

func (m *MockConfigService) GetAllPublic(ctx context.Context) (map[string]interface{}, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[string]interface{}), args.Error(1)
}
func (m *MockConfigService) Get(ctx context.Context, key string) (interface{}, error) {
	args := m.Called(ctx, key)
	return args.Get(0), args.Error(1)
}

// Add missing interface methods
func (m *MockConfigService) GetInt(ctx context.Context, key string, defaultValue int) int {
	args := m.Called(ctx, key, defaultValue)
	// Return mocked value or default if error/not mocked?
	if err := args.Error(1); err != nil {
		return defaultValue
	}
	return args.Int(0)
}
func (m *MockConfigService) GetString(ctx context.Context, key string, defaultValue string) string {
	args := m.Called(ctx, key, defaultValue)
	if err := args.Error(1); err != nil {
		return defaultValue
	}
	return args.String(0)
}
func (m *MockConfigService) GetBool(ctx context.Context, key string, defaultValue bool) bool {
	args := m.Called(ctx, key, defaultValue)
	if err := args.Error(1); err != nil {
		return defaultValue
	}
	return args.Bool(0)
}
func (m *MockConfigService) GetFloat64(ctx context.Context, key string, defaultValue float64) float64 {
	args := m.Called(ctx, key, defaultValue)
	if err := args.Error(1); err != nil {
		return defaultValue
	}
	// Attempt to return float64 directly
	if fVal, ok := args.Get(0).(float64); ok {
		return fVal
	}
	// Fallback for mock flexibility (e.g., if int was provided)
	return float64(args.Int(0))
}
func (m *MockConfigService) Load(ctx context.Context) error {
	args := m.Called(ctx)
	_ = args
	return args.Error(0)
}

func (m *MockConfigService) SubscribeToChanges(ctx context.Context) error {
	args := m.Called(ctx)
	_ = args
	return args.Error(0)
}

func (m *MockConfigService) SetConfigValue(ctx context.Context, key string, value interface{}, isPublic bool) error {
	args := m.Called(ctx, key, value, isPublic)
	return args.Error(0)
}

func (m *MockConfigService) GetAPIEndpointConfig(ctx context.Context, apiType models.APIType, endpoint string, isAuthenticated bool) (*models.APIEndpointConfig, error) {
	args := m.Called(ctx, apiType, endpoint, isAuthenticated)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.APIEndpointConfig), args.Error(1)
}

func (m *MockConfigService) GetDuration(ctx context.Context, key string, defaultValue time.Duration) time.Duration {
	args := m.Called(ctx, key, defaultValue)
	if err := args.Error(1); err != nil {
		return defaultValue
	}
	// Return duration from mock (might need type assertion)
	return args.Get(0).(time.Duration)
}

// MockLocationService
type MockLocationService struct {
	mock.Mock
}

func (m *MockLocationService) SearchLocations(ctx context.Context, query string, countryCode *string, limit int) ([]models.Location, error) {
	args := m.Called(ctx, query, countryCode, limit)
	_ = args // Explicitly use
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.Location), args.Error(1)
}

// MockUserValidationService implements services.IUserValidationService
type MockUserValidationService struct {
	mock.Mock
}

func (m *MockUserValidationService) GetValidationTypes(ctx context.Context) ([]models.UserValidationType, error) {
	args := m.Called(ctx)
	_ = args // Explicitly use
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.UserValidationType), args.Error(1)
}

func (m *MockUserValidationService) GetValidationTypeByID(ctx context.Context, typeID utils.SixID) (*models.UserValidationType, error) {
	args := m.Called(ctx, typeID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.UserValidationType), args.Error(1)
}

func (m *MockUserValidationService) CreateDomainValidation(ctx context.Context, userID utils.SixID, typeID utils.SixID, domainName string) (*models.UserValidation, error) {
	args := m.Called(ctx, userID, typeID, domainName)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.UserValidation), args.Error(1)
}

func (m *MockUserValidationService) CreateOnlineProfileValidation(ctx context.Context, userID utils.SixID, typeID utils.SixID, profileID string) (*models.UserValidation, error) {
	args := m.Called(ctx, userID, typeID, profileID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.UserValidation), args.Error(1)
}

// Add methods to mock
func (m *MockUserValidationService) GetValidationByID(ctx context.Context, validationID utils.SixID) (*models.UserValidation, error) {
	args := m.Called(ctx, validationID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.UserValidation), args.Error(1)
}
func (m *MockUserValidationService) ConfirmValidation(ctx context.Context, validationID utils.SixID) error {
	args := m.Called(ctx, validationID)
	return args.Error(0)
}

// MockEmailTemplateService implements services.IEmailTemplateService
type MockEmailTemplateService struct {
	mock.Mock
}

func (m *MockEmailTemplateService) GetTemplate(ctx context.Context, templateID, locale string) (*models.EmailTemplate, error) {
	args := m.Called(ctx, templateID, locale)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.EmailTemplate), args.Error(1)
}
