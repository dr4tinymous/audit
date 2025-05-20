// Package audit provides comprehensive event auditing, monitoring, and correlation capabilities.
// It enables structured event logging, contextual tracking, schema validation, and 
// type-safe event handling for applications that require detailed audit trails
// and observability across various system components including HTTP, authentication,
// database operations, and business entities.
package audit

import (
	"context"
	"reflect"
	"time"
	"go.opentelemetry.io/otel/trace"
)

// ContextIDKey is used to store correlation IDs in context.
// This type serves as a unique key for storing and retrieving correlation
// identifiers within a context.Context object.
type ContextIDKey struct{}

// WithContextID attaches a correlation ID to the context for event correlation.
// This function creates a derived context that carries the specified correlation ID,
// allowing for tracing related events across system boundaries.
//
// Parameters:
// - ctx: The parent context to derive from
// - id: The correlation ID string to attach
//
// Returns:
// - A derived context containing the correlation ID
func WithContextID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, ContextIDKey{}, id)
}

// ContextIDFrom retrieves the correlation ID from the context, returning an empty string if not set.
// This function safely extracts the correlation ID from the provided context,
// handling the case where no correlation ID has been set.
//
// Parameters:
// - ctx: The context from which to extract the correlation ID
//
// Returns:
// - The correlation ID string, or an empty string if not found
func ContextIDFrom(ctx context.Context) string {
	if id, ok := ctx.Value(ContextIDKey{}).(string); ok {
		return id
	}
	return ""
}

// EventT is a generic Event interface with typed payloads.
// This interface extends the base Event interface to provide
// type-safe access to event payload data.
type EventT[T any] interface {
	Event
	// TypedPayload returns the strongly-typed payload data
	TypedPayload() T
}

// BasicEventT is a generic implementation of EventT.
// It provides a concrete implementation of the EventT interface
// with a strongly-typed payload field.
type BasicEventT[T any] struct {
	BasicEvent
	payload T
}

// Ensure BasicEventT implements EventT.
var _ EventT[interface{}] = (*BasicEventT[interface{}])(nil)

// TypedPayload returns the typed payload.
// This method implements the EventT interface, providing type-safe access
// to the event's payload data.
//
// Returns:
// - The strongly-typed payload data
func (e BasicEventT[T]) TypedPayload() T { return e.payload }

// HTTPRequestPayload is the payload for HTTP request events.
// It contains essential information about incoming HTTP requests.
type HTTPRequestPayload struct {
	// Method is the HTTP method used (GET, POST, etc.)
	Method string
	// Path is the requested URL path
	Path   string
}

// HTTPResponsePayload is the payload for HTTP response events.
// It captures key metrics about HTTP responses being sent.
type HTTPResponsePayload struct {
	// Status is the HTTP status code returned
	Status      int
	// DurationMS is the request processing time in milliseconds
	DurationMS  int64
}

// AuthRegisterPayload is the payload for user registration events.
// It contains identifying information about newly registered users.
type AuthRegisterPayload struct {
	// UserID is the unique identifier assigned to the user
	UserID string
	// Email is the user's registered email address
	Email  string
}

// Define additional payloads for other event types as needed...

// HTTP Event Types
const (
	// EventTypeHTTPRequestReceived is emitted when an HTTP request is received
	EventTypeHTTPRequestReceived  EventType = "http_request_received"
	// EventTypeHTTPResponseSent is emitted when an HTTP response is sent
	EventTypeHTTPResponseSent     EventType = "http_response_sent"
	// EventTypeHTTPRouteNotFound is emitted when a requested route does not exist
	EventTypeHTTPRouteNotFound    EventType = "http_route_not_found"
	// EventTypeHTTPMethodNotAllowed is emitted when a request uses an unsupported HTTP method
	EventTypeHTTPMethodNotAllowed EventType = "http_method_not_allowed"
)

// Authentication Event Types
const (
	// EventTypeAuthRegister is emitted when a new user registers
	EventTypeAuthRegister          EventType = "auth_register"
	// EventTypeAuthLogin is emitted when a user logs in
	EventTypeAuthLogin             EventType = "auth_login"
	// EventTypeAuthLogout is emitted when a user logs out
	EventTypeAuthLogout            EventType = "auth_logout"
	// EventTypeAuthTokenIssued is emitted when an authentication token is issued
	EventTypeAuthTokenIssued       EventType = "auth_token_issued"
	// EventTypeAuthTokenRevoked is emitted when an authentication token is revoked
	EventTypeAuthTokenRevoked      EventType = "auth_token_revoked"
	// EventTypeAuthCredentialsChecked is emitted when user credentials are verified
	EventTypeAuthCredentialsChecked EventType = "auth_credentials_checked"
)

// Database Event Types
const (
	// EventTypeDBConnected is emitted when a database connection is established
	EventTypeDBConnected     EventType = "db_connected"
	// EventTypeDBInit is emitted when database initialization completes
	EventTypeDBInit          EventType = "db_init"
	// EventTypeDBError is emitted when a database operation fails
	EventTypeDBError         EventType = "db_error"
	// EventTypeDBQuery is emitted after a database query is executed
	EventTypeDBQuery         EventType = "db_query"
	// EventTypeDBExec is emitted after a database statement is executed
	EventTypeDBExec          EventType = "db_exec"
	// EventTypeDBTxStarted is emitted when a database transaction begins
	EventTypeDBTxStarted     EventType = "db_tx_started"
	// EventTypeDBTxCommitted is emitted when a database transaction is committed
	EventTypeDBTxCommitted   EventType = "db_tx_committed"
	// EventTypeDBTxRolledBack is emitted when a database transaction is rolled back
	EventTypeDBTxRolledBack  EventType = "db_tx_rolled_back"
)

// Work Item Event Types
const (
	// EventTypeWorkItemCreated is emitted when a new work item is created
	EventTypeWorkItemCreated   EventType = "work_item_created"
	// EventTypeWorkItemUpdated is emitted when a work item is updated
	EventTypeWorkItemUpdated   EventType = "work_item_updated"
	// EventTypeWorkItemDeleted is emitted when a work item is deleted
	EventTypeWorkItemDeleted   EventType = "work_item_deleted"
	// EventTypeWorkItemAssigned is emitted when a work item is assigned to a user
	EventTypeWorkItemAssigned  EventType = "work_item_assigned"
	// EventTypeWorkItemUnassigned is emitted when a work item is unassigned
	EventTypeWorkItemUnassigned EventType = "work_item_unassigned"
	// EventTypeCustomFieldSet is emitted when a custom field is set on a work item
	EventTypeCustomFieldSet    EventType = "custom_field_set"
)

// Comment & Attachment Event Types
const (
	// EventTypeCommentAdded is emitted when a comment is added to a work item
	EventTypeCommentAdded      EventType = "comment_added"
	// EventTypeCommentDeleted is emitted when a comment is deleted
	EventTypeCommentDeleted    EventType = "comment_deleted"
	// EventTypeAttachmentAdded is emitted when an attachment is added to a work item
	EventTypeAttachmentAdded   EventType = "attachment_added"
	// EventTypeAttachmentRemoved is emitted when an attachment is removed
	EventTypeAttachmentRemoved EventType = "attachment_removed"
)

// User Event Types
const (
	// EventTypeUserCreated is emitted when a new user is created
	EventTypeUserCreated   EventType = "user_created"
	// EventTypeUserUpdated is emitted when a user's information is updated
	EventTypeUserUpdated   EventType = "user_updated"
	// EventTypeUserDeleted is emitted when a user is deleted
	EventTypeUserDeleted   EventType = "user_deleted"
	// EventTypeUserLoggedIn is emitted when a user logs into the system
	EventTypeUserLoggedIn  EventType = "user_logged_in"
	// EventTypeUserLoggedOut is emitted when a user logs out of the system
	EventTypeUserLoggedOut EventType = "user_logged_out"
)

// Team Event Types
const (
	// EventTypeTeamCreated is emitted when a new team is created
	EventTypeTeamCreated      EventType = "team_created"
	// EventTypeTeamUpdated is emitted when a team's information is updated
	EventTypeTeamUpdated      EventType = "team_updated"
	// EventTypeTeamDeleted is emitted when a team is deleted
	EventTypeTeamDeleted      EventType = "team_deleted"
	// EventTypeTeamMemberAdded is emitted when a user is added to a team
	EventTypeTeamMemberAdded  EventType = "team_member_added"
	// EventTypeTeamMemberRemoved is emitted when a user is removed from a team
	EventTypeTeamMemberRemoved EventType = "team_member_removed"
)

// init registers schemas for all event types during package initialization.
// This function establishes the expected structure and validation rules for all
// supported event types, ensuring consistency and type safety across the application.
func init() {
	// HTTP Schemas
	RegisterSchema(EventTypeHTTPRequestReceived, EventSchema{
		RequiredFields: []string{"method", "path"},
		FieldTypes: map[string]reflect.Type{
			"method": reflect.TypeOf(""),
			"path":   reflect.TypeOf(""),
		},
	})
	RegisterSchema(EventTypeHTTPResponseSent, EventSchema{
		RequiredFields: []string{"status", "duration_ms"},
		FieldTypes: map[string]reflect.Type{
			"status":      reflect.TypeOf(0),
			"duration_ms": reflect.TypeOf(int64(0)),
		},
	})
	RegisterSchema(EventTypeHTTPRouteNotFound, EventSchema{
		RequiredFields: []string{"path"},
		FieldTypes: map[string]reflect.Type{
			"path": reflect.TypeOf(""),
		},
	})
	RegisterSchema(EventTypeHTTPMethodNotAllowed, EventSchema{
		RequiredFields: []string{"method"},
		FieldTypes: map[string]reflect.Type{
			"method": reflect.TypeOf(""),
		},
	})
	// Authentication Schemas
	RegisterSchema(EventTypeAuthRegister, EventSchema{
		RequiredFields: []string{"user_id", "email"},
		FieldTypes: map[string]reflect.Type{
			"user_id": reflect.TypeOf(""),
			"email":   reflect.TypeOf(""),
		},
	})
	RegisterSchema(EventTypeAuthLogin, EventSchema{
		RequiredFields: []string{"user_id"},
		FieldTypes: map[string]reflect.Type{
			"user_id": reflect.TypeOf(""),
		},
	})
	RegisterSchema(EventTypeAuthLogout, EventSchema{
		RequiredFields: []string{"user_id"},
		FieldTypes: map[string]reflect.Type{
			"user_id": reflect.TypeOf(""),
		},
	})
	RegisterSchema(EventTypeAuthTokenIssued, EventSchema{
		RequiredFields: []string{"user_id", "expires_in_s"},
		FieldTypes: map[string]reflect.Type{
			"user_id":      reflect.TypeOf(""),
			"expires_in_s": reflect.TypeOf(0),
		},
	})
	RegisterSchema(EventTypeAuthTokenRevoked, EventSchema{
		RequiredFields: []string{"token_id"},
		FieldTypes: map[string]reflect.Type{
			"token_id": reflect.TypeOf(""),
		},
	})
	RegisterSchema(EventTypeAuthCredentialsChecked, EventSchema{
		RequiredFields: []string{"email", "success"},
		FieldTypes: map[string]reflect.Type{
			"email":   reflect.TypeOf(""),
			"success": reflect.TypeOf(false),
		},
	})
	// Database Schemas
	RegisterSchema(EventTypeDBConnected, EventSchema{
		RequiredFields: []string{"driver", "dsn"},
		FieldTypes: map[string]reflect.Type{
			"driver": reflect.TypeOf(""),
			"dsn":    reflect.TypeOf(""),
		},
	})
	RegisterSchema(EventTypeDBInit, EventSchema{
		RequiredFields: []string{"schema"},
		FieldTypes: map[string]reflect.Type{
			"schema": reflect.TypeOf(""),
		},
	})
	RegisterSchema(EventTypeDBError, EventSchema{
		RequiredFields: []string{"error", "query"},
		FieldTypes: map[string]reflect.Type{
			"error": reflect.TypeOf(""),
			"query": reflect.TypeOf(""),
		},
	})
	RegisterSchema(EventTypeDBQuery, EventSchema{
		RequiredFields: []string{"query", "duration_ms"},
		FieldTypes: map[string]reflect.Type{
			"query":       reflect.TypeOf(""),
			"duration_ms": reflect.TypeOf(int64(0)),
		},
	})
	RegisterSchema(EventTypeDBExec, EventSchema{
		RequiredFields: []string{"statement", "rows_affected"},
		FieldTypes: map[string]reflect.Type{
			"statement":     reflect.TypeOf(""),
			"rows_affected": reflect.TypeOf(int64(0)),
		},
	})
	RegisterSchema(EventTypeDBTxStarted, EventSchema{
		RequiredFields: []string{"tx_id"},
		FieldTypes: map[string]reflect.Type{
			"tx_id": reflect.TypeOf(""),
		},
	})
	RegisterSchema(EventTypeDBTxCommitted, EventSchema{
		RequiredFields: []string{"tx_id"},
		FieldTypes: map[string]reflect.Type{
			"tx_id": reflect.TypeOf(""),
		},
	})
	RegisterSchema(EventTypeDBTxRolledBack, EventSchema{
		RequiredFields: []string{"tx_id", "reason"},
		FieldTypes: map[string]reflect.Type{
			"tx_id":  reflect.TypeOf(""),
			"reason": reflect.TypeOf(""),
		},
	})
	// Work Item Schemas
	RegisterSchema(EventTypeWorkItemCreated, EventSchema{
		RequiredFields: []string{"work_item_id", "metadata"},
		FieldTypes: map[string]reflect.Type{
			"work_item_id": reflect.TypeOf(""),
			"metadata":     reflect.TypeOf(map[string]string{}),
		},
	})
	RegisterSchema(EventTypeWorkItemUpdated, EventSchema{
		RequiredFields: []string{"work_item_id", "changes"},
		FieldTypes: map[string]reflect.Type{
			"work_item_id": reflect.TypeOf(""),
			"changes":      reflect.TypeOf(map[string]interface{}{}),
		},
	})
	RegisterSchema(EventTypeWorkItemDeleted, EventSchema{
		RequiredFields: []string{"work_item_id"},
		FieldTypes: map[string]reflect.Type{
			"work_item_id": reflect.TypeOf(""),
		},
	})
	RegisterSchema(EventTypeWorkItemAssigned, EventSchema{
		RequiredFields: []string{"work_item_id", "assignee_id"},
		FieldTypes: map[string]reflect.Type{
			"work_item_id": reflect.TypeOf(""),
			"assignee_id":  reflect.TypeOf(""),
		},
	})
	RegisterSchema(EventTypeWorkItemUnassigned, EventSchema{
		RequiredFields: []string{"work_item_id", "assignee_id"},
		FieldTypes: map[string]reflect.Type{
			"work_item_id": reflect.TypeOf(""),
			"assignee_id":  reflect.TypeOf(""),
		},
	})
	RegisterSchema(EventTypeCustomFieldSet, EventSchema{
		RequiredFields: []string{"work_item_id", "field", "value"},
		FieldTypes: map[string]reflect.Type{
			"work_item_id": reflect.TypeOf(""),
			"field":        reflect.TypeOf(""),
			"value":        reflect.TypeOf(nil),
		},
	})
	// Comment & Attachment Schemas
	RegisterSchema(EventTypeCommentAdded, EventSchema{
		RequiredFields: []string{"comment_id", "work_item_id", "comment"},
		FieldTypes: map[string]reflect.Type{
			"comment_id":   reflect.TypeOf(""),
			"work_item_id": reflect.TypeOf(""),
			"comment":      reflect.TypeOf(""),
		},
	})
	RegisterSchema(EventTypeCommentDeleted, EventSchema{
		RequiredFields: []string{"comment_id", "work_item_id"},
		FieldTypes: map[string]reflect.Type{
			"comment_id":   reflect.TypeOf(""),
			"work_item_id": reflect.TypeOf(""),
		},
	})
	RegisterSchema(EventTypeAttachmentAdded, EventSchema{
		RequiredFields: []string{"attachment_id", "work_item_id", "filename"},
		FieldTypes: map[string]reflect.Type{
			"attachment_id": reflect.TypeOf(""),
			"work_item_id":  reflect.TypeOf(""),
			"filename":      reflect.TypeOf(""),
		},
	})
	RegisterSchema(EventTypeAttachmentRemoved, EventSchema{
		RequiredFields: []string{"attachment_id", "work_item_id"},
		FieldTypes: map[string]reflect.Type{
			"attachment_id": reflect.TypeOf(""),
			"work_item_id":  reflect.TypeOf(""),
		},
	})
	// User Schemas
	RegisterSchema(EventTypeUserCreated, EventSchema{
		RequiredFields: []string{"user_id", "email"},
		FieldTypes: map[string]reflect.Type{
			"user_id": reflect.TypeOf(""),
			"email":   reflect.TypeOf(""),
		},
	})
	RegisterSchema(EventTypeUserUpdated, EventSchema{
		RequiredFields: []string{"user_id", "changes"},
		FieldTypes: map[string]reflect.Type{
			"user_id": reflect.TypeOf(""),
			"changes": reflect.TypeOf(map[string]interface{}{}),
		},
	})
	RegisterSchema(EventTypeUserDeleted, EventSchema{
		RequiredFields: []string{"user_id"},
		FieldTypes: map[string]reflect.Type{
			"user_id": reflect.TypeOf(""),
		},
	})
	RegisterSchema(EventTypeUserLoggedIn, EventSchema{
		RequiredFields: []string{"user_id"},
		FieldTypes: map[string]reflect.Type{
			"user_id": reflect.TypeOf(""),
		},
	})
	RegisterSchema(EventTypeUserLoggedOut, EventSchema{
		RequiredFields: []string{"user_id"},
		FieldTypes: map[string]reflect.Type{
			"user_id": reflect.TypeOf(""),
		},
	})
	// Team Schemas
	RegisterSchema(EventTypeTeamCreated, EventSchema{
		RequiredFields: []string{"team_id", "name"},
		FieldTypes: map[string]reflect.Type{
			"team_id": reflect.TypeOf(""),
			"name":    reflect.TypeOf(""),
		},
	})
	RegisterSchema(EventTypeTeamUpdated, EventSchema{
		RequiredFields: []string{"team_id", "changes"},
		FieldTypes: map[string]reflect.Type{
			"team_id": reflect.TypeOf(""),
			"changes": reflect.TypeOf(map[string]interface{}{}),
		},
	})
	RegisterSchema(EventTypeTeamDeleted, EventSchema{
		RequiredFields: []string{"team_id"},
		FieldTypes: map[string]reflect.Type{
			"team_id": reflect.TypeOf(""),
		},
	})
	RegisterSchema(EventTypeTeamMemberAdded, EventSchema{
		RequiredFields: []string{"team_id", "user_id"},
		FieldTypes: map[string]reflect.Type{
			"team_id": reflect.TypeOf(""),
			"user_id": reflect.TypeOf(""),
		},
	})
	RegisterSchema(EventTypeTeamMemberRemoved, EventSchema{
		RequiredFields: []string{"team_id", "user_id"},
		FieldTypes: map[string]reflect.Type{
			"team_id": reflect.TypeOf(""),
			"user_id": reflect.TypeOf(""),
		},
	})
}

// NewHTTPRequestReceived creates an Event for an incoming HTTP request.
// This function captures information about HTTP requests entering the system,
// providing a starting point for request tracing and monitoring.
//
// Parameters:
// - ctx: Context carrying correlation IDs and tracing information
// - source: The component or service that received the request
// - method: The HTTP method (GET, POST, etc.)
// - path: The request URL path
//
// Returns:
// - A new Event instance capturing the HTTP request details
func NewHTTPRequestReceived(ctx context.Context, source, method, path string) Event {
	spanCtx := trace.SpanContextFromContext(ctx)
	return NewBasicEvent(
		EventTypeHTTPRequestReceived,
		source,
		ContextIDFrom(ctx),
		map[string]string{"method": method, "path": path},
		spanCtx,
	)
}

// NewHTTPRequestReceivedT creates a typed Event for an incoming HTTP request.
// This function provides a type-safe version of NewHTTPRequestReceived,
// allowing for stronger type checking and less error-prone access to event data.
//
// Parameters:
// - ctx: Context carrying correlation IDs and tracing information
// - source: The component or service that received the request
// - method: The HTTP method (GET, POST, etc.)
// - path: The request URL path
//
// Returns:
// - A strongly-typed Event instance with an HTTPRequestPayload
func NewHTTPRequestReceivedT(ctx context.Context, source, method, path string) BasicEventT[HTTPRequestPayload] {
	spanCtx := trace.SpanContextFromContext(ctx)
	return BasicEventT[HTTPRequestPayload]{
		BasicEvent: NewBasicEvent(
			EventTypeHTTPRequestReceived,
			source,
			ContextIDFrom(ctx),
			map[string]string{"method": method, "path": path},
			spanCtx,
		),
		payload: HTTPRequestPayload{Method: method, Path: path},
	}
}

// NewHTTPResponseSent creates an Event when an HTTP response is sent.
// This function captures information about HTTP responses leaving the system,
// allowing for response time tracking and status code monitoring.
//
// Parameters:
// - ctx: Context carrying correlation IDs and tracing information
// - source: The component or service that is sending the response
// - status: The HTTP status code
// - duration: The time taken to process the request
//
// Returns:
// - A new Event instance capturing the HTTP response details
func NewHTTPResponseSent(ctx context.Context, source string, status int, duration time.Duration) Event {
	spanCtx := trace.SpanContextFromContext(ctx)
	return NewBasicEvent(
		EventTypeHTTPResponseSent,
		source,
		ContextIDFrom(ctx),
		map[string]interface{}{"status": status, "duration_ms": duration.Milliseconds()},
		spanCtx,
	)
}

// NewHTTPResponseSentT creates a typed Event for an HTTP response sent.
// This function provides a type-safe version of NewHTTPResponseSent,
// ensuring compile-time type safety for response event data.
//
// Parameters:
// - ctx: Context carrying correlation IDs and tracing information
// - source: The component or service that is sending the response
// - status: The HTTP status code
// - duration: The time taken to process the request
//
// Returns:
// - A strongly-typed Event instance with an HTTPResponsePayload
func NewHTTPResponseSentT(ctx context.Context, source string, status int, duration time.Duration) BasicEventT[HTTPResponsePayload] {
	spanCtx := trace.SpanContextFromContext(ctx)
	return BasicEventT[HTTPResponsePayload]{
		BasicEvent: NewBasicEvent(
			EventTypeHTTPResponseSent,
			source,
			ContextIDFrom(ctx),
			map[string]interface{}{"status": status, "duration_ms": duration.Milliseconds()},
			spanCtx,
		),
		payload: HTTPResponsePayload{Status: status, DurationMS: duration.Milliseconds()},
	}
}

// NewHTTPRouteNotFound creates an Event when no route matches.
// This function generates an event when a client requests a path
// that doesn't match any defined routes, indicating potential configuration issues
// or client errors.
//
// Parameters:
// - ctx: Context carrying correlation IDs and tracing information
// - source: The component or service that handled the request
// - path: The requested URL path that wasn't found
//
// Returns:
// - A new Event instance for the route not found condition
func NewHTTPRouteNotFound(ctx context.Context, source, path string) Event {
	spanCtx := trace.SpanContextFromContext(ctx)
	return NewBasicEvent(
		EventTypeHTTPRouteNotFound,
		source,
		ContextIDFrom(ctx),
		map[string]string{"path": path},
		spanCtx,
	)
}

// NewHTTPMethodNotAllowed creates an Event when the HTTP method is not allowed.
// This function generates an event when a client attempts to use an HTTP method
// that isn't supported for the requested resource.
//
// Parameters:
// - ctx: Context carrying correlation IDs and tracing information
// - source: The component or service that handled the request
// - method: The HTTP method that was not allowed
//
// Returns:
// - A new Event instance for the method not allowed condition
func NewHTTPMethodNotAllowed(ctx context.Context, source, method string) Event {
	spanCtx := trace.SpanContextFromContext(ctx)
	return NewBasicEvent(
		EventTypeHTTPMethodNotAllowed,
		source,
		ContextIDFrom(ctx),
		map[string]string{"method": method},
		spanCtx,
	)
}

// NewAuthRegister creates an Event for user registration.
// This function tracks when new users register with the system,
// capturing essential user identification information.
//
// Parameters:
// - ctx: Context carrying correlation IDs and tracing information
// - source: The component or service that processed the registration
// - userID: The unique identifier assigned to the new user
// - email: The email address provided by the user
//
// Returns:
// - A new Event instance for the user registration
func NewAuthRegister(ctx context.Context, source, userID, email string) Event {
	spanCtx := trace.SpanContextFromContext(ctx)
	return NewBasicEvent(
		EventTypeAuthRegister,
		source,
		ContextIDFrom(ctx),
		map[string]string{"user_id": userID, "email": email},
		spanCtx,
	)
}

// NewAuthRegisterT creates a typed Event for user registration.
// This function provides a type-safe version of NewAuthRegister,
// allowing for stronger typing of registration event data.
//
// Parameters:
// - ctx: Context carrying correlation IDs and tracing information
// - source: The component or service that processed the registration
// - userID: The unique identifier assigned to the new user
// - email: The email address provided by the user
//
// Returns:
// - A strongly-typed Event instance with an AuthRegisterPayload
func NewAuthRegisterT(ctx context.Context, source, userID, email string) BasicEventT[AuthRegisterPayload] {
	spanCtx := trace.SpanContextFromContext(ctx)
	return BasicEventT[AuthRegisterPayload]{
		BasicEvent: NewBasicEvent(
			EventTypeAuthRegister,
			source,
			ContextIDFrom(ctx),
			map[string]string{"user_id": userID, "email": email},
			spanCtx,
		),
		payload: AuthRegisterPayload{UserID: userID, Email: email},
	}
}

// NewAuthLogin creates an Event for a successful login.
// This function tracks when users authenticate successfully with the system,
// providing essential information for security monitoring and user activity tracking.
//
// Parameters:
// - ctx: Context carrying correlation IDs and tracing information
// - source: The component or service that processed the login
// - userID: The unique identifier of the authenticated user
//
// Returns:
// - A new Event instance for the successful login
func NewAuthLogin(ctx context.Context, source, userID string) Event {
	spanCtx := trace.SpanContextFromContext(ctx)
	return NewBasicEvent(
		EventTypeAuthLogin,
		source,
		ContextIDFrom(ctx),
		map[string]string{"user_id": userID},
		spanCtx,
	)
}

// NewAuthLogout creates an Event for user logout.
// This function tracks when users explicitly log out of the system,
// completing the authentication lifecycle and providing important security audit information.
//
// Parameters:
// - ctx: Context carrying correlation IDs and tracing information
// - source: The component or service that processed the logout
// - userID: The unique identifier of the user who logged out
//
// Returns:
// - A new Event instance for the user logout
func NewAuthLogout(ctx context.Context, source, userID string) Event {
	spanCtx := trace.SpanContextFromContext(ctx)
	return NewBasicEvent(
		EventTypeAuthLogout,
		source,
		ContextIDFrom(ctx),
		map[string]string{"user_id": userID},
		spanCtx,
	)
}

// NewAuthTokenIssued creates an Event when a token is issued.
// This function records the creation of authentication tokens,
// which is crucial for security auditing and monitoring token lifecycle.
//
// Parameters:
// - ctx: Context carrying correlation IDs and tracing information
// - source: The component or service that issued the token
// - userID: The unique identifier of the user receiving the token
// - expiresIn: The validity duration of the token
//
// Returns:
// - A new Event instance for the token issuance
func NewAuthTokenIssued(ctx context.Context, source, userID string, expiresIn time.Duration) Event {
	spanCtx := trace.SpanContextFromContext(ctx)
	return NewBasicEvent(
		EventTypeAuthTokenIssued,
		source,
		ContextIDFrom(ctx),
		map[string]interface{}{"user_id": userID, "expires_in_s": int(expiresIn.Seconds())},
		spanCtx,
	)
}

// NewAuthTokenRevoked creates an Event when a token is revoked.
// This function tracks when authentication tokens are explicitly invalidated
// before their natural expiration, which is important for security monitoring.
//
// Parameters:
// - ctx: Context carrying correlation IDs and tracing information
// - source: The component or service that revoked the token
// - tokenID: The unique identifier of the revoked token
//
// Returns:
// - A new Event instance for the token revocation
func NewAuthTokenRevoked(ctx context.Context, source, tokenID string) Event {
	spanCtx := trace.SpanContextFromContext(ctx)
	return NewBasicEvent(
		EventTypeAuthTokenRevoked,
		source,
		ContextIDFrom(ctx),
		map[string]string{"token_id": tokenID},
		spanCtx,
	)
}

// NewAuthCredentialsChecked creates an Event after credential verification.
//
// This function generates an event when authentication credentials are checked, regardless
// of success or failure. It captures the email address that was checked and the outcome
// of the verification.
//
// Parameters:
// - ctx: The context which may contain tracing information
// - source: The component or service that initiated the credential check
// - email: The email address that was used in the authentication attempt
// - success: Boolean indicating whether the authentication was successful
//
// Returns:
// - Event: A fully formed event object containing authentication verification details
func NewAuthCredentialsChecked(ctx context.Context, source, email string, success bool) Event {
	spanCtx := trace.SpanContextFromContext(ctx)
	return NewBasicEvent(
		EventTypeAuthCredentialsChecked,
		source,
		ContextIDFrom(ctx),
		map[string]interface{}{"email": email, "success": success},
		spanCtx,
	)
}

// NewDBConnected creates an Event for successful DB connection.
//
// This function records when a database connection has been successfully established.
// It includes information about the database driver and connection string (DSN).
//
// Parameters:
// - ctx: The context which may contain tracing information
// - source: The component or service that initiated the database connection
// - driver: The database driver type (e.g., "postgres", "mysql")
// - dsn: The data source name or connection string (sensitive information should be redacted)
//
// Returns:
// - Event: A fully formed event object containing database connection details
func NewDBConnected(ctx context.Context, source, driver, dsn string) Event {
	spanCtx := trace.SpanContextFromContext(ctx)
	return NewBasicEvent(
		EventTypeDBConnected,
		source,
		ContextIDFrom(ctx),
		map[string]string{"driver": driver, "dsn": dsn},
		spanCtx,
	)
}

// NewDBInit creates an Event when DB schema initialization completes.
//
// This function records when a database schema has been initialized or migrated
// to a specific version. This is typically used during application startup or
// during database migration processes.
//
// Parameters:
// - ctx: The context which may contain tracing information
// - source: The component or service that initiated the schema initialization
// - schema: The schema name or version identifier that was initialized
//
// Returns:
// - Event: A fully formed event object containing schema initialization details
func NewDBInit(ctx context.Context, source, schema string) Event {
	spanCtx := trace.SpanContextFromContext(ctx)
	return NewBasicEvent(
		EventTypeDBInit,
		source,
		ContextIDFrom(ctx),
		map[string]string{"schema": schema},
		spanCtx,
	)
}

// NewDBError creates an Event on database error.
//
// This function records when a database operation encounters an error. It captures
// both the error message and the query that was being executed when the error occurred.
//
// Parameters:
// - ctx: The context which may contain tracing information
// - source: The component or service that encountered the database error
// - query: The SQL query or operation that failed
// - err: The error that occurred during the database operation
//
// Returns:
// - Event: A fully formed event object containing database error details
func NewDBError(ctx context.Context, source, query string, err error) Event {
	spanCtx := trace.SpanContextFromContext(ctx)
	return NewBasicEvent(
		EventTypeDBError,
		source,
		ContextIDFrom(ctx),
		map[string]interface{}{"error": err.Error(), "query": query},
		spanCtx,
	)
}

// NewDBQuery creates an Event after executing a query.
//
// This function records when a database query has been executed, along with
// its execution duration. This can be useful for performance monitoring and
// identifying slow queries.
//
// Parameters:
// - ctx: The context which may contain tracing information
// - source: The component or service that executed the query
// - query: The SQL query that was executed
// - duration: The time taken to execute the query
//
// Returns:
// - Event: A fully formed event object containing query execution details with duration in milliseconds
func NewDBQuery(ctx context.Context, source, query string, duration time.Duration) Event {
	spanCtx := trace.SpanContextFromContext(ctx)
	return NewBasicEvent(
		EventTypeDBQuery,
		source,
		ContextIDFrom(ctx),
		map[string]interface{}{"query": query, "duration_ms": duration.Milliseconds()},
		spanCtx,
	)
}

// NewDBExec creates an Event after executing a statement.
//
// This function records when a database modification statement (like INSERT, UPDATE, DELETE)
// has been executed, along with the number of rows that were affected by the operation.
//
// Parameters:
// - ctx: The context which may contain tracing information
// - source: The component or service that executed the statement
// - stmt: The SQL statement that was executed
// - rowsAffected: The number of database rows that were affected by the statement
//
// Returns:
// - Event: A fully formed event object containing statement execution details
func NewDBExec(ctx context.Context, source, stmt string, rowsAffected int64) Event {
	spanCtx := trace.SpanContextFromContext(ctx)
	return NewBasicEvent(
		EventTypeDBExec,
		source,
		ContextIDFrom(ctx),
		map[string]interface{}{"statement": stmt, "rows_affected": rowsAffected},
		spanCtx,
	)
}

// NewDBTxStarted creates an Event when a transaction begins.
//
// This function records when a new database transaction has been started.
// It includes a transaction ID which can be used to correlate subsequent
// events related to the same transaction.
//
// Parameters:
// - ctx: The context which may contain tracing information
// - source: The component or service that started the transaction
// - txID: A unique identifier for the transaction
//
// Returns:
// - Event: A fully formed event object containing transaction start details
func NewDBTxStarted(ctx context.Context, source, txID string) Event {
	spanCtx := trace.SpanContextFromContext(ctx)
	return NewBasicEvent(
		EventTypeDBTxStarted,
		source,
		ContextIDFrom(ctx),
		map[string]string{"tx_id": txID},
		spanCtx,
	)
}

// NewDBTxCommitted creates an Event when a transaction commits.
//
// This function records when a database transaction has been successfully committed.
// It references the same transaction ID that was used when the transaction started.
//
// Parameters:
// - ctx: The context which may contain tracing information
// - source: The component or service that committed the transaction
// - txID: The unique identifier for the transaction that was committed
//
// Returns:
// - Event: A fully formed event object containing transaction commit details
func NewDBTxCommitted(ctx context.Context, source, txID string) Event {
	spanCtx := trace.SpanContextFromContext(ctx)
	return NewBasicEvent(
		EventTypeDBTxCommitted,
		source,
		ContextIDFrom(ctx),
		map[string]string{"tx_id": txID},
		spanCtx,
	)
}

// NewDBTxRolledBack creates an Event when a transaction rolls back.
//
// This function records when a database transaction has been rolled back.
// It captures both the transaction ID and the reason for the rollback,
// which could be due to an error or an explicit rollback request.
//
// Parameters:
// - ctx: The context which may contain tracing information
// - source: The component or service that rolled back the transaction
// - txID: The unique identifier for the transaction that was rolled back
// - reason: A description of why the transaction was rolled back
//
// Returns:
// - Event: A fully formed event object containing transaction rollback details
func NewDBTxRolledBack(ctx context.Context, source, txID, reason string) Event {
	spanCtx := trace.SpanContextFromContext(ctx)
	return NewBasicEvent(
		EventTypeDBTxRolledBack,
		source,
		ContextIDFrom(ctx),
		map[string]string{"tx_id": txID, "reason": reason},
		spanCtx,
	)
}

// NewWorkItemCreated creates an Event for a new work item.
//
// This function records when a new work item (such as a task, issue, or ticket)
// has been created. It includes both the work item's ID and additional metadata
// that provides context about the work item.
//
// Parameters:
// - ctx: The context which may contain tracing information
// - source: The component or service that created the work item
// - id: The unique identifier for the newly created work item
// - metadata: A map of key-value pairs containing additional information about the work item
//
// Returns:
// - Event: A fully formed event object containing work item creation details
func NewWorkItemCreated(ctx context.Context, source, id string, metadata map[string]string) Event {
	spanCtx := trace.SpanContextFromContext(ctx)
	return NewBasicEvent(
		EventTypeWorkItemCreated,
		source,
		ContextIDFrom(ctx),
		map[string]interface{}{"work_item_id": id, "metadata": metadata},
		spanCtx,
	)
}

// NewWorkItemUpdated creates an Event for a work item update.
//
// This function records when an existing work item has been updated.
// It captures the specific changes that were made to the work item,
// which could include changes to status, priority, or other attributes.
//
// Parameters:
// - ctx: The context which may contain tracing information
// - source: The component or service that updated the work item
// - id: The unique identifier for the updated work item
// - changes: A map describing the fields that were changed and their new values
//
// Returns:
// - Event: A fully formed event object containing work item update details
func NewWorkItemUpdated(ctx context.Context, source, id string, changes map[string]interface{}) Event {
	spanCtx := trace.SpanContextFromContext(ctx)
	return NewBasicEvent(
		EventTypeWorkItemUpdated,
		source,
		ContextIDFrom(ctx),
		map[string]interface{}{"work_item_id": id, "changes": changes},
		spanCtx,
	)
}

// NewWorkItemDeleted creates an Event for deletion of a work item.
//
// This function records when a work item has been deleted or marked as deleted.
// It includes the identifier of the work item that was removed from the system.
//
// Parameters:
// - ctx: The context which may contain tracing information
// - source: The component or service that deleted the work item
// - id: The unique identifier for the deleted work item
//
// Returns:
// - Event: A fully formed event object containing work item deletion details
func NewWorkItemDeleted(ctx context.Context, source, id string) Event {
	spanCtx := trace.SpanContextFromContext(ctx)
	return NewBasicEvent(
		EventTypeWorkItemDeleted,
		source,
		ContextIDFrom(ctx),
		map[string]string{"work_item_id": id},
		spanCtx,
	)
}

// NewWorkItemAssigned creates an Event when a work item is assigned.
//
// This function records when a work item has been assigned to a specific user.
// It captures both the work item ID and the ID of the assignee.
//
// Parameters:
// - ctx: The context which may contain tracing information
// - source: The component or service that performed the assignment
// - itemID: The unique identifier for the work item that was assigned
// - assigneeID: The unique identifier for the user to whom the work item was assigned
//
// Returns:
// - Event: A fully formed event object containing work item assignment details
func NewWorkItemAssigned(ctx context.Context, source, itemID, assigneeID string) Event {
	spanCtx := trace.SpanContextFromContext(ctx)
	return NewBasicEvent(
		EventTypeWorkItemAssigned,
		source,
		ContextIDFrom(ctx),
		map[string]string{"work_item_id": itemID, "assignee_id": assigneeID},
		spanCtx,
	)
}

// NewWorkItemUnassigned creates an Event when a work item is unassigned.
//
// This function records when a work item has been unassigned from a user.
// It captures both the work item ID and the ID of the user from whom
// the work item was unassigned.
//
// Parameters:
// - ctx: The context which may contain tracing information
// - source: The component or service that performed the unassignment
// - itemID: The unique identifier for the work item that was unassigned
// - assigneeID: The unique identifier for the user from whom the work item was unassigned
//
// Returns:
// - Event: A fully formed event object containing work item unassignment details
func NewWorkItemUnassigned(ctx context.Context, source, itemID, assigneeID string) Event {
	spanCtx := trace.SpanContextFromContext(ctx)
	return NewBasicEvent(
		EventTypeWorkItemUnassigned,
		source,
		ContextIDFrom(ctx),
		map[string]string{"work_item_id": itemID, "assignee_id": assigneeID},
		spanCtx,
	)
}

// NewCustomFieldSet creates an Event when a custom field is set.
//
// This function records when a custom field on a work item has been set to a specific value.
// It captures the work item ID, the name of the field, and the value that was set.
//
// Parameters:
// - ctx: The context which may contain tracing information
// - source: The component or service that set the custom field
// - itemID: The unique identifier for the work item on which the field was set
// - field: The name of the custom field that was set
// - value: The value that was assigned to the custom field (can be of any type)
//
// Returns:
// - Event: A fully formed event object containing custom field setting details
func NewCustomFieldSet(ctx context.Context, source, itemID, field string, value interface{}) Event {
	spanCtx := trace.SpanContextFromContext(ctx)
	return NewBasicEvent(
		EventTypeCustomFieldSet,
		source,
		ContextIDFrom(ctx),
		map[string]interface{}{"work_item_id": itemID, "field": field, "value": value},
		spanCtx,
	)
}

// NewCommentAdded creates an Event for a new comment.
//
// This function records when a comment has been added to a work item.
// It captures the IDs of both the comment and the work item, as well as
// the content of the comment.
//
// Parameters:
// - ctx: The context which may contain tracing information
// - source: The component or service that added the comment
// - commentID: The unique identifier for the newly added comment
// - itemID: The unique identifier for the work item to which the comment was added
// - content: The text content of the comment
//
// Returns:
// - Event: A fully formed event object containing comment addition details
func NewCommentAdded(ctx context.Context, source, commentID, itemID, content string) Event {
	spanCtx := trace.SpanContextFromContext(ctx)
	return NewBasicEvent(
		EventTypeCommentAdded,
		source,
		ContextIDFrom(ctx),
		map[string]string{"comment_id": commentID, "work_item_id": itemID, "comment": content},
		spanCtx,
	)
}

// NewCommentDeleted creates an Event when a comment is deleted.
//
// This function records when a comment has been deleted from a work item.
// It captures the IDs of both the deleted comment and the work item from
// which the comment was removed.
//
// Parameters:
// - ctx: The context which may contain tracing information
// - source: The component or service that deleted the comment
// - commentID: The unique identifier for the deleted comment
// - itemID: The unique identifier for the work item from which the comment was deleted
//
// Returns:
// - Event: A fully formed event object containing comment deletion details
func NewCommentDeleted(ctx context.Context, source, commentID, itemID string) Event {
	spanCtx := trace.SpanContextFromContext(ctx)
	return NewBasicEvent(
		EventTypeCommentDeleted,
		source,
		ContextIDFrom(ctx),
		map[string]string{"comment_id": commentID, "work_item_id": itemID},
		spanCtx,
	)
}

// NewAttachmentAdded creates an Event when an attachment is added.
//
// This function records when a file attachment has been added to a work item.
// It captures the IDs of both the attachment and the work item, as well as
// the filename of the attachment.
//
// Parameters:
// - ctx: The context which may contain tracing information
// - source: The component or service that added the attachment
// - attachmentID: The unique identifier for the newly added attachment
// - itemID: The unique identifier for the work item to which the attachment was added
// - filename: The original filename of the attachment
//
// Returns:
// - Event: A fully formed event object containing attachment addition details
func NewAttachmentAdded(ctx context.Context, source, attachmentID, itemID, filename string) Event {
	spanCtx := trace.SpanContextFromContext(ctx)
	return NewBasicEvent(
		EventTypeAttachmentAdded,
		source,
		ContextIDFrom(ctx),
		map[string]string{"attachment_id": attachmentID, "work_item_id": itemID, "filename": filename},
		spanCtx,
	)
}

// NewAttachmentRemoved creates an Event when an attachment is removed.
//
// This function records when a file attachment has been removed from a work item.
// It captures the IDs of both the removed attachment and the work item from
// which the attachment was removed.
//
// Parameters:
// - ctx: The context which may contain tracing information
// - source: The component or service that removed the attachment
// - attachmentID: The unique identifier for the removed attachment
// - itemID: The unique identifier for the work item from which the attachment was removed
//
// Returns:
// - Event: A fully formed event object containing attachment removal details
func NewAttachmentRemoved(ctx context.Context, source, attachmentID, itemID string) Event {
	spanCtx := trace.SpanContextFromContext(ctx)
	return NewBasicEvent(
		EventTypeAttachmentRemoved,
		source,
		ContextIDFrom(ctx),
		map[string]string{"attachment_id": attachmentID, "work_item_id": itemID},
		spanCtx,
	)
}

// NewUserCreated creates an Event for a new user.
//
// This function records when a new user account has been created in the system.
// It captures both the user's ID and email address.
//
// Parameters:
// - ctx: The context which may contain tracing information
// - source: The component or service that created the user
// - userID: The unique identifier for the newly created user
// - email: The email address associated with the user account
//
// Returns:
// - Event: A fully formed event object containing user creation details
func NewUserCreated(ctx context.Context, source, userID, email string) Event {
	spanCtx := trace.SpanContextFromContext(ctx)
	return NewBasicEvent(
		EventTypeUserCreated,
		source,
		ContextIDFrom(ctx),
		map[string]string{"user_id": userID, "email": email},
		spanCtx,
	)
}

// NewUserUpdated creates an Event for user updates.
//
// This function records when an existing user account has been updated.
// It captures the specific changes that were made to the user's profile
// or account settings.
//
// Parameters:
// - ctx: The context which may contain tracing information
// - source: The component or service that updated the user
// - userID: The unique identifier for the updated user
// - changes: A map describing the fields that were changed and their new values
//
// Returns:
// - Event: A fully formed event object containing user update details
func NewUserUpdated(ctx context.Context, source, userID string, changes map[string]interface{}) Event {
	spanCtx := trace.SpanContextFromContext(ctx)
	return NewBasicEvent(
		EventTypeUserUpdated,
		source,
		ContextIDFrom(ctx),
		map[string]interface{}{"user_id": userID, "changes": changes},
		spanCtx,
	)
}

// NewUserDeleted creates an Event when a user is deleted.
//
// This function records when a user account has been deleted or deactivated.
// It includes the identifier of the user that was removed from the system.
//
// Parameters:
// - ctx: The context which may contain tracing information
// - source: The component or service that deleted the user
// - userID: The unique identifier for the deleted user
//
// Returns:
// - Event: A fully formed event object containing user deletion details
func NewUserDeleted(ctx context.Context, source, userID string) Event {
	spanCtx := trace.SpanContextFromContext(ctx)
	return NewBasicEvent(
		EventTypeUserDeleted,
		source,
		ContextIDFrom(ctx),
		map[string]string{"user_id": userID},
		spanCtx,
	)
}

// NewUserLoggedIn creates an Event when a user logs in.
//
// This function records when a user has successfully authenticated and logged in.
// It includes the identifier of the user who performed the login.
//
// Parameters:
// - ctx: The context which may contain tracing information
// - source: The component or service that processed the login
// - userID: The unique identifier for the user who logged in
//
// Returns:
// - Event: A fully formed event object containing user login details
func NewUserLoggedIn(ctx context.Context, source, userID string) Event {
	spanCtx := trace.SpanContextFromContext(ctx)
	return NewBasicEvent(
		EventTypeUserLoggedIn,
		source,
		ContextIDFrom(ctx),
		map[string]string{"user_id": userID},
		spanCtx,
	)
}

// NewUserLoggedOut creates an Event when a user logs out.
//
// This function records when a user has logged out of the system.
// It captures the identifier of the user who performed the logout.
//
// Parameters:
// - ctx: The context which may contain tracing information
// - source: The component or service that processed the logout
// - userID: The unique identifier for the user who logged out
//
// Returns:
// - Event: A fully formed event object containing user logout details
func NewUserLoggedOut(ctx context.Context, source, userID string) Event {
	spanCtx := trace.SpanContextFromContext(ctx)
	return NewBasicEvent(
		EventTypeUserLoggedOut,
		source,
		ContextIDFrom(ctx),
		map[string]string{"user_id": userID},
		spanCtx,
	)
}

// NewTeamCreated creates an Event for a new team.
//
// This function records when a new team or group has been created in the system.
// It captures both the team's ID and name.
//
// Parameters:
// - ctx: The context which may contain tracing information
// - source: The component or service that created the team
// - teamID: The unique identifier for the newly created team
// - name: The display name of the team
//
// Returns:
// - Event: A fully formed event object containing team creation details
func NewTeamCreated(ctx context.Context, source, teamID, name string) Event {
	spanCtx := trace.SpanContextFromContext(ctx)
	return NewBasicEvent(
		EventTypeTeamCreated,
		source,
		ContextIDFrom(ctx),
		map[string]string{"team_id": teamID, "name": name},
		spanCtx,
	)
}

// NewTeamUpdated creates an Event for team updates.
//
// This function records when an existing team has been updated.
// It captures the specific changes that were made to the team's
// properties or settings.
//
// Parameters:
// - ctx: The context which may contain tracing information
// - source: The component or service that updated the team
// - teamID: The unique identifier for the updated team
// - changes: A map describing the fields that were changed and their new values
//
// Returns:
// - Event: A fully formed event object containing team update details
func NewTeamUpdated(ctx context.Context, source, teamID string, changes map[string]interface{}) Event {
	spanCtx := trace.SpanContextFromContext(ctx)
	return NewBasicEvent(
		EventTypeTeamUpdated,
		source,
		ContextIDFrom(ctx),
		map[string]interface{}{"team_id": teamID, "changes": changes},
		spanCtx,
	)
}

// NewTeamDeleted creates an Event when a team is deleted.
//
// This function records when a team has been deleted or deactivated.
// It includes the identifier of the team that was removed from the system.
//
// Parameters:
// - ctx: The context which may contain tracing information
// - source: The component or service that deleted the team
// - teamID: The unique identifier for the deleted team
//
// Returns:
// - Event: A fully formed event object containing team deletion details
func NewTeamDeleted(ctx context.Context, source, teamID string) Event {
	spanCtx := trace.SpanContextFromContext(ctx)
	return NewBasicEvent(
		EventTypeTeamDeleted,
		source,
		ContextIDFrom(ctx),
		map[string]string{"team_id": teamID},
		spanCtx,
	)
}

// NewTeamMemberAdded creates an Event when a user joins a team.
//
// This function records when a user has been added to a team.
// It captures both the team ID and the ID of the user who joined.
//
// Parameters:
// - ctx: The context which may contain tracing information
// - source: The component or service that added the team member
// - teamID: The unique identifier for the team to which the user was added
// - userID: The unique identifier for the user who was added to the team
//
// Returns:
// - Event: A fully formed event object containing team member addition details
func NewTeamMemberAdded(ctx context.Context, source, teamID, userID string) Event {
	spanCtx := trace.SpanContextFromContext(ctx)
	return NewBasicEvent(
		EventTypeTeamMemberAdded,
		source,
		ContextIDFrom(ctx),
		map[string]string{"team_id": teamID, "user_id": userID},
		spanCtx,
	)
}

// NewTeamMemberRemoved creates an Event when a user leaves a team.
//
// This function records when a user has been removed from a team.
// It captures both the team ID and the ID of the user who was removed.
//
// Parameters:
// - ctx: The context which may contain tracing information
// - source: The component or service that removed the team member
// - teamID: The unique identifier for the team from which the user was removed
// - userID: The unique identifier for the user who was removed from the team
//
// Returns:
// - Event: A fully formed event object containing team member removal details
func NewTeamMemberRemoved(ctx context.Context, source, teamID, userID string) Event {
	spanCtx := trace.SpanContextFromContext(ctx)
	return NewBasicEvent(
		EventTypeTeamMemberRemoved,
		source,
		ContextIDFrom(ctx),
		map[string]string{"team_id": teamID, "user_id": userID},
		spanCtx,
	)
}