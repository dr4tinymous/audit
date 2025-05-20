package audit

import (
	"context"
	"reflect"
	"time"

	"go.opentelemetry.io/otel/trace"
)

// ContextIDKey is used to store correlation IDs in context.
type ContextIDKey struct{}

// WithContextID attaches a correlation ID to the context for event correlation.
func WithContextID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, ContextIDKey{}, id)
}

// ContextIDFrom retrieves the correlation ID from the context, returning an empty string if not set.
func ContextIDFrom(ctx context.Context) string {
	if id, ok := ctx.Value(ContextIDKey{}).(string); ok {
		return id
	}
	return ""
}

// EventT is a generic Event interface with typed payloads.
type EventT[T any] interface {
	Event
	TypedPayload() T
}

// BasicEventT is a generic implementation of EventT.
type BasicEventT[T any] struct {
	BasicEvent
	payload T
}

// Ensure BasicEventT implements EventT.
var _ EventT[interface{}] = (*BasicEventT[interface{}])(nil)

// TypedPayload returns the typed payload.
func (e BasicEventT[T]) TypedPayload() T { return e.payload }

// HTTPRequestPayload is the payload for HTTP request events.
type HTTPRequestPayload struct {
	Method string
	Path   string
}

// HTTPResponsePayload is the payload for HTTP response events.
type HTTPResponsePayload struct {
	Status      int
	DurationMS  int64
}

// AuthRegisterPayload is the payload for user registration events.
type AuthRegisterPayload struct {
	UserID string
	Email  string
}

// Define additional payloads for other event types as needed...

// HTTP Event Types
const (
	EventTypeHTTPRequestReceived  EventType = "http_request_received"
	EventTypeHTTPResponseSent     EventType = "http_response_sent"
	EventTypeHTTPRouteNotFound    EventType = "http_route_not_found"
	EventTypeHTTPMethodNotAllowed EventType = "http_method_not_allowed"
)

// Authentication Event Types
const (
	EventTypeAuthRegister          EventType = "auth_register"
	EventTypeAuthLogin             EventType = "auth_login"
	EventTypeAuthLogout            EventType = "auth_logout"
	EventTypeAuthTokenIssued       EventType = "auth_token_issued"
	EventTypeAuthTokenRevoked      EventType = "auth_token_revoked"
	EventTypeAuthCredentialsChecked EventType = "auth_credentials_checked"
)

// Database Event Types
const (
	EventTypeDBConnected     EventType = "db_connected"
	EventTypeDBInit          EventType = "db_init"
	EventTypeDBError         EventType = "db_error"
	EventTypeDBQuery         EventType = "db_query"
	EventTypeDBExec          EventType = "db_exec"
	EventTypeDBTxStarted     EventType = "db_tx_started"
	EventTypeDBTxCommitted   EventType = "db_tx_committed"
	EventTypeDBTxRolledBack  EventType = "db_tx_rolled_back"
)

// Work Item Event Types
const (
	EventTypeWorkItemCreated   EventType = "work_item_created"
	EventTypeWorkItemUpdated   EventType = "work_item_updated"
	EventTypeWorkItemDeleted   EventType = "work_item_deleted"
	EventTypeWorkItemAssigned  EventType = "work_item_assigned"
	EventTypeWorkItemUnassigned EventType = "work_item_unassigned"
	EventTypeCustomFieldSet    EventType = "custom_field_set"
)

// Comment & Attachment Event Types
const (
	EventTypeCommentAdded      EventType = "comment_added"
	EventTypeCommentDeleted    EventType = "comment_deleted"
	EventTypeAttachmentAdded   EventType = "attachment_added"
	EventTypeAttachmentRemoved EventType = "attachment_removed"
)

// User Event Types
const (
	EventTypeUserCreated   EventType = "user_created"
	EventTypeUserUpdated   EventType = "user_updated"
	EventTypeUserDeleted   EventType = "user_deleted"
	EventTypeUserLoggedIn  EventType = "user_logged_in"
	EventTypeUserLoggedOut EventType = "user_logged_out"
)

// Team Event Types
const (
	EventTypeTeamCreated      EventType = "team_created"
	EventTypeTeamUpdated      EventType = "team_updated"
	EventTypeTeamDeleted      EventType = "team_deleted"
	EventTypeTeamMemberAdded  EventType = "team_member_added"
	EventTypeTeamMemberRemoved EventType = "team_member_removed"
)

// init registers schemas for all event types during package initialization.
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