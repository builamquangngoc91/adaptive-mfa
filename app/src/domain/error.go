package domain

type Error struct {
	Message   string                 `json:"message,omitempty"`
	Code      string                 `json:"code,omitempty"`
	RequestID string                 `json:"request_id,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}
