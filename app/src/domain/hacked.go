package domain

type DisavowRequest struct{}

type DisavowResponse struct {
	Message string `json:"message"`
}
