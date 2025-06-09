package payment

type PaymentRequestInput struct {
	Amount      float64 `json:"amount"`
	Email       string  `json:"email"`
	FirstName   string  `json:"first_name"`
	LastName    string  `json:"last_name"`
	CallbackURL string  `json:"callback_url"`
}

type PaymentResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	URL     string `json:"url"`
}
