package payment

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/shopspring/decimal"

	chapa "github.com/Chapa-Et/chapa-go"
)

var chapaAPI = chapa.New()

func CreatePayment(w http.ResponseWriter, r *http.Request) {
	var req PaymentRequestInput
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	txnRef := GenerateTxnRef(20)

	paymentReq := &chapa.PaymentRequest{
		Amount:         decimal.NewFromFloat(req.Amount),
		Currency:       "ETB",
		FirstName:      req.FirstName,
		LastName:       req.LastName,
		Email:          req.Email,
		CallbackURL:    req.CallbackURL,
		TransactionRef: txnRef,
		Customization: map[string]interface{}{
			"title":       "Payment for Service",
			"description": "Service purchase via Chapa",
			"logo":        "https://yourdomain.com/logo.png",
		},
	}

	response, err := chapaAPI.PaymentRequest(paymentReq)
	if err != nil {
		http.Error(w, fmt.Sprintf("Payment initiation failed: %v", err), http.StatusInternalServerError)
		return
	}

	// Optional: Save txnRef + user info to DB for later tracking

	json.NewEncoder(w).Encode(PaymentResponse{
		Status:  "success",
		Message: "Payment created",
		URL:     response.Data.CheckoutURL,
	})
}

func VerifyPayment(w http.ResponseWriter, r *http.Request) {
	txnRef := r.URL.Query().Get("txn_ref")
	if txnRef == "" {
		http.Error(w, "Missing txn_ref query parameter", http.StatusBadRequest)
		return
	}

	verifyResp, err := chapaAPI.Verify(txnRef)
	if err != nil {
		http.Error(w, fmt.Sprintf("Verification failed: %v", err), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(verifyResp)
}
