package payment

import "net/http"

func RegisterPaymentRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/payment/create", CreatePayment)
	mux.HandleFunc("/api/payment/verify", VerifyPayment)
}
