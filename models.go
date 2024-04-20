package main

type Prime struct {
	P  string   `json:"p"`
	Pa []string `json:"pA"`

	Q  string   `json:"q"`
	Qa []string `json:"qA"`
}

type Keys struct {
	PublicKey  string `json:"public-key"`
	PrivateKey string `json:"private-key"`
}

type SignMessageRequest struct {
	Message string `json:"message"`
}

type VerifySignatureResponse struct {
	IsValid bool `json:"is_valid"`
}

type VerifyRequest struct {
	R         string `json:"r"`
	S         string `json:"s"`
	PublicKey string `json:"public-key"`
	Message   string `json:"message"`
}

type SignMessageResponse struct {
	R          string `json:"r"`
	S          string `json:"s"`
	Сiphertext string `json:"ciphertext"`
}

type Encrypt struct {
	Сiphertext string `json:"ciphertext"`
}

type Decrypted struct {
	DecryptedText string `json:"decrypted-text"`
}
