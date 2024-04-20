package main

import (
	"crypto/aes"
	"crypto/cipher"
	randez "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"math/rand"
	"net/http"
	"time"
)

const (
	keyCrypt = "xd-key-lol-kek-cheburec123456789"
)

var (
	currentKey *PrivateKey
)

func main() {

	http.HandleFunc("/generate-primes", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			p, pA, err := generatePrime(1024)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				http.Error(w, fmt.Sprintf("Ошибка генерации простого числа p: %v", err), http.StatusInternalServerError)
				return
			}

			q, qA, err := generatePrime(1024)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				http.Error(w, fmt.Sprintf("Ошибка генерации простого числа q: %v", err), http.StatusInternalServerError)
				return
			}

			resp := Prime{
				P: p.String(),
				Q: q.String(),
			}

			log.Print(len(pA), len(qA))
			for i := 0; i < 10; i++ {
				resp.Pa = append(resp.Pa, pA[i].String())
				resp.Qa = append(resp.Qa, qA[i].String())
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		}
	})
	http.HandleFunc("/generate-keys", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			params, err := generateDSAParameters()
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				http.Error(w, fmt.Sprintf("Ошибка генерации параметров DSA: %v", err), http.StatusInternalServerError)
				return
			}

			privateKey, err := generateDSAKeys(params)
			if err != nil {
				http.Error(w, fmt.Sprintf("Ошибка генерации ключей DSA: %v", err), http.StatusInternalServerError)
				return
			}

			currentKey = privateKey
			resp := Keys{
				PublicKey:  privateKey.Y.String(),
				PrivateKey: privateKey.X.String(),
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		}
	})
	http.HandleFunc("/sign-message", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			var request SignMessageRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				http.Error(w, "Неправильный запрос", http.StatusBadRequest)
				return
			}

			key := []byte(keyCrypt)
			encryptedMessage, err := encrypt(request.Message, key)
			if err != nil {
				http.Error(w, fmt.Sprintf("Ошибка шифровки сообщения: %v", err), http.StatusInternalServerError)
				return
			}

			r, s, err := signMessage(currentKey, []byte(encryptedMessage))
			if err != nil {
				http.Error(w, fmt.Sprintf("Ошибка подписания сообщения: %v", err), http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(SignMessageResponse{
				R:          r.String(),
				S:          s.String(),
				Сiphertext: encryptedMessage,
			})
		}
	})
	http.HandleFunc("/verify-message", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			var request VerifyRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				http.Error(w, "Неправильный запрос", http.StatusBadRequest)
				return
			}

			n := new(big.Int)

			_, success := n.SetString(request.PublicKey, 10)
			if !success {
				http.Error(w, "Недопустимый ключ!", http.StatusBadRequest)
				return
			}

			currentKey.Y = n

			r := new(big.Int)

			_, success = r.SetString(request.R, 10)
			if !success {
				http.Error(w, "Недопустимая подпись r!", http.StatusBadRequest)
				return
			}

			s := new(big.Int)

			_, success = s.SetString(request.S, 10)
			if !success {
				http.Error(w, "Недопустимая подпись s!", http.StatusBadRequest)
				return
			}

			isValid := verifySignature(&currentKey.PublicKey, []byte(request.Message), r, s)

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(VerifySignatureResponse{IsValid: isValid})
		}
	})
	http.HandleFunc("/encrypt-message", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			var request Encrypt
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				http.Error(w, "Неправильный запрос", http.StatusBadRequest)
				return
			}

			key := []byte(keyCrypt)
			decryptedMessage, err := decrypt(request.Сiphertext, key)
			if err != nil {
				http.Error(w, fmt.Sprintf("Ошибка расшифровки сообщения: %v", err), http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(Decrypted{DecryptedText: decryptedMessage})
		}
	})

	log.Fatal(http.ListenAndServe(":8080", nil))

}

func millerRabin(n, a *big.Int) bool {
	if a.Cmp(big.NewInt(1)) == 0 || a.Cmp(n) == 0 {
		return true
	}

	nMinus1 := new(big.Int).Sub(n, big.NewInt(1))
	s := big.NewInt(0)
	d := new(big.Int).Set(nMinus1)
	for d.Bit(0) == 0 {
		s.Add(s, big.NewInt(1))
		d.Rsh(d, 1)
	}

	aPowD := new(big.Int).Exp(a, d, n)
	if aPowD.Cmp(big.NewInt(1)) == 0 || aPowD.Cmp(nMinus1) == 0 {
		return true
	}

	for i := big.NewInt(1); i.Cmp(s) == -1; i.Add(i, big.NewInt(1)) {
		aPowD.Exp(aPowD, big.NewInt(2), n)
		if aPowD.Cmp(nMinus1) == 0 {
			return true
		}
	}

	return false
}

func IsPrime(n *big.Int, certainty int) (bool, []*big.Int) {
	if n.Cmp(big.NewInt(2)) == -1 {
		return false, nil
	}

	if n.Cmp(big.NewInt(2)) == 0 {
		return true, nil
	}

	if n.Bit(0) == 0 {
		return false, nil
	}

	as := make([]*big.Int, 0, 10)
	for i := 0; i < certainty; i++ {
		a := new(big.Int).Rand(rand.New(rand.NewSource(time.Now().UnixNano())), new(big.Int).Sub(n, big.NewInt(3)))
		a.Add(a, big.NewInt(2))

		as = append(as, a)
		if !millerRabin(n, a) {
			return false, nil
		}
	}

	return true, as
}

func generateRandomNumber(bits int) *big.Int {
	return new(big.Int).Rand(rand.New(rand.NewSource(time.Now().UnixNano())), new(big.Int).Lsh(big.NewInt(1), uint(bits)))
}

func generatePrime(bits int) (*big.Int, []*big.Int, error) {
	for {
		n := generateRandomNumber(bits)

		prime, as := IsPrime(n, 10)
		if prime {
			return n, as, nil
		}
	}
}

func generateDSAParameters() (*Parameters, error) {
	// Создаем новый объект для параметров DSA
	params := new(Parameters)

	// Генерируем параметры DSA
	err := GenerateParameters(params, randez.Reader, L1024N160)
	if err != nil {
		return nil, err
	}

	return params, nil
}

// Функция для генерации ключей DSA
func generateDSAKeys(params *Parameters) (*PrivateKey, error) {
	privateKey := new(PrivateKey)
	privateKey.Parameters = *params

	err := GenerateKey(privateKey, randez.Reader)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func signMessage(privateKey *PrivateKey, message []byte) (r, s *big.Int, err error) {
	hashedMessage := sha256.Sum256(message)

	r, s, err = Sign(randez.Reader, privateKey, hashedMessage[:])
	if err != nil {
		return nil, nil, err
	}

	return r, s, nil
}

func verifySignature(publicKey *PublicKey, message []byte, r, s *big.Int) bool {
	hashedMessage := sha256.Sum256(message)

	return Verify(publicKey, hashedMessage[:], r, s)
}

func encrypt(text string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(randez.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(text), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decrypt(encryptedText string, key []byte) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedText)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", fmt.Errorf("malformed ciphertext")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
