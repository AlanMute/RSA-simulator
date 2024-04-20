package main

import (
	"errors"
	"io"
	"math/big"
	"sync"
)

type Parameters struct {
	P, Q, G *big.Int
}

type PublicKey struct {
	Parameters
	Y *big.Int
}

type PrivateKey struct {
	PublicKey
	X *big.Int
}

var ErrInvalidPublicKey = errors.New("crypto/dsa: invalid public key")

type ParameterSizes int

const (
	L1024N160 ParameterSizes = iota
	L2048N224
	L2048N256
	L3072N256
)

const numMRTests = 64

func GenerateParameters(params *Parameters, rand io.Reader, sizes ParameterSizes) error {

	var L, N int
	switch sizes {
	case L1024N160:
		L = 1024
		N = 160
	case L2048N224:
		L = 2048
		N = 224
	case L2048N256:
		L = 2048
		N = 256
	case L3072N256:
		L = 3072
		N = 256
	default:
		return errors.New("crypto/dsa: invalid ParameterSizes")
	}

	qBytes := make([]byte, N/8)
	pBytes := make([]byte, L/8)

	q := new(big.Int)
	p := new(big.Int)
	rem := new(big.Int)
	one := new(big.Int)
	one.SetInt64(1)

GeneratePrimes:
	for {
		if _, err := io.ReadFull(rand, qBytes); err != nil {
			return err
		}

		qBytes[len(qBytes)-1] |= 1
		qBytes[0] |= 0x80
		q.SetBytes(qBytes)

		if !q.ProbablyPrime(numMRTests) {
			continue
		}

		for i := 0; i < 4*L; i++ {
			if _, err := io.ReadFull(rand, pBytes); err != nil {
				return err
			}

			pBytes[len(pBytes)-1] |= 1
			pBytes[0] |= 0x80

			p.SetBytes(pBytes)
			rem.Mod(p, q)
			rem.Sub(rem, one)
			p.Sub(p, rem)
			if p.BitLen() < L {
				continue
			}

			if !p.ProbablyPrime(numMRTests) {
				continue
			}

			params.P = p
			params.Q = q
			break GeneratePrimes
		}
	}

	h := new(big.Int)
	h.SetInt64(2)
	g := new(big.Int)

	pm1 := new(big.Int).Sub(p, one)
	e := new(big.Int).Div(pm1, q)

	for {
		g.Exp(h, e, p)
		if g.Cmp(one) == 0 {
			h.Add(h, one)
			continue
		}

		params.G = g
		return nil
	}
}

func GenerateKey(priv *PrivateKey, rand io.Reader) error {
	if priv.P == nil || priv.Q == nil || priv.G == nil {
		return errors.New("crypto/dsa: parameters not set up before generating key")
	}

	x := new(big.Int)
	xBytes := make([]byte, priv.Q.BitLen()/8)

	for {
		_, err := io.ReadFull(rand, xBytes)
		if err != nil {
			return err
		}
		x.SetBytes(xBytes)
		if x.Sign() != 0 && x.Cmp(priv.Q) < 0 {
			break
		}
	}

	priv.X = x
	priv.Y = new(big.Int)
	priv.Y.Exp(priv.G, x, priv.P)
	return nil
}

func fermatInverse(k, P *big.Int) *big.Int {
	two := big.NewInt(2)
	pMinus2 := new(big.Int).Sub(P, two)
	return new(big.Int).Exp(k, pMinus2, P)
}

func Sign(rand io.Reader, priv *PrivateKey, hash []byte) (r, s *big.Int, err error) {
	MaybeReadByte(rand)

	n := priv.Q.BitLen()
	if priv.Q.Sign() <= 0 || priv.P.Sign() <= 0 || priv.G.Sign() <= 0 || priv.X.Sign() <= 0 || n%8 != 0 {
		err = ErrInvalidPublicKey
		return
	}
	n >>= 3

	var attempts int
	for attempts = 10; attempts > 0; attempts-- {
		k := new(big.Int)
		buf := make([]byte, n)
		for {
			_, err = io.ReadFull(rand, buf)
			if err != nil {
				return
			}
			k.SetBytes(buf)

			if k.Sign() > 0 && k.Cmp(priv.Q) < 0 {
				break
			}
		}

		kInv := fermatInverse(k, priv.Q)

		r = new(big.Int).Exp(priv.G, k, priv.P)
		r.Mod(r, priv.Q)

		if r.Sign() == 0 {
			continue
		}

		z := k.SetBytes(hash)

		s = new(big.Int).Mul(priv.X, r)
		s.Add(s, z)
		s.Mod(s, priv.Q)
		s.Mul(s, kInv)
		s.Mod(s, priv.Q)

		if s.Sign() != 0 {
			break
		}
	}

	if attempts == 0 {
		return nil, nil, ErrInvalidPublicKey
	}

	return
}

func Verify(pub *PublicKey, hash []byte, r, s *big.Int) bool {

	if pub.P.Sign() == 0 {
		return false
	}

	if r.Sign() < 1 || r.Cmp(pub.Q) >= 0 {
		return false
	}
	if s.Sign() < 1 || s.Cmp(pub.Q) >= 0 {
		return false
	}

	w := new(big.Int).ModInverse(s, pub.Q)
	if w == nil {
		return false
	}

	n := pub.Q.BitLen()
	if n%8 != 0 {
		return false
	}
	z := new(big.Int).SetBytes(hash)

	u1 := new(big.Int).Mul(z, w)
	u1.Mod(u1, pub.Q)
	u2 := w.Mul(r, w)
	u2.Mod(u2, pub.Q)
	v := u1.Exp(pub.G, u1, pub.P)
	u2.Exp(pub.Y, u2, pub.P)
	v.Mul(v, u2)
	v.Mod(v, pub.P)
	v.Mod(v, pub.Q)

	return v.Cmp(r) == 0
}

var (
	closedChanOnce sync.Once
	closedChan     chan struct{}
)

func MaybeReadByte(r io.Reader) {
	closedChanOnce.Do(func() {
		closedChan = make(chan struct{})
		close(closedChan)
	})

	select {
	case <-closedChan:
		return
	case <-closedChan:
		var buf [1]byte
		r.Read(buf[:])
	}
}
