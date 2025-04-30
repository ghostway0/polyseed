package polyseed

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"io"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"

	"github.com/ghostway0/polyseed/internal/polyseed"
)

const (
	SeedH1         = "H1"
	SeedH2         = "H2"
	SeedH3         = "H3"
	SeedSessionKey = "Session"
)

type CryptoContext struct {
	params rlwe.Parameters
	ringQ  *ring.Ring
}

func NewCryptoContext() (*CryptoContext, error) {
	paramLiteral := rlwe.ParametersLiteral{
		LogN: 14,
		Q: []uint64{0x200000008001, 0x400018001,
			0x3fffd0001, 0x400060001,
			0x400068001, 0x3fff90001,
			0x400080001, 0x4000a8001,
			0x400108001, 0x3ffeb8001},
		P:        []uint64{},
		RingType: ring.Standard,
	}

	params, err := rlwe.NewParametersFromLiteral(paramLiteral)
	if err != nil {
		return nil, fmt.Errorf("failed to create parameters: %w", err)
	}

	ringQ, err := ring.NewRing(params.N(), params.Q())
	if err != nil {
		return nil, fmt.Errorf("failed to create ring: %w", err)
	}

	return &CryptoContext{
		params: params,
		ringQ:  ringQ,
	}, nil
}

func Client(ctx *CryptoContext, rw io.ReadWriter, clientID [16]byte, password []byte) ([]byte, error) {
	if _, err := rw.Write(clientID[:]); err != nil {
		return nil, fmt.Errorf("failed to send client ID: %w", err)
	}

	serverID := make([]byte, 16)
	if _, err := rw.Read(serverID); err != nil {
		return nil, fmt.Errorf("failed to read server ID: %w", err)
	}

	a, err := polyseed.NewPolyFromSeed(ctx.ringQ, append(clientID[:], serverID...))
	if err != nil {
		return nil, err
	}

	prng, err := sampling.NewPRNG()
	if err != nil {
		return nil, fmt.Errorf("failed to create PRNG: %w", err)
	}

	errorGaussian := ring.NewGaussianSampler(prng, ctx.ringQ, rlwe.DefaultXe, true)
	secretGaussian, err := ring.NewSampler(prng, ctx.ringQ, rlwe.DefaultXs, true)
	if err != nil {
		return nil, fmt.Errorf("failed to create secret sampler: %w", err)
	}

	// Sample polynomials s_C and e_C
	s_C := ctx.ringQ.NewPoly()
	e_C := ctx.ringQ.NewPoly()
	errorGaussian.Read(e_C)
	secretGaussian.Read(s_C)

	// alpha = a * s_C + 2e_C
	alpha := ctx.ringQ.NewPoly()
	ctx.ringQ.MulCoeffsMontgomery(*a, s_C, alpha)
	ctx.ringQ.MulScalarThenAdd(e_C, 2, alpha)

	// Compute gamma = H₁(pw)
	hash := sha256.New()
	hash.Write([]byte(SeedH1))
	hash.Write(password)
	gamma := hash.Sum(nil)

	gamma_poly, err := polyseed.NewPolyFromSeed(ctx.ringQ, gamma)
	if err != nil {
		return nil, err
	}

	// Send m = alpha + gamma to the server
	m := ctx.ringQ.NewPoly()
	ctx.ringQ.Add(alpha, *gamma_poly, m)

	if _, err := m.WriteTo(rw); err != nil {
		return nil, fmt.Errorf("failed to send m to server: %w", err)
	}

	// Receive (mu, w, k) from server
	mu := ctx.ringQ.NewPoly()
	if _, err := mu.ReadFrom(rw); err != nil {
		return nil, fmt.Errorf("failed to read mu from server: %w", err)
	}

	w := ctx.ringQ.NewPoly()
	if _, err := w.ReadFrom(rw); err != nil {
		return nil, fmt.Errorf("failed to read w from server: %w", err)
	}

	k := make([]byte, 32)
	if _, err := rw.Read(k); err != nil {
		return nil, fmt.Errorf("failed to read k from server: %w", err)
	}

	// Compute k_C = s_C * mu
	k_C := ctx.ringQ.NewPoly()
	ctx.ringQ.MulCoeffsMontgomery(s_C, mu, k_C)

	// Compute sigma_C = Mod2(k_C, w)
	sigma_C := ctx.ringQ.NewPoly()
	polyseed.Mod2(&sigma_C, &k_C, &w, ctx.params.Q()[0], ctx.params.Q()[0]/2)

	// Verify k == H₂(C, S, m, mu, sigma_C, -gamma)
	neg_gamma := ctx.ringQ.NewPoly()
	ctx.ringQ.Neg(*gamma_poly, neg_gamma)

	hash = sha256.New()
	hash.Write([]byte(SeedH2))
	hash.Write(clientID[:])
	hash.Write(serverID)
	hash.Write(polyseed.Uint64SliceToBytes(m.Coeffs[0]))
	hash.Write(polyseed.Uint64SliceToBytes(mu.Coeffs[0]))
	hash.Write(polyseed.Uint64SliceToBytes(sigma_C.Coeffs[0]))
	hash.Write(polyseed.Uint64SliceToBytes(neg_gamma.Coeffs[0]))
	k_expected := hash.Sum(nil)

	if subtle.ConstantTimeCompare(k, k_expected) != 1 {
		return nil, fmt.Errorf("verification failed, aborting")
	}

	hash = sha256.New()
	hash.Write([]byte(SeedH3))
	hash.Write(clientID[:])
	hash.Write(serverID)
	hash.Write(polyseed.Uint64SliceToBytes(m.Coeffs[0]))
	hash.Write(polyseed.Uint64SliceToBytes(mu.Coeffs[0]))
	hash.Write(polyseed.Uint64SliceToBytes(sigma_C.Coeffs[0]))
	hash.Write(polyseed.Uint64SliceToBytes(neg_gamma.Coeffs[0]))
	k_prime := hash.Sum(nil)

	hash = sha256.New()
	hash.Write([]byte(SeedSessionKey))
	hash.Write(clientID[:])
	hash.Write(serverID)
	hash.Write(polyseed.Uint64SliceToBytes(m.Coeffs[0]))
	hash.Write(polyseed.Uint64SliceToBytes(mu.Coeffs[0]))
	hash.Write(polyseed.Uint64SliceToBytes(sigma_C.Coeffs[0]))
	hash.Write(polyseed.Uint64SliceToBytes(neg_gamma.Coeffs[0]))
	sk_C := hash.Sum(nil)

	// Send k_prime to server
	if _, err := rw.Write(k_prime); err != nil {
		return nil, fmt.Errorf("failed to send k_prime to server: %w", err)
	}

	return sk_C, nil
}

func Server(ctx *CryptoContext, rw io.ReadWriter, serverID [16]byte, password []byte) ([]byte, error) {
	clientID := make([]byte, 16)
	if _, err := rw.Read(clientID); err != nil {
		return nil, fmt.Errorf("failed to read client ID: %w", err)
	}

	if _, err := rw.Write(serverID[:]); err != nil {
		return nil, fmt.Errorf("failed to send server ID: %w", err)
	}

	// Derive gamma' = -H₁(pw)
	hash := sha256.New()
	hash.Write([]byte(SeedH1))
	hash.Write(password)
	gamma := hash.Sum(nil)

	// Receive m from client
	m := ctx.ringQ.NewPoly()
	if _, err := m.ReadFrom(rw); err != nil {
		return nil, fmt.Errorf("failed to read m from client: %w", err)
	}

	// alpha = m + gamma'
	gamma_poly, err := polyseed.NewPolyFromSeed(ctx.ringQ, gamma)
	if err != nil {
		return nil, fmt.Errorf("failed to convert gamma to polynomial: %w", err)
	}

	gamma_prime := ctx.ringQ.NewPoly()
	ctx.ringQ.Neg(*gamma_poly, gamma_prime)

	alpha := ctx.ringQ.NewPoly()
	ctx.ringQ.Add(m, gamma_prime, alpha)

	// Sample s_S, e_S ← χβ
	prng, err := sampling.NewPRNG()
	if err != nil {
		return nil, fmt.Errorf("failed to create PRNG: %w", err)
	}
	secretGaussian, err := ring.NewSampler(prng, ctx.ringQ, rlwe.DefaultXs, true)
	if err != nil {
		return nil, fmt.Errorf("failed to create secret sampler: %w", err)
	}
	errorGaussian := ring.NewGaussianSampler(prng, ctx.ringQ, rlwe.DefaultXe, true)

	s_S := ctx.ringQ.NewPoly()
	e_S := ctx.ringQ.NewPoly()
	secretGaussian.Read(s_S)
	errorGaussian.Read(e_S)

	a, err := polyseed.NewPolyFromSeed(ctx.ringQ, append(clientID, serverID[:]...))

	// mu = a * s_S + 2e_S
	mu := ctx.ringQ.NewPoly()
	ctx.ringQ.MulCoeffsMontgomery(s_S, *a, mu)
	ctx.ringQ.MulScalarThenAdd(e_S, 2, mu)

	// k_S = alpha * s_S
	k_S := ctx.ringQ.NewPoly()
	ctx.ringQ.MulCoeffsMontgomery(alpha, s_S, k_S)

	// w = Cha(k_S)
	w := ctx.ringQ.NewPoly()
	polyseed.Cha(k_S, w, ctx.params.Q()[0])

	// sigma = Mod2(k_S, w)
	sigma := ctx.ringQ.NewPoly()
	polyseed.Mod2(&sigma, &k_S, &w, ctx.params.Q()[0], ctx.params.Q()[0]/2)

	// k = H₂(C, S, m, mu, sigma, gamma_prime)
	hash = sha256.New()
	hash.Write([]byte(SeedH2))
	hash.Write([]byte(clientID))
	hash.Write(serverID[:])
	hash.Write(polyseed.Uint64SliceToBytes(m.Coeffs[0]))
	hash.Write(polyseed.Uint64SliceToBytes(mu.Coeffs[0]))
	hash.Write(polyseed.Uint64SliceToBytes(sigma.Coeffs[0]))
	hash.Write(polyseed.Uint64SliceToBytes(gamma_prime.Coeffs[0]))
	k := hash.Sum(nil)

	// k_prime = H₃(C, S, m, mu, sigma, gamma_prime)
	hash = sha256.New()
	hash.Write([]byte(SeedH3))
	hash.Write([]byte(clientID))
	hash.Write(serverID[:])
	hash.Write(polyseed.Uint64SliceToBytes(m.Coeffs[0]))
	hash.Write(polyseed.Uint64SliceToBytes(mu.Coeffs[0]))
	hash.Write(polyseed.Uint64SliceToBytes(sigma.Coeffs[0]))
	hash.Write(polyseed.Uint64SliceToBytes(gamma_prime.Coeffs[0]))
	k_prime := hash.Sum(nil)

	// Send (mu, w, k) to client
	if _, err := mu.WriteTo(rw); err != nil {
		return nil, fmt.Errorf("failed to send mu: %w", err)
	}
	if _, err := w.WriteTo(rw); err != nil {
		return nil, fmt.Errorf("failed to send w: %w", err)
	}
	if _, err := rw.Write(k); err != nil {
		return nil, fmt.Errorf("failed to send k: %w", err)
	}

	// Receive k' from client
	clientK := make([]byte, 32)
	if _, err := rw.Read(clientK); err != nil {
		return nil, fmt.Errorf("failed to read k_prime from client: %w", err)
	}

	// If k_prime == k_prime, derive sk_S
	if subtle.ConstantTimeCompare(clientK, k_prime) != 1 {
		return nil, fmt.Errorf("authentication failed: k_prime mismatch")
	}

	hash = sha256.New()
	hash.Write([]byte(SeedSessionKey))
	hash.Write([]byte(clientID))
	hash.Write(serverID[:])
	hash.Write(polyseed.Uint64SliceToBytes(m.Coeffs[0]))
	hash.Write(polyseed.Uint64SliceToBytes(mu.Coeffs[0]))
	hash.Write(polyseed.Uint64SliceToBytes(sigma.Coeffs[0]))
	hash.Write(polyseed.Uint64SliceToBytes(gamma_prime.Coeffs[0]))
	sk_S := hash.Sum(nil)

	return sk_S, nil
}
