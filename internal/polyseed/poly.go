package polyseed

import (
	"io"
	"encoding/binary"

	"github.com/tuneinsight/lattigo/v6/ring"
	"golang.org/x/crypto/sha3"
)

// https://github.com/FutureTPM/ROTed/blob/arm/include/rlweke.hpp#L98
func Mod2(sk, k, sig *ring.Poly, q, qov2 uint64) {
	for i := 0; i < len(sk.Coeffs[0]); i++ {
		sk.Coeffs[0][i] = 0
	}

	for i := 0; i < len(sk.Coeffs[0]); i++ {
		if sig.Coeffs[0][i] == 1 {
			sk.Coeffs[0][i] = qov2
		}
	}

	for i := 0; i < len(sk.Coeffs[0]); i++ {
		sk.Coeffs[0][i] = (sk.Coeffs[0][i] + k.Coeffs[0][i]) % q
	}

	for i := 0; i < len(sk.Coeffs[0]); i++ {
		var ski int64
		if sk.Coeffs[0][i] <= qov2 {
			ski = int64(sk.Coeffs[0][i])
		} else {
			ski = int64(sk.Coeffs[0][i]) - int64(q)
		}
		sk.Coeffs[0][i] = uint64(ski & 1)
	}
}

func Uint64SliceToBytes(slice []uint64) []byte {
	buf := make([]byte, 8*len(slice))
	for i, v := range slice {
		binary.BigEndian.PutUint64(buf[i*8:], v)
	}
	return buf
}

func NewPolyFromSeed(r *ring.Ring, seed []byte) (*ring.Poly, error) {
	pol := r.NewPoly()
	N := r.N()
	level := r.Level()

	prg := sha3.NewShake256()
	_, _ = prg.Write(seed)

	for i := 0; i <= level; i++ {
		for j := 0; j < N; j++ {
			var buf [8]byte
			if _, err := io.ReadFull(prg, buf[:]); err != nil {
				return nil, err
			}
			val := binary.LittleEndian.Uint64(buf[:]) % r.Modulus().Uint64()
			pol.Coeffs[i][j] = val
		}
	}

	return &pol, nil
}

func Cha(k, ko ring.Poly, q uint64) {
	qDiv4 := q / 4
	negQDiv4 := q - qDiv4

	N := len(k.Coeffs[0])
	level := len(k.Coeffs) - 1

	for l := 0; l <= level; l++ {
		coeffs := k.Coeffs[l]
		coeffsOut := ko.Coeffs[l]
		for i := 0; i < N; i++ {
			val := coeffs[i]
			if val > qDiv4 && val < negQDiv4 {
				coeffsOut[i] = 1 // Not in E
			} else {
				coeffsOut[i] = 0 // In E
			}
		}
	}
}
