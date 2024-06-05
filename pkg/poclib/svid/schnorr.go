package svid

import (
	"fmt"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519"
)

// Set parameters
var curve = edwards25519.NewBlakeSHA256Ed25519()
var sha256 = curve.Hash()
var g = curve.Point().Base()

type Signature struct {
	R kyber.Point
	S kyber.Scalar
}

// 	Sign signs a message using Schnorr EdDSA.
//
//	This function generates a signature for the provided message
// using Schnorr EdDSA algorithm.
//	It picks a random scalar 'k' from the allowed set,
// calculates the public key 'r' as 'k * G',
// where 'G' is the base point of the curve,
// calculates the hash 'h' of '(r + message + publicKey)',
// and finally calculates the scalar 's' as 'k - h * privateKey'.

// m: Message
// x: Private key
func Sign(m string, z kyber.Scalar) Signature {

	// Pick a random k from allowed set.
	k := curve.Scalar().Pick(curve.RandomStream())

	// r = k * G (a.k.a the same operation as r = g^k)
	r := curve.Point().Mul(k, g)

	// h := Hash(r.String() + m + publicKey)
	publicKey := curve.Point().Mul(z, g)
	h := Hash(r.String() + m + publicKey.String())

	// s = k - e * x
	s := curve.Scalar().Sub(k, curve.Scalar().Mul(h, z))

	return Signature{R: r, S: s}
}

//	Verify verifies Schnorr EdDSA signatures.
//	This function verifies a signature for a given message
//
// using Schnorr EdDSA algorithm.
//
//	It calculates the hash 'h' of '(R + message + publicKey)',
//
// attempts to reconstruct 's * G' using the provided
// signature where 'G' is the base point of the curve,
// and finally checks if the reconstructed point
// equals the actual 's * G'.
//
// m: Message
// s: Signature
// y: Public key
func Verify(m string, S Signature, y kyber.Point) bool {

	h := Hash(S.R.String() + m + y.String())

	// Attempt to reconstruct 's * G' with a provided signature; s * G = r - h * y
	sGv := curve.Point().Sub(S.R, curve.Point().Mul(h, y))

	// Construct the actual 's * G'
	sG := curve.Point().Mul(S.S, g)

	// Equality check; ensure signature and public key outputs to s * G.
	return sG.Equal(sGv)
}

//	Verifygg verifies concatenated EdDSA signatures using Galindo-Garcia algorithm.
//
//	It takes the original public key,
// an array of signature points (Sig.R),
// an array of hash scalars, and the last
// signature scalar (Sig.S) as input parameters.
//	The function calculates intermediate
// points 'y' from the first to the last-1 parts,
// and then calculates the last 'y'.
//	Finally, it checks if 'g ^ lastsig.S' equals 'lastsig.R - y ^ lastHash'.

// origpubkey: first public key
// setSigR: array with all Sig.R
// setH: array with all Hashes
// lastsigS: last signature.S
func Verifygg(origpubkey kyber.Point, setSigR []kyber.Point, setH []kyber.Scalar, lastsigS kyber.Scalar) bool {

	// Important to note that as new assertions are added in the beginning of the token, the content of arrays is in reverse order.
	// e.g. setSigR[0] = last appended signature.
	if (len(setSigR)) != len(setH) {
		fmt.Println("Incorrect parameters!")
		return false
	}

	var i = len(setSigR) - 1
	var y kyber.Point

	// calculate all y's from first to last-1 parts
	for i > 0 {
		if i == len(setSigR)-1 {
			y = origpubkey
		} else {
			y = curve.Point().Sub(setSigR[i+1], curve.Point().Mul(setH[i+1], y))
		}
		i--
	}

	// calculate last y
	y = curve.Point().Sub(setSigR[i+1], curve.Point().Mul(setH[i+1], y))

	// check if g ^ lastsig.S = lastsig.R - y ^ lastHash
	leftside := curve.Point().Mul(lastsigS, g)
	rightside := curve.Point().Sub(setSigR[i], curve.Point().Mul(setH[i], y))

	return leftside.Equal(rightside)
}

// IDKeyPair generates a key pair based on the provided ID.
//
//	This function takes an ID string as input
//
// and generates a key pair using the Schnorr EdDSA algorithm.
//
//	It generates a private key by hashing
//
// the provided ID string and then calculates the
// corresponding public key by multiplying the
// private key with the base point of the curve.
func IDKeyPair(id string) (kyber.Scalar, kyber.Point) {

	privateKey := Hash(id)
	publicKey := curve.Point().Mul(privateKey, curve.Point().Base())

	return privateKey, publicKey
}

//	RandomKeyPair generates a new random key pair
//
// using the Schnorr EdDSA algorithm.
//
//	It generates a random private key and
//
// calculates the corresponding public key
// by multiplying the private key with
// the base point of the curve.
func RandomKeyPair() (kyber.Scalar, kyber.Point) {

	privateKey := curve.Scalar().Pick(curve.RandomStream())
	publicKey := curve.Point().Mul(privateKey, curve.Point().Base())

	return privateKey, publicKey
}

// Given string, return hash Scalar
func Hash(s string) kyber.Scalar {
	sha256.Reset()
	sha256.Write([]byte(s))

	return curve.Scalar().SetBytes(sha256.Sum(nil))
}

func (S Signature) String() string {
	return fmt.Sprintf("(r=%s, s=%s)", S.R, S.S)
}

func CompactGGValidation(concKey kyber.Point, concSigR kyber.Point, m string, sigS kyber.Scalar) bool {

	// 	// now, there is only one signature. The 'r' part is the hash of all r parts concatenated. The 's' part is from the last signature.
	// 	// the validation uses the hash of payload, the r part

	//     // // check if g ^ lastsig.S = lastsig.R - y ^ lastHash
	//     // leftside    := curve.Point().Mul(lastsigS, g)
	//     // rightside   := curve.Point().Sub(SigR, curve.Point().Mul(H, y0))

	//     // return leftside.Equal(rightside)

	h := Hash(concSigR.String() + m + concKey.String())

	y := curve.Point().Sub(concSigR, curve.Point().Mul(h, concKey))
	// check if g ^ lastsig.S = lastsig.R - y ^ lastHash
	rightside := curve.Point().Mul(sigS, g)

	return y.Equal(rightside)

}

// // Verify concatenated EdDSA signatures using Galindo-Garcia
// // origpubkey: first public key
// // setSigR: array with all Sig.R
// // setH: array with all Hashes
// // lastsigS: last signature.S
// func CompactGGValidation(origpubkey kyber.Point, setSigR []kyber.Point, setH []kyber.Scalar, lastsigS kyber.Scalar) bool {

//     // Important to note that as new assertions are added in the beginning of the token, the content of arrays is in reverse order.
//     // e.g. setSigR[0] = last appended signature.
//     if (len(setSigR)) != len(setH) {
//         fmt.Println("Incorrect parameters!")
//         return false
//     }

//     var i = len(setSigR)-1
//     var y kyber.Point

//     // calculate all y's from first to last-1 parts
// 	for (i > 0) {
//         if (i == len(setSigR)-1) {
//             y = origpubkey
//         } else {
//             y = curve.Point().Sub(setSigR[i+1], curve.Point().Mul(setH[i+1], y))
//         }
//         i--
//     }

//     // calculate last y
//     y = curve.Point().Sub(setSigR[i+1], curve.Point().Mul(setH[i+1], y))

//     // check if g ^ lastsig.S = lastsig.R - y ^ lastHash
//     leftside    := curve.Point().Mul(lastsigS, g)
//     rightside   := curve.Point().Sub(setSigR[i], curve.Point().Mul(setH[i], y))

//     return leftside.Equal(rightside)
// }
