package dasvid

import (
  "fmt"
//   "flag"
  "go.dedis.ch/kyber/v3"
  "go.dedis.ch/kyber/v3/group/edwards25519"
//   "bytes"
)

var curve = edwards25519.NewBlakeSHA256Ed25519()
var sha256 = curve.Hash()

type Signature struct {
    R kyber.Point
    S kyber.Scalar
}

func Hash(s string) kyber.Scalar {
    sha256.Reset()
    sha256.Write([]byte(s))

    return curve.Scalar().SetBytes(sha256.Sum(nil))
}

// m: Message
// x: Private key
func Sign(m string, x kyber.Scalar) Signature {
    // Get the base of the curve.
    g := curve.Point().Base()

    // Pick a random k from allowed set.
    k := curve.Scalar().Pick(curve.RandomStream())

    // r = k * G (a.k.a the same operation as r = g^k)
    r := curve.Point().Mul(k, g)

    // MAM:
    // Sign function modified to add public key in hash. Otherwise it is possible to modify the token and generate a valid public key with PublicKey function
    // Original: Hash(m || r)
    // e := Hash(m + r.String())
    publicKey := curve.Point().Mul(x, curve.Point().Base())
    e := Hash(publicKey.String() + m + r.String())
    
    // s = k - e * x
    s := curve.Scalar().Sub(k, curve.Scalar().Mul(e, x))

    return Signature{R: r, S: s}
}

// m: Message
// S: Signature
func PublicKey(m string, S Signature) kyber.Point {
    // Create a generator.
    g := curve.Point().Base()

    // e = Hash(m || r)
    e := Hash(m + S.R.String())

    // y = (r - s * G) * (1 / e)
    y := curve.Point().Sub(S.R, curve.Point().Mul(S.S, g))
    y = curve.Point().Mul(curve.Scalar().Div(curve.Scalar().One(), e), y)

    return y
}

// m: Message
// s: Signature
// y: Public key
func Verify(m string, S Signature, y kyber.Point) bool {
    // Create a generator.
    g := curve.Point().Base()

    // e = Hash(m || r)
    // Hash(pubkey || m || r)
    e := Hash(y.String() + m + S.R.String())
    // e := Hash(m + S.R.String())

    // Attempt to reconstruct 's * G' with a provided signature; s * G = r - e * y
    sGv := curve.Point().Sub(S.R, curve.Point().Mul(e, y))

    // Construct the actual 's * G'
    sG := curve.Point().Mul(S.S, g)

    // Equality check; ensure signature and public key outputs to s * G.
    return sG.Equal(sGv)
}

func (S Signature) String() string {
    return fmt.Sprintf("(r=%s, s=%s)", S.R, S.S)
}

// m: Message
// s: Signature
// pubkey: Public keys
// S0.R, S1.R, S1
// y1 = (r0 * pubkey0)^h0
// verificar se (S1.R * y1)^h1 = g^s1
func Verifygg(m0 string, s0 Signature, pubkey0 kyber.Point, m1 string, s1 Signature, pubkey1 kyber.Point) bool {

    // UNDER DEVELOPMENT. NOT WORKING.


    // Create a generator.
    g := curve.Point().Base()

    // Hash(pubkey || m || r)
    h0          := Hash(pubkey0.String() + m0 + s0.R.String())
    h1          := Hash(pubkey1.String() + m1 + s1.R.String())

    // S0.R é um ponto e, por isso, não consigo multiplicar por (h0 * y0) pq é outro ponto.
    // tentei com add sem sucesso
    y1          := curve.Point().Sub(s0.R, curve.Point().Mul(h0, pubkey0))

    leftside    := curve.Point().Sub(s1.R, curve.Point().Mul(h1, y1))
    rightside   := curve.Point().Mul(s1.S, g)

    // return equality result
    return leftside.Equal(rightside)


    // verify r1 * ((r0 * y0) * h0) * h1 = g * s1
    // y1 = r0 * y0 ^ h0
    // r1 * y1 ^ h1 = g ^ s1  
    return false
}

// Given ID, return a keypair 
func IDKeyPair(id string) (kyber.Scalar, kyber.Point){


    privateKey	:= Hash(id)
    publicKey 	:= curve.Point().Mul(privateKey, curve.Point().Base())

    return privateKey, publicKey
}

// Return a new random key pair
func RandomKeyPair() (kyber.Scalar, kyber.Point){

    privateKey	:= curve.Scalar().Pick(curve.RandomStream())
    publicKey 	:= curve.Point().Mul(privateKey, curve.Point().Base())

    return privateKey, publicKey
}


// Example

// func main() {

//     message := "abc"
//     flag.Parse()
// //    args := flag.Args()
// //    message=args[0]

//     privateKey := curve.Scalar().Pick(curve.RandomStream())
//     publicKey := curve.Point().Mul(privateKey, curve.Point().Base())

//   fmt.Printf("Message to sign: %s\n\n", message)
//     fmt.Printf("Private key: %s\n", privateKey)
//     fmt.Printf("Public key: %s\n\n", publicKey)

//     signature := Sign(message, privateKey)

//     fmt.Printf("Signature (r=%s, s=%s)\n\n", signature.r, signature.s)

//     derivedPublicKey := PublicKey(message, signature)

//     fmt.Printf("Derived public key: %s\n\n", derivedPublicKey)

//     fmt.Printf("Checking keys %t\n", publicKey.Equal(derivedPublicKey))
//     fmt.Printf("Checking signature %t\n\n", Verify(message, signature, publicKey))
// }


// --------------- DRAFTS ---------------------
// Tentando implementar func que retorna um ponto, dado uma string, para usar esse ponto como public key.
//  not working. 

// func HashPoint(s string) kyber.Point {
//     sha256.Reset()
//     sha256.Write([]byte(s))

//     var pt kyber.Point
// 	bufpt := bytes.NewBuffer(sha256.Sum(nil))
// 	if err := curve.Read(bufpt, &pt); err != nil {
// 		fmt.Printf("Error! value: %s\n",  err)
// 		return nil
// 	}

//     return pt
// }