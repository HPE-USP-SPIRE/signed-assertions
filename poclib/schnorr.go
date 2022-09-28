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
func Sign(m string, z kyber.Scalar) Signature {
    // Get the base of the curve.
    g := curve.Point().Base()

    // Pick a random k from allowed set.
    k := curve.Scalar().Pick(curve.RandomStream())

    // r = k * G (a.k.a the same operation as r = g^k)
    r := curve.Point().Mul(k, g)

    // h := Hash(publicKey + m + r.String())
    publicKey := curve.Point().Mul(z, g)
    h := Hash(publicKey.String() + m + r.String())
    
    // s = k - e * x
    s := curve.Scalar().Add(k, curve.Scalar().Mul(h, z))

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

    // h = Hash(pubkey || m || r)
    h := Hash(y.String() + m + S.R.String())

    // Attempt to reconstruct 's * G' with a provided signature; s * G = r - h * y
    sGv := curve.Point().Add(S.R, curve.Point().Mul(h, y))

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

    // working for max 2 hops.

    // Create a generator.
    g := curve.Point().Base()

    // Hash(pubkey || m || r)
    h0          := Hash(pubkey0.String() + m0 + s0.R.String())
    h1          := Hash(pubkey1.String() + m1 + s1.R.String())

    // y1 = r0 - pubkey0 * h0 
    y1          := curve.Point().Add(s0.R, curve.Point().Mul(h0, pubkey0))
    // check y1 correctness
    // testvalue   := curve.Point().Mul(s0.S, g)
    // if y1.Equal(testvalue) == true {
    //     fmt.Println("y1 valido")
    // }

    // check: g ^s1 == r1 - y1 ^h1 
    leftside    := curve.Point().Mul(s1.S, g)
    rightside   := curve.Point().Add(s1.R, curve.Point().Mul(h1, y1))

    // verify r1 * ((r0 * y0) * h0) * h1 = g * s1

    return leftside.Equal(rightside)
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