package dasvid

import (
  "fmt"
//   "flag"
  "go.dedis.ch/kyber/v3"
  "go.dedis.ch/kyber/v3/group/edwards25519"
  "bytes"
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
    

    // MAM:
    // DUVIDA: Aqui ele faz k - e*x, mas nos slides temos k + e * x. Tanto faz?
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
// y: Public key
func Verifygg(m0 string, S0 Signature, m1 string, S1 Signature) bool {
    // Create a generator.
    g := curve.Point().Base()

    // Hash(pubkey || m || r)
    tmph0          := Hash(m0 + S0.R.String())
    var h0 kyber.Point
	bufh0 := bytes.NewBuffer([]byte(tmph0.String()))
	if err := curve.Read(bufh0, &h0); err != nil {
		fmt.Printf("Error! value: %s\n",  err)
		return false
	}

    tmph1          := Hash(m1 + S1.R.String())
    var h1 kyber.Point
	bufh1 := bytes.NewBuffer([]byte(tmph1.String()))
	if err := curve.Read(bufh1, &h1); err != nil {
		fmt.Printf("Error! value: %s\n",  err)
		return false
	}

    tmpy0          := PublicKey(m0, S0)
    var y0 kyber.Scalar
	bufy0 := bytes.NewBuffer([]byte(tmpy0.String()))
	if err := curve.Read(bufy0, &y0); err != nil {
		fmt.Printf("Error! value: %s\n",  err)
		return false
	}

    var S0R kyber.Scalar
	bufS0R := bytes.NewBuffer([]byte(S0.R.String()))
	if err := curve.Read(bufS0R, &S0R); err != nil {
		fmt.Printf("Error! value: %s\n",  err)
		return false
	}

    var S1R kyber.Scalar
	bufS1R := bytes.NewBuffer([]byte(S1.R.String()))
	if err := curve.Read(bufS1R, &S1R); err != nil {
		fmt.Printf("Error! value: %s\n",  err)
		return false
	}

    tmpy1          := curve.Point().Mul(S0R, curve.Point().Mul(y0, h0))
    var y1 kyber.Scalar
	bufy1 := bytes.NewBuffer([]byte(tmpy1.String()))
	if err := curve.Read(bufy1, &y1); err != nil {
		fmt.Printf("Error! value: %s\n",  err)
		return false
	}

    var scalarS1 kyber.Scalar
	bufscalarS1 := bytes.NewBuffer([]byte(S1.String()))
	if err := curve.Read(bufscalarS1, &scalarS1); err != nil {
		fmt.Printf("Error! value: %s\n",  err)
		return false
	}

    leftside    := curve.Point().Mul(S1R, curve.Point().Mul(y1, h1))
    rightside   := curve.Point().Mul(scalarS1, g)

    // return equality result
    return leftside.Equal(rightside)
    
    // h0 := Hash(r0.String() + m0 + S0.R.String())
    // h1 := Hash(r1.String() + m1 + S1.R.String())

    // verify r1 * ((r0 * y0) * h0) * h1 = g * s1
    // y1 = r0 * y0 ^ h0
    // r1 * y1 ^ h1 = g ^ s1  
    // curve.Point().Mul(r0, curve.Point().Add(k, S0.R))
    // curve.Point().Mul(r1, )


    // Attempt to reconstruct 's * G' with a provided signature; s * G = r - e * y
    // sGv := curve.Point().Sub(S.R, curve.Point().Mul(e, y))

    // Construct the actual 's * G'
    // sG := curve.Point().Mul(S.S, g)

    // Equality check; ensure signature and public key outputs to s * G.
    // return sG.Equal(sGv)
}

// Não sei se faz sentido ter essa função. 
// Pensei que poderia ser útil para as workloads terem/obterem seus respectivos keypair, dado um id secreto
func IDKeyPair(id string) (kyber.Scalar, kyber.Point){

    // Given ID, return a keypair 
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