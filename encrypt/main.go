package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/boseji/auth/aesgcm"
	"golang.org/x/crypto/ssh"
)

type Message struct {
	Ciphertext            string   `json:"ciphertext"`
	EncKey                string   `json:"enc_key"`
	EncIV                 string   `json:"enc_iv"`
	PubKeyDestHash        [32]byte `json:"pubkeydest_hash"`
	Signature             string   `json:"signature"`
	PubKeySenderSignature string   `json:"pubkeysender_signature"`
	Algos                 Algos    `json:"algos"`
}

type Algos struct {
	Symmetric  string `json:"symmetric"`
	Asymmetric string `json:"asymmetric"`
	Hash       string `json:"hash"`
}

// crypto/aes, crypto/rsa, crypto/sha256, encoding/base64, encoding/json (tous natifs)
func main() {

	fileMessage := flag.String("f", "", "Un fichier message.txt contenant le message à chiffrer")
	filePublicKeyDest := flag.String("pub_key_dest", "", "Clé publique du destinataire pour chiffré la donnée")
	filePrivateKeySender := flag.String("priv_key_sender", "", "Clé privé de l'émetteur pour signer la donnée")
	filePublicKeySender := flag.String("pub_key_sender", "", "Clé privé de l'émetteur pour signer la donnée")

	flag.Parse()
	if *fileMessage == "" {
		fmt.Fprintln(os.Stderr, "Aucun fichier n'est passé en entrée, option -f")
		os.Exit(1)

	}
	if *filePublicKeyDest == "" {
		fmt.Fprintln(os.Stderr, "Clé publique du destinataire absente, option -pub_key_dest")
		os.Exit(1)

	}
	if *filePrivateKeySender == "" {
		fmt.Fprintln(os.Stderr, "Clé privé de l'émetteur absente, option -priv_key_sender")
		os.Exit(1)
	}
	if *filePublicKeySender == "" {
		fmt.Fprintln(os.Stderr, "Clé public de l'émetteur absente, option -pub_key_sender")
		os.Exit(1)
	}

	messageHex, _ := os.ReadFile(*fileMessage)

	publicKeyDestRsa, publicKeyDest := retrievePublicKeyRsa(*filePublicKeyDest)
	_, publicKeySender := retrievePublicKeyRsa(*filePublicKeySender)
	privateKeySenderRsa := retrievePrivateKeyRsa(*filePrivateKeySender)

	hashMessage := sha256.Sum256(messageHex)

	// Génération de iv + secret
	secret_key := generateKey(32)
	iv := generateKey(12)

	// Chiffrage symétrique du
	ciphertext, _, _ := aesgcm.Encrypt(messageHex, *secret_key, *iv)

	secretKeyEncrypt, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKeyDestRsa, *secret_key, []byte(""))
	ivEncrypt, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKeyDestRsa, *iv, []byte(""))
	publicKeyDestSha256 := sha256.Sum256([]byte(base64.StdEncoding.EncodeToString(publicKeyDest)))
	signature, _ := rsa.SignPKCS1v15(rand.Reader, privateKeySenderRsa, crypto.SHA256, hashMessage[:])

	// sha256Message := sha256.Sum256(messageHex)

	message_secure := Message{
		Ciphertext:            base64.StdEncoding.EncodeToString(ciphertext),
		EncKey:                base64.StdEncoding.EncodeToString(secretKeyEncrypt),
		EncIV:                 base64.StdEncoding.EncodeToString(ivEncrypt),
		PubKeyDestHash:        publicKeyDestSha256,
		Signature:             base64.StdEncoding.EncodeToString(signature),
		PubKeySenderSignature: base64.StdEncoding.EncodeToString(publicKeySender),
		Algos: Algos{
			Symmetric:  "AES-256-GCM",
			Asymmetric: "RSA-2048",
			Hash:       "SHA-256",
		},
	}

	reqBodyBytes := new(bytes.Buffer)
	json.NewEncoder(reqBodyBytes).Encode(message_secure)
	os.WriteFile("message_secure.json", reqBodyBytes.Bytes(), 0666)

}

func generateKey(octect int) *[]byte {
	secret_key := make([]byte, octect) // 32 octets = 256 bits
	// fmt.Printf("ma clé au début %s \n", secret_key)
	_, err := rand.Read(secret_key)
	if err != nil {
		log.Fatalf("Erreur lors de la génération de la clé : %v", err)
	}
	// fmt.Printf("ma clé à la fin %s \n", secret_key)
	return &secret_key
}

func retrievePublicKeyRsa(file string) (*rsa.PublicKey, []byte) {
	pubKeyData, _ := os.ReadFile(file)
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(pubKeyData)
	if err != nil {
		log.Fatalf("Erreur parse clé SSH : %v", err)
	}

	// Conversion vers *rsa.PublicKey
	cryptoPubKey, ok := pubKey.(ssh.CryptoPublicKey)
	if !ok {
		log.Fatalf("Clé non compatible avec crypto")
	}
	rsaPubKey, ok := cryptoPubKey.CryptoPublicKey().(*rsa.PublicKey)
	if !ok {
		log.Fatalf("Clé publique n'est pas RSA")
	}
	return rsaPubKey, pubKeyData
}

func retrievePrivateKeyRsa(file string) *rsa.PrivateKey {
	// Lire le fichier contenant la clé privée OpenSSH
	privBytes, err := os.ReadFile(file)
	if err != nil {
		log.Fatalf("Erreur lecture fichier : %v", err)
	}

	// Parser la clé privée brute
	privKey, _ := ssh.ParseRawPrivateKey(privBytes)

	if err != nil {
		log.Fatalf("Erreur parsing clé privée : %v", err)
	}

	// Tenter de convertir en clé RSA
	rsaPrivKey, ok := privKey.(*rsa.PrivateKey)
	if !ok {
		log.Fatalf("Clé privée n'est pas de type RSA")
	}
	return rsaPrivKey
}
