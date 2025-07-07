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

func main() {
	//---------------------------------------------------------------------------------------------------------------

	messageSecure := flag.String("f", "", "Un fichier message_secure.json contenant le message à déchiffrer")
	filePrivateKeyDest := flag.String("priv_key_dest", "", "Clé privé du destinataire pour déchiffré la donnée")

	flag.Parse()
	if *messageSecure == "" {
		fmt.Fprintln(os.Stderr, "Aucun fichier à déchiffrer n'est passé en entrée, option -f")
		os.Exit(1)

	}
	// go run .\main.go -f .\message_secure.json -priv_key_dest
	if *filePrivateKeyDest == "" {
		fmt.Fprintln(os.Stderr, "Clé privé du destinataire absente, option -priv_key_dest")
		os.Exit(1)

	}
	messageSecureData, _ := os.ReadFile(*messageSecure)
	var messageSecureJson Message
	json.Unmarshal(messageSecureData, &messageSecureJson)
	privateKeyRsa := retrievePrivateKeyRsa(*filePrivateKeyDest)
	EncIvDecode, _ := base64.StdEncoding.DecodeString(messageSecureJson.EncIV)
	EncSecretDecode, _ := base64.StdEncoding.DecodeString(messageSecureJson.EncKey)
	EncCipherText, _ := base64.StdEncoding.DecodeString(messageSecureJson.Ciphertext)
	SignatureM, _ := base64.StdEncoding.DecodeString(messageSecureJson.Signature)
	publicKeySenderRsa := retrieveBase64RSAPublicKey(messageSecureJson.PubKeySenderSignature)

	ivDecrypt, _ := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKeyRsa, EncIvDecode, []byte(""))
	secretDecrypt, _ := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKeyRsa, EncSecretDecode, []byte(""))
	ciphertextDecrypt, _ := aesgcm.Decrypt(EncCipherText, ivDecrypt, secretDecrypt)
	ciphertextDecryptHashed := sha256.Sum256(ciphertextDecrypt)
	errSignature := rsa.VerifyPKCS1v15(publicKeySenderRsa, crypto.SHA256, ciphertextDecryptHashed[:], SignatureM)

	if errSignature != nil {
		fmt.Println("Signature incorrecte")
	} else {
		fmt.Println("Signature correcte")
	}
	os.WriteFile("message_secure_decrypted.txt", ciphertextDecrypt, 0666)

}

func retrieveBase64RSAPublicKey(pubKeyBase64 string) *rsa.PublicKey {
	// 1. Décodage base64
	pubKeyBytes, err := base64.StdEncoding.DecodeString(pubKeyBase64)
	if err != nil {
		log.Fatalf("Erreur de décodage base64 : %v", err)
	}

	// Pour vérifier que ça ressemble bien à du SSH :
	if !bytes.HasPrefix(pubKeyBytes, []byte("ssh-rsa")) {
		log.Fatalf("Le contenu décodé ne commence pas par 'ssh-rsa'")
	}

	// 2. Parsing SSH
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(pubKeyBytes)
	if err != nil {
		log.Fatalf("Erreur de parsing de la clé SSH : %v", err)
	}

	// 3. Extraction de la clé RSA
	cryptoPubKey, ok := pubKey.(ssh.CryptoPublicKey)
	if !ok {
		log.Fatalf("Clé SSH non compatible avec crypto")
	}

	rsaPubKey, ok := cryptoPubKey.CryptoPublicKey().(*rsa.PublicKey)
	if !ok {
		log.Fatalf("Clé n'est pas de type RSA")
	}

	return rsaPubKey
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
