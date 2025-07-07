# Guide d'utilisation
- git clone le repo
- Allez dans le dossier encrypt
- Modifiez le fichier message.txt de sorte à ce qu'on chiffre le contenu de ce fichier
- exécutez la commandesuivante :
    - .\encrypt_and_sign.exe -f .\message.txt -pub_key_dest .\key_dest.pub -priv_key_sender .\key_sender -pub_key_sender .\key_sender.pub
- Vous venez d'encrypter votre message et cela a généré un fichier message_secure.json
- Copiez-Coller ce fichier message_secure.json dans le repertoire /decrypt
- Pour déchiffrer ce message nous allons exécuter la commande suivant : 
    - .\decrypt.exe -f .\message_secure.json -priv_key_dest .\key_dest

# Encrypter un message


go build -o encryptor.exe encryptor.go

go run .\main.go -f .\message.txt -pub_key_dest .\key_dest.pub -priv_key_sender .\key_sender -pub_key_sender .\key_sender.pub
ou 
.\encrypt_and_sign.exe -f .\message.txt -pub_key_dest .\key_dest.pub -priv_key_sender .\key_sender -pub_key_sender .\key_sender.pub

# Decrypter un message

go run .\main.go -f .\message_secure.json -priv_key_dest .\key_dest 
ou 
.\decrypt.exe -f .\message_secure.json -priv_key_dest .\key_dest
