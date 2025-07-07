# Guide d'utilisation
- git clone le repo
- Modifiez le fichier message.txt de sorte à ce qu'on chiffre le contenu de ce fichier
- exécutez la commandesuivante :
    - .\encrypt_and_sign.exe -f .\message.txt -pub_key_dest .\key_dest.pub -priv_key_sender .\key_sender -pub_key_sender .\key_sender.pub
- Vous venez d'encrypter votre message et cela a généré un fichier message_secure.json
- Pour déchiffrer ce message nous allons exécuter la commande suivant : 
    - .\decrypt.exe -f .\message_secure.json -priv_key_dest .\key_dest
    - Regardez dans le terminal si la signature a bien été validé
    - Regardez si votre message déchiffré et est identique à la source grâce au fichier message_secure_decrypted.txt