# Guide d'utilisation

# Encrypter un message


go build -o encryptor.exe encryptor.go

go run .\main.go -f .\message.txt -pub_key_dest .\key_dest.pub -priv_key_sender .\key_sender -pub_key_sender .\key_sender.pub
ou 
.\encrypt_and_sign.exe -f .\message.txt -pub_key_dest .\key_dest.pub -priv_key_sender .\key_sender -pub_key_sender .\key_sender.pub

# Decrypter un message

go run .\main.go -f .\message_secure.json -priv_key_dest .\key_dest 
ou 
.\decrypt.exe -f .\message_secure.json -priv_key_dest .\key_dest
