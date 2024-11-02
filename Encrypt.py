from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os

# Função para criptografar usando AES
def encrypt_aes(message, key):
    iv = os.urandom(16)  # Gera um IV aleatório
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Adiciona padding à mensagem
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_message = padder.update(message.encode()) + padder.finalize()
    
    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
    return iv + encrypted_message  # Retorna IV + mensagem criptografada

# Função para descriptografar usando AES
def decrypt_aes(encrypted_message, key):
    iv = encrypted_message[:16]  # Extrai o IV
    encrypted_message = encrypted_message[16:]
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # Descriptografa a mensagem
    padded_message = decryptor.update(encrypted_message) + decryptor.finalize()
    
    # Remove o padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    message = unpadder.update(padded_message) + unpadder.finalize()
    
    return message.decode()

def main():
    # Gera uma chave de 256 bits (32 bytes) para AES-256
    key = os.urandom(32)
    
    while True:
        # Solicita a entrada do usuário
        original_message = input("Insira o dado a ser Encryptado...\n")
        
        # Criptografa a mensagem
        encrypted_message = encrypt_aes(original_message, key)
        print("Encrypted Data:", encrypted_message.hex())
        
        # Descriptografa a mensagem
        decrypted_message = decrypt_aes(encrypted_message, key)
        print("Decrypted Data:", decrypted_message)
        
        print("\nAção executada com sucesso!")
        
        # Opção para sair do programa
        option = input("\n\tAperte a tecla 'q' + 'Enter' para sair do programa.\n\tSe deseja continuar aperte 'Enter'.\n").lower()
        if option == "q":
            break

    print("\nAté breve!")

if __name__ == "__main__":
    main()
