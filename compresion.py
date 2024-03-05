import os
import subprocess
import gzip
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

def backup_compress_encrypt_database(username, password, database_name, private_key_path, output_file):
    # Hacer el respaldo de la base de datos utilizando mysqldump
    mysqldump_command = f"mysqldump -u {username} -p{password} {database_name}"
    database_dump = subprocess.check_output(mysqldump_command, shell=True)

    # Comprimir el respaldo utilizando gzip
    compressed_data = gzip.compress(database_dump)

    # Encriptar el respaldo comprimido utilizando una clave privada
    with open(private_key_path, "rb") as private_key_file:
        private_key = serialization.load_pem_private_key(
            private_key_file.read(),
            password=None,
            backend=default_backend()
        )

    encrypted_data = private_key.sign(
        compressed_data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # Guardar el archivo comprimido y encriptado
    with open(output_file, "wb") as output_file:
        output_file.write(encrypted_data)

def decrypt_decompress_restore_database(encrypted_file, public_key_path, username, password, database_name):
    # Desencriptar el archivo utilizando una clave pública
    with open(public_key_path, "rb") as public_key_file:
        public_key = serialization.load_pem_public_key(
            public_key_file.read(),
            backend=default_backend()
        )

    with open(encrypted_file, "rb") as input_file:
        encrypted_data = input_file.read()

    try:
        decrypted_data = public_key.verify(
            encrypted_data,
            encrypted_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except Exception as e:
        print(f"Error al desencriptar: {e}")
        return

    # Descomprimir el archivo desencriptado
    decompressed_data = gzip.decompress(decrypted_data)

    # Guardar el archivo descomprimido temporalmente
    temp_filename = "temp.sql"
    with open(temp_filename, "wb") as temp_file:
        temp_file.write(decompressed_data)

    # Restaurar la base de datos desde el archivo descomprimido
    restore_command = f"mysql -u {username} -p{password} {database_name} < {temp_filename}"
    subprocess.run(restore_command, shell=True)

    # Eliminar el archivo temporal
    os.remove(temp_filename)

# Configuración de la base de datos
db_username = "tu_usuario"
db_password = "tu_contraseña"
db_name = "tu_base_de_datos"

# Configuración de las claves
private_key_path = "private_key.pem"
public_key_path = "public_key.pem"

# Comprimir y encriptar la base de datos
backup_filename = "backup.dat"
backup_compress_encrypt_database(db_username, db_password, db_name, private_key_path, backup_filename)

# Desencriptar y descomprimir para restaurar la base de datos
decrypt_decompress_restore_database(backup_filename, public_key_path, db_username, db_password, db_name)
