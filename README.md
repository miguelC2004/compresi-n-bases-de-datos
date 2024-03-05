### Proyecto de Backup, Compresión y Encriptación de Bases de Datos MySQL

Este proyecto realiza una serie de operaciones para respaldar, comprimir, encriptar, desencriptar, descomprimir y restaurar una base de datos MySQL

## Requisitos

- Python 3.x
- MySQL Server
- Paquetes de Python:
  - cryptography
  - gzip
  - subprocess

## Instalación

1. Clona el repositorio o copia los archivos en tu sistema.
2. Instala las dependencias utilizando `pip install -r requirements.txt`.

## Uso

1. **Respaldar, comprimir y encriptar la base de datos:**

   ```python
   import os
   import subprocess
   import gzip
   from cryptography.hazmat.backends import default_backend
   from cryptography.hazmat.primitives.asymmetric import rsa, padding
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

   # Configuración de la base de datos y las claves
   db_username = "server"
   db_password = ""
   db_name = "base_de_datos"
   private_key_path = "private_key.pem"
   backup_filename = "backup.dat"

   # Llamada a la función
   backup_compress_encrypt_database(db_username, db_password, db_name, private_key_path, backup_filename)
   ```
   
   2. **Desencriptar, descomprimir y restaurar la base de datos:**
   ```python
   def decrypt_decompress_restore_database(encrypted_file, public_key_path, output_file):
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

    # Restaurar la base de datos desde el archivo descomprimido
    restore_command = f"mysql -u {username} -p{password} {database_name}"
    subprocess.run(restore_command, input=decompressed_data, shell=True)
   ```
