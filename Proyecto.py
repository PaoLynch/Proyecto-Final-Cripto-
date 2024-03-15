import os
import base64
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives import padding
import secrets
import sqlite3
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def create_tables_if_not_exist():

# Creación de tablas
    c.execute('''
        CREATE TABLE IF NOT EXISTS eddsa_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT, 
            file_name TEXT, 
            public_key TEXT
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS rsa_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT, 
            file_name TEXT, 
            public_key TEXT
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS minute_signatures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_name TEXT NOT NULL,
            joint_signature TEXT NOT NULL
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS memorandum_signatures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_name TEXT,
            signature_base64 TEXT
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS confidential_memorandums (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_name TEXT,
            signature_base64 TEXT,
            encrypted_text TEXT,
            encrypted_aes_key TEXT
        )
    ''')

    conn.commit()

# Función para generar un par de claves usando ed25519
def generate_key_pair_ed25519():

    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key

# Función para guardar una clave privada en un archivo PEM
def save_private_key(private_key, file_name):

    with open(file_name, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

# Función para guardar una clave pública en un archivo PEM
def save_public_key(public_key, file_name):

    with open(file_name, 'wb') as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    # Guardar la clave pública en la base de datos
    c.execute("INSERT INTO eddsa_keys (file_name, public_key) VALUES (?, ?)", (file_name, public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')))
    conn.commit()

def generate_rsa_keys():
    # Generar llaves RSA
    private_key_rsa = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    public_key_rsa = private_key_rsa.public_key()

    # Pedir el nombre y ruta para guardar la llave privada RSA
    private_key_rsa_name = input("Ingrese el nombre para la llave privada RSA: ")
    with open(f'{private_key_rsa_name}.pem', 'wb') as f:
        f.write(private_key_rsa.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Pedir el nombre y ruta para guardar la llave pública RSA
    public_key_rsa_name = input("Ingrese el nombre para la llave pública RSA: ")
    with open(f'{public_key_rsa_name}.pem', 'wb') as f:
        f.write(public_key_rsa.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    # Guardar la clave pública RSA en la base de datos
    c.execute("INSERT INTO rsa_keys (file_name, public_key) VALUES (?, ?)", (public_key_rsa_name, public_key_rsa.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')))
    conn.commit()

def sign_file_minutes(file_path):
    with open(file_path, 'rb') as file:
        data = file.read()

    num_people = int(input("Ingrese la cantidad de personas que van a firmar: "))

    signatures = []

    for i in range(num_people):
        key_path = input(f"Ingrese la ruta de la llave privada {i+1} (en formato .pem): ")

        with open(key_path, 'rb') as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )

        signature = private_key.sign(data)
        signature_base64 = base64.b64encode(signature).decode('utf-8')
        signatures.append(signature_base64)

    # Guardar la firma conjunta en la base de datos
    save_joint_signature_to_db(file_path, '\n'.join(signatures))

# Función para guardar la firma conjunta en la base de datos
def save_joint_signature_to_db(file_name, joint_signature):
    c.execute('INSERT INTO minute_signatures (file_name, joint_signature) VALUES (?, ?)',
                (file_name, joint_signature))
    conn.commit()
    print("Firma conjunta guardada en la base de datos.")

def verify_file_minutes(file_path):
    with open(file_path, 'rb') as file:
        data = file.read()

    # Mostrar las firmas disponibles en la base de datos
    print("Firmas disponibles:")
    c.execute('SELECT id, file_name FROM minute_signatures')
    signatures = c.fetchall()

    for signature in signatures:
        print(f"{signature[0]}. {signature[1]}")

    # Permitir al usuario seleccionar una firma por su ID
    signature_id = input("Seleccione el número de ID de la firma que desea verificar: ")

    # Obtener la firma seleccionada desde la base de datos
    c.execute('SELECT joint_signature FROM minute_signatures WHERE id = ?', (signature_id,))
    joint_signature = c.fetchone()

    if joint_signature:
        signatures = joint_signature[0].split('\n')

        num_people = len(signatures)

        for i in range(num_people):
            # Mostrar las llaves públicas de edDSA disponibles
            print("Llaves públicas de edDSA disponibles:")
            c.execute('SELECT id, file_name FROM eddsa_keys')
            public_keys = c.fetchall()

            for key in public_keys:
                print(f"{key[0]}. {key[1]}")

            # Permitir al usuario seleccionar una llave por su ID
            key_id = input(f"Seleccione el número de ID de la llave pública {i+1} que desea utilizar: ")

            # Obtener la llave pública seleccionada desde la base de datos
            c.execute('SELECT public_key FROM eddsa_keys WHERE id = ?', (key_id,))
            public_key_pem = c.fetchone()

            if public_key_pem:
                public_key = serialization.load_pem_public_key(
                    public_key_pem[0].encode('utf-8'),
                    backend=default_backend()
                )

                signature_base64 = signatures[i]
                signature = base64.b64decode(signature_base64)

                try:
                    public_key.verify(signature, data)
                    print(f"Firma {i+1} verificada con éxito usando la llave pública seleccionada.")
                except Exception as e:
                    print(f"Firma {i+1} no válida: {e}")
            else:
                print("Llave pública no encontrada.")
    else:
        print("Firma no encontrada.")

def sign_file_memorandums(file_path, private_key_path):
    with open(file_path, 'rb') as file:
        data = file.read()

    with open(private_key_path, 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

    signature = private_key.sign(data)
    signature_base64 = base64.b64encode(signature).decode('utf-8')
    c.execute('''
        INSERT INTO memorandum_signatures (file_name, signature_base64) VALUES (?, ?)
    ''', (file_path, signature_base64))
    conn.commit()

    
def verify_file_memorandums(file_path):
    with open(file_path, 'rb') as file:
        data = file.read()

    # Mostrar las firmas disponibles en la base de datos
    print("Firmas disponibles:")
    c.execute('SELECT id, file_name FROM memorandum_signatures')
    signatures = c.fetchall()

    for signature in signatures:
        print(f"{signature[0]}. {signature[1]}")

    # Permitir al usuario seleccionar una firma por su ID
    signature_id = input("Seleccione el número de ID de la firma que desea verificar: ")

    # Obtener la firma seleccionada desde la base de datos
    c.execute('SELECT signature_base64 FROM memorandum_signatures WHERE id = ?', (signature_id,))
    signature_base64 = c.fetchone()

    if signature_base64:
        signature = base64.b64decode(signature_base64[0])
        
        # Mostrar las llaves públicas de edDSA disponibles
        print("Llaves públicas de edDSA disponibles:")
        c.execute('SELECT id, file_name FROM eddsa_keys')
        public_keys = c.fetchall()

        for key in public_keys:
            print(f"{key[0]}. {key[1]}")

        # Permitir al usuario seleccionar una llave por su ID
        key_id = input("Seleccione el número de ID de la llave pública que desea utilizar: ")

        # Obtener la llave pública seleccionada desde la base de datos
        c.execute('SELECT public_key FROM eddsa_keys WHERE id = ?', (key_id,))
        public_key_pem = c.fetchone()

        if public_key_pem:
            public_key = serialization.load_pem_public_key(
                public_key_pem[0].encode('utf-8'),
                backend=default_backend()
            )

            try:
                public_key.verify(signature, data)
                print(f"Firma verificada con éxito usando la llave pública seleccionada.")
            except Exception as e:
                print(f"Firma no válida: {e}")
        else:
            print("Llave pública no encontrada.")
    else:
        print("Firma no encontrada.")

def sign_and_encrypt():

    # Pedir al usuario la ruta del archivo a firmar y encriptar
    file_path = input("Ingrese la ruta del archivo que desea firmar y encriptar: ")

    # Preguntar al usuario si desea generar llaves RSA
    generate_rsa = input("¿Desea generar llaves RSA? (s/n): ").lower()

    if generate_rsa == 's':
        generate_rsa_keys()
    
    # Generar una llave AES
    aes_key = secrets.token_bytes(16)

    # Preguntar al usuario la ruta del archivo de la llave privada edDSA
    private_key_eddsa_path = input("Ingrese la ruta del archivo de la llave privada edDSA (en formato .pem): ")
    with open(private_key_eddsa_path, 'rb') as f:
        private_key_eddsa = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )

    # Firmar el archivo
    with open(file_path, 'rb') as f:
        data = f.read()

    # Agregar relleno (padding) si es necesario
    if len(data) % 16 != 0:
        data += b' ' * (16 - len(data) % 16)

    signature = private_key_eddsa.sign(data)

    # Convertir la firma a Base64
    signature_base64 = base64.b64encode(signature).decode('utf-8')

    # Guardar la firma en la base de datos
    c.execute('''
        INSERT INTO confidential_memorandums (file_name, signature_base64, encrypted_text, encrypted_aes_key)
        VALUES (?, ?, ?, ?)
    ''', (file_path, signature_base64, None, None))
    conn.commit()

    # Buscar llaves públicas de RSA en la base de datos
    c.execute('SELECT id, file_name FROM rsa_keys')
    rsa_keys = c.fetchall()

    if not rsa_keys:
        print("No hay llaves públicas RSA disponibles en la base de datos.")
        return

    # Mostrar las llaves públicas de RSA disponibles
    print("Llaves públicas de RSA disponibles:")
    for key in rsa_keys:
        print(f"{key[0]}. {key[1]}")

    # Permitir al usuario seleccionar una llave por su ID
    rsa_key_id = input("Seleccione el número de ID de la llave pública RSA que desea utilizar: ")

    # Obtener la llave pública RSA seleccionada desde la base de datos
    c.execute('SELECT public_key FROM rsa_keys WHERE id = ?', (rsa_key_id,))
    public_key_rsa_pem = c.fetchone()

    if public_key_rsa_pem:
        public_key_rsa = serialization.load_pem_public_key(
            public_key_rsa_pem[0].encode('utf-8'),
            backend=default_backend()
        )

        # Generar la llave cifrada y guardarla en la base de datos
        encrypted_aes_key = public_key_rsa.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Guardar la llave cifrada en la base de datos
        c.execute('''
            UPDATE confidential_memorandums
            SET encrypted_aes_key = ?
            WHERE file_name = ?
        ''', (sqlite3.Binary(encrypted_aes_key), file_path))
        conn.commit()

        # Cifrar el archivo con AES en modo CBC
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(b'\0' * 16), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()

        # Guardar el texto cifrado en la base de datos
        c.execute('''
            UPDATE confidential_memorandums
            SET encrypted_text = ?
            WHERE file_name = ?
        ''', (sqlite3.Binary(ciphertext), file_path))
        conn.commit()

        print(f"Archivo '{file_path}' cifrado y firmado correctamente.")
    else:
        print("Llave pública RSA no encontrada.")
  
def decrypt_and_verify():
    # Mostrar los archivos cifrados disponibles en la base de datos
    print("Archivos cifrados disponibles:")
    c.execute('SELECT id, file_name FROM confidential_memorandums WHERE encrypted_text IS NOT NULL AND encrypted_aes_key IS NOT NULL')
    encrypted_files = c.fetchall()

    if not encrypted_files:
        print("No hay archivos cifrados disponibles en la base de datos.")
        return

    # Mostrar los archivos cifrados disponibles
    for encrypted_file in encrypted_files:
        print(f"{encrypted_file[0]}. {encrypted_file[1]}")

    # Permitir al usuario seleccionar un archivo por su ID
    encrypted_file_id = input("Seleccione el número de ID del archivo cifrado que desea descifrar: ")

    # Obtener el archivo cifrado seleccionado desde la base de datos
    c.execute('SELECT file_name, encrypted_text, encrypted_aes_key FROM confidential_memorandums WHERE id = ?', (encrypted_file_id,))
    encrypted_data = c.fetchone()

    if encrypted_data:
        file_name, encrypted_text, encrypted_aes_key = encrypted_data

        # Pedir al usuario la ruta del archivo de la llave privada RSA
        private_key_rsa_path = input("Ingrese la ruta del archivo de la llave privada RSA (en formato .pem): ")

        # Cargar la llave privada RSA desde el archivo
        with open(private_key_rsa_path, 'rb') as private_key_file:
            private_key_rsa = serialization.load_pem_private_key(
                private_key_file.read(),
                password=None,
                backend=default_backend()
            )

        # Descifrar la llave AES con RSA-OAEP
        aes_key = private_key_rsa.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Descifrar el archivo con AES en modo CBC
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(b'\0' * 16), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_text) + decryptor.finalize()

        # Verificar la firma
        c.execute('SELECT signature_base64 FROM confidential_memorandums WHERE id = ?', (encrypted_file_id,))
        signature_base64 = c.fetchone()

        if signature_base64:
            signature = base64.b64decode(signature_base64[0])

            # Buscar llaves públicas de edDSA en la base de datos
            c.execute('SELECT id, file_name FROM eddsa_keys')
            eddsa_keys = c.fetchall()

            if not eddsa_keys:
                print("No hay llaves públicas de edDSA disponibles en la base de datos.")
                return

            # Mostrar las llaves públicas de edDSA disponibles
            print("Llaves públicas de edDSA disponibles:")
            for key in eddsa_keys:
                print(f"{key[0]}. {key[1]}")

            # Permitir al usuario seleccionar una llave por su ID
            eddsa_key_id = input("Seleccione el número de ID de la llave pública edDSA que desea utilizar: ")

            # Obtener la llave pública edDSA seleccionada desde la base de datos
            c.execute('SELECT public_key FROM eddsa_keys WHERE id = ?', (eddsa_key_id,))
            public_key_eddsa_pem = c.fetchone()

            if public_key_eddsa_pem:
                public_key_eddsa = serialization.load_pem_public_key(
                    public_key_eddsa_pem[0].encode('utf-8'),
                    backend=default_backend()
                )

                try:
                    public_key_eddsa.verify(signature, decrypted_data)
                    print("Verificación exitosa.")

                    # Guardar el contenido descifrado en un nuevo archivo
                    output_file_path = f'decrypted_{file_name}'
                    with open(output_file_path, 'wb') as output_file:
                        output_file.write(decrypted_data)

                    print(f"Contenido del archivo guardado en: {output_file_path}")
                except Exception as e:
                    print("Error en la verificación:", e)
            else:
                print("Llave pública edDSA no encontrada.")
        else:
            print("Firma no encontrada.")
    else:
        print("Archivo cifrado no encontrado.")

        
# Menú principal
while True:
    # Conexión a la base de datos
    conn = sqlite3.connect('documentos.db')
    c = conn.cursor()
    # Llamamos a la función para crear las tablas
    create_tables_if_not_exist()
    print("1. Generar llaves")
    print("2. Ingresar un documento")
    print("3. Verificar o descifrar")
    print("4. Salir")
    option = input("Seleccione una opción: ")

    if option == "1":
        # Pedir al usuario el nombre de los archivos de llaves
        private_key_file = input("Ingrese el nombre del archivo de llave privada (sin extensión): ") + '.pem'
        public_key_file = input("Ingrese el nombre del archivo de llave pública (sin extensión): ") + '.pem'

        # Generar un par de claves y guardar la clave privada en un archivo PEM
        private_key, public_key = generate_key_pair_ed25519()
        save_private_key(private_key, private_key_file)
        save_public_key(public_key, public_key_file)

        print(f"Llaves generadas y guardadas en {private_key_file} y {public_key_file}")

    elif option == "2":
        # Pedir al usuario el tipo de documento
        print("Seleccione el tipo de documento: ")
        print("1. Minute")
        print("2. Memorandum")
        print("3. Memorandum Confidencial")
        document_type = input("Seleccione una opción: ")

        if document_type == "1":
            file_path = input("Ingrese la ruta del archivo que desea firmar: ")
            sign_file_minutes(file_path)

        elif document_type == "2":
            file_to_sign = input("Ingrese la ruta del archivo que desea firmar: ")
            private_key_to_use = input("Ingrese la ruta de la llave privada (en formato .pem): ")
            sign_file_memorandums(file_to_sign, private_key_to_use)

        elif document_type == "3":
            sign_and_encrypt()

        else:
            print("Tipo de documento no válido. Solo se permite 'minute', 'memorandum' o 'memorandum confidencial'.")
    
    elif option =="3":
        # Pedir al usuario el tipo de documento
        print("Seleccione el tipo de documento: ")
        print("1. Minute")
        print("2. Memorandum")
        print("3. Memorandum Confidencial")
        document_type = input("Seleccione una opción: ")
        
        if document_type == "1":
            file_path = input("Ingrese la ruta del archivo original: ")
            verify_file_minutes(file_path)

        elif document_type == "2":
            file_to_verify = input("Ingrese la ruta del archivo original: ")
            verify_file_memorandums(file_to_verify)

        elif document_type == "3":  
            decrypt_and_verify()

        else:
            print("Tipo de documento no válido. Solo se permite 'minute', 'memorandum' o 'memorandum confidencial'.")

    elif option == "4":
        break

    else:
        print("Opción inválida")