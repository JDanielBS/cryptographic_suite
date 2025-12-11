# Suite Criptográfica

Suite de herramientas criptográficas implementada en Python para el laboratorio de Programación Segura.

## 📋 Características

- **Message Digest**: Generación de resúmenes digitales (MD5, SHA-1, SHA-256, SHA-384, SHA-512, HMAC)
- **Firma Digital**: Generación y verificación de firmas con RSA (PSS y Textbook)
- **Cifrado RSA**: Cifrado con clave privada y pública
- **Cifrado Simétrico**: DES (ECB/CFB), AES (CBC), ARC4
- **Cifrado Híbrido**: RSA + AES-GCM
- **Curvas Elípticas**: ECDSA (secp256k1, secp384r1, secp521r1) y Ed25519

## 🚀 Instalación

### Prerrequisitos

- Python 3.8 o superior
- pip (gestor de paquetes de Python)

### Pasos de instalación

1. **Clonar o descargar el repositorio**

2. **Crear un entorno virtual**

```bash
python -m venv venv
```

3. **Activar el entorno virtual**

   - En Windows:
   ```bash
   venv\Scripts\activate
   ```

   - En Linux/Mac:
   ```bash
   source venv/bin/activate
   ```

4. **Instalar las dependencias**

```bash
pip install -r requirements.txt
```

## ▶️ Ejecución

Para ejecutar la suite criptográfica:

```bash
python crypto_suite/main.py
```

Esto abrirá la interfaz gráfica principal desde donde podrás acceder a todos los módulos implementados.

## 📁 Estructura del proyecto

```
secure_programming/
├── crypto_suite/
│   ├── main.py              # Punto de entrada de la aplicación
│   ├── backend/             # Lógica de negocio
│   │   ├── message_digest_logic.py
│   │   ├── digital_signature_logic.py
│   │   ├── encryption_logic.py
│   │   └── elliptic_curves_logic.py
│   └── ui/                  # Interfaces gráficas
│       ├── message_digest_ui.py
│       ├── digital_signature_ui.py
│       ├── encryption_ui.py
│       └── elliptic_curves_ui.py
├── requirements.txt
└── README.md
```

## 🔧 Tecnologías utilizadas

- **Python 3**: Lenguaje principal
- **cryptography**: Biblioteca criptográfica principal
- **tkinter**: Framework para interfaces gráficas
- **pycryptodome**: Funcionalidades criptográficas adicionales

## 📝 Notas

- Algunos algoritmos (DES-ECB, ARC4, RSA Textbook) están marcados como **inseguros** y se incluyen únicamente con fines educativos.
- Se recomienda usar los algoritmos modernos (AES, RSA-PSS, Ed25519) para aplicaciones reales.

## 👨‍💻 Autor

Desarrollado para el curso de Programación Segura
