# 📝 FIRMA DIGITAL - Punto 1b
## Resumen de Funcionamiento

### 🎯 Objetivo
Implementar un sistema de firma digital usando RSA que permite:
- Generar pares de claves (pública/privada)
- Firmar mensajes con la clave privada
- Verificar firmas con la clave pública

---

## 🔧 Tecnologías Utilizadas

### Biblioteca Criptográfica
- **cryptography** (Python 3.13+)
  - Módulo: `cryptography.hazmat.primitives.asymmetric.rsa`
  - Algoritmo: RSA con padding PSS
  - Hashing: SHA-256, SHA-384, SHA-512

### Interfaz Gráfica
- **tkinter** - Interfaz gráfica nativa de Python
- Diseño oscuro profesional con tabs

---

## 📋 Funcionalidades Implementadas

### 1️⃣ Generación de Claves (Tab 1)
**Proceso:**
1. El usuario selecciona el tamaño de clave (1024, 2048 o 4096 bits)
2. Se genera un par de claves RSA usando `rsa.generate_private_key()`
3. Las claves se serializan en formato PEM
4. Se muestran en la interfaz:
   - **Clave Pública**: Para compartir con otros
   - **Clave Privada**: Mantener en secreto
5. Opciones de exportación:
   - Guardar en archivos `.pem`
   - Copiar al portapapeles

**Código base:**
```python
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()
```

---

### 2️⃣ Firmar Mensaje (Tab 2)
**Proceso:**
1. Cargar o usar la clave privada generada
2. Escribir el mensaje a firmar
3. Seleccionar algoritmo hash (SHA-256/384/512)
4. Al hacer clic en "Firmar Mensaje":
   - El mensaje se codifica a bytes
   - Se aplica el hash seleccionado
   - Se firma con RSA-PSS (Probabilistic Signature Scheme)
   - La firma se codifica en Base64 para visualización
5. Exportar firma:
   - Guardar en archivo `.sig`
   - Copiar al portapapeles

**Código base:**
```python
signature = private_key.sign(
    message.encode('utf-8'),
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
```

---

### 3️⃣ Verificar Firma (Tab 3)
**Proceso:**
1. Cargar la clave pública del firmante
2. Pegar o escribir el mensaje original
3. Pegar o cargar la firma digital
4. Al hacer clic en "Verificar Firma":
   - La firma se decodifica de Base64
   - Se intenta verificar con múltiples algoritmos hash
   - Si coincide: ✅ **FIRMA VÁLIDA**
   - Si no coincide: ❌ **FIRMA INVÁLIDA**

**Código base:**
```python
public_key.verify(
    signature,
    message.encode('utf-8'),
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
```

---

## 🔐 Conceptos Criptográficos

### RSA (Rivest-Shamir-Adleman)
- **Algoritmo asimétrico**: Usa dos claves diferentes
- **Clave privada**: Solo el propietario la conoce (para firmar)
- **Clave pública**: Se comparte con todos (para verificar)

### Proceso de Firma Digital
```
Mensaje Original
    ↓
Hash del mensaje (SHA-256)
    ↓
Cifrado con clave privada = FIRMA
    ↓
Firma + Mensaje se envían
```

### Proceso de Verificación
```
Firma recibida
    ↓
Descifrado con clave pública = Hash original
    ↓
Hash del mensaje recibido
    ↓
¿Coinciden? → Firma válida ✅
```

### PSS Padding
- **Probabilistic Signature Scheme**
- Más seguro que PKCS#1 v1.5
- Añade aleatoriedad para prevenir ataques

---

## 🚀 Cómo Usar

### Escenario 1: Generar y Firmar
1. Abrir el módulo desde el Home
2. Tab "Generar Claves" → Seleccionar 2048 bits → Generar
3. Guardar ambas claves (o solo usar en sesión)
4. Tab "Firmar Mensaje" → Escribir mensaje → Firmar
5. Guardar o copiar la firma

### Escenario 2: Verificar Firma de Terceros
1. Tab "Verificar Firma"
2. Cargar clave pública del firmante
3. Pegar mensaje original
4. Pegar firma recibida
5. Verificar → Ver resultado

---

## 📦 Dependencias

### Instalar en Python 3.13
```bash
pip install cryptography
```

### Verificar instalación
```bash
python -c "from cryptography.hazmat.primitives.asymmetric import rsa; print('OK')"
```

---

## 🔒 Seguridad

### ✅ Buenas Prácticas Implementadas
- Claves RSA de mínimo 2048 bits (recomendado)
- Uso de PSS padding (más seguro)
- Soporte para múltiples algoritmos hash
- Formato PEM estándar para portabilidad

### ⚠️ Consideraciones
- La clave privada se maneja en memoria sin cifrado
- Para producción, usar contraseña para serializar clave privada:
  ```python
  encryption_algorithm=serialization.BestAvailableEncryption(b'password')
  ```

---

## 🎨 Interfaz

### Características de UI
- **Tema oscuro profesional** (#1e1e1e)
- **3 tabs organizados** por funcionalidad
- **Botones intuitivos** con iconos
- **Áreas de texto** con scroll
- **Indicadores de estado** (✅/❌)
- **Mensajes claros** de error/éxito

### Esquema de Colores
- Background: `#1e1e1e` (negro suave)
- Accent: `#00ff88` (verde neón)
- Texto: `#ffffff` (blanco)
- Error: `#ff4444` (rojo)
- Success: `#00ff88` (verde)

---

## 🧪 Flujo de Prueba Completo

### Caso de Uso: Alice firma un mensaje para Bob

1. **Alice genera sus claves:**
   - Tab 1 → Generar 2048 bits
   - Guarda `alice_private.pem` (secreto)
   - Comparte `alice_public.pem` con Bob

2. **Alice firma un mensaje:**
   - Tab 2 → Carga `alice_private.pem`
   - Escribe: "Hola Bob, este mensaje es auténtico"
   - Firma con SHA-256
   - Guarda `mensaje_firma.sig`
   - Envía mensaje + firma a Bob

3. **Bob verifica la firma:**
   - Tab 3 → Carga `alice_public.pem`
   - Pega el mensaje original
   - Carga `mensaje_firma.sig`
   - Verifica → ✅ **FIRMA VÁLIDA**
   - Bob confirma que el mensaje es de Alice y no fue alterado

---

## 📚 Referencias

### Documentación
- [Cryptography Library](https://cryptography.io/en/latest/)
- [RSA (cryptography)](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/)
- [RFC 8017 - PKCS #1 v2.2](https://tools.ietf.org/html/rfc8017)

### Conceptos
- **Firma Digital**: Autenticación + Integridad
- **No-repudio**: El firmante no puede negar haber firmado
- **Integridad**: Detecta cualquier alteración del mensaje

---

## ✅ Cumplimiento del Punto 1b

### Requisito Original
> "Generar una firma Digital (Firmar y verificar)"

### Implementación
✅ Generación de claves RSA  
✅ Firma de mensajes con clave privada  
✅ Verificación de firmas con clave pública  
✅ Interfaz gráfica profesional  
✅ Integración con el Home principal  
✅ Soporte para múltiples algoritmos hash  
✅ Exportación/importación de claves y firmas  

---

**Desarrollado para:** Laboratorio de Programación Segura  
**Fecha:** Diciembre 2025  
**Tecnología:** Python 3.13 + cryptography + tkinter
