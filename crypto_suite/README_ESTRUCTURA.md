# 📁 Estructura del Proyecto - Suite Criptográfica

## 🎯 Separación de Responsabilidades

Este proyecto sigue el patrón de **separación de responsabilidades** (Separation of Concerns), dividiendo la lógica de negocio de la presentación.

```
crypto_suite/
│
├── backend/                    # 🧠 LÓGICA DE NEGOCIO (Backend)
│   ├── __init__.py
│   ├── message_digest_logic.py # Operaciones de hash y HMAC
│   └── ...                     # (Más módulos de lógica)
│
├── ui/                         # 🎨 INTERFACES GRÁFICAS (Frontend)
│   ├── __init__.py
│   ├── message_digest_ui.py    # UI para Message Digest
│   └── ...                     # (Más módulos de UI)
│
├── modules/                    # 📦 MÓDULOS LEGACY (A migrar)
│   ├── digital_signature_module.py
│   ├── encryption_module.py
│   └── message_digest_module.py  # [OBSOLETO - usar ui/message_digest_ui.py]
│
├── assets/                     # 🖼️ RECURSOS (imágenes, iconos)
├── utils/                      # 🛠️ UTILIDADES
├── main.py                     # 🏠 PUNTO DE ENTRADA PRINCIPAL
└── README_ESTRUCTURA.md        # 📖 Este archivo
```

---

## 🔑 Principios de Diseño

### 1️⃣ **Backend (Lógica de Negocio)**
- ✅ Sin dependencias de UI (no importa `tkinter`)
- ✅ Funciones puras y clases reutilizables
- ✅ Validación de datos
- ✅ Operaciones criptográficas
- ✅ Testeable de forma independiente

**Ejemplo:** `backend/message_digest_logic.py`
```python
class MessageDigestLogic:
    @staticmethod
    def generate_digest(message: str, algorithm: str) -> Dict:
        # Lógica pura sin UI
        hash_obj = hashlib.new(algorithm, message.encode('utf-8'))
        return {'digest_hex': hash_obj.hexdigest(), ...}
```

### 2️⃣ **UI (Presentación)**
- ✅ Depende del backend (importa desde `backend/`)
- ✅ Maneja eventos de usuario
- ✅ Renderiza resultados
- ✅ No contiene lógica de negocio

**Ejemplo:** `ui/message_digest_ui.py`
```python
from backend.message_digest_logic import MessageDigestLogic

class MessageDigestUI:
    def __init__(self, root):
        self.logic = MessageDigestLogic()  # Instancia del backend
    
    def generate_digest(self):
        result = self.logic.generate_digest(message, algo)  # Llama al backend
        self.display_result(result)  # Solo renderiza
```

---

## 📋 Ventajas de esta Estructura

| Aspecto | Antes (Monolítico) | Ahora (Separado) |
|---------|-------------------|------------------|
| **Testeo** | ❌ Difícil (requiere UI) | ✅ Fácil (backend independiente) |
| **Reutilización** | ❌ Código mezclado | ✅ Backend reutilizable en CLI, API, etc. |
| **Mantenimiento** | ❌ Cambios afectan todo | ✅ Cambios aislados por capa |
| **Legibilidad** | ❌ Archivos grandes (500+ líneas) | ✅ Archivos enfocados (~200 líneas) |
| **Escalabilidad** | ❌ Difícil agregar nuevas UIs | ✅ Múltiples UIs usan mismo backend |

---

## 🚀 Uso de la Nueva Estructura

### **Ejecutar la aplicación**
```bash
python main.py
```

### **Ejecutar solo la UI de Message Digest**
```bash
python ui/message_digest_ui.py
```

### **Usar la lógica en un script**
```python
from backend.message_digest_logic import MessageDigestLogic

logic = MessageDigestLogic()
result = logic.generate_digest("Hello World", "sha256")
print(result['digest_hex'])
```

---

## 📝 Estado de Migración

| Módulo | Estado | Backend | UI | Legacy |
|--------|--------|---------|----|----|  
| **Message Digest** | ✅ Migrado | `backend/message_digest_logic.py` | `ui/message_digest_ui.py` | `modules/message_digest_module.py` (obsoleto) |
| **Firma Digital** | ✅ Migrado | `backend/digital_signature_logic.py` | `ui/digital_signature_ui.py` | `modules/digital_signature_module.py` (obsoleto) |
| **Cifrado RSA** | ✅ Migrado | `backend/encryption_logic.py` | `ui/encryption_ui.py` | `modules/encryption_module.py` (obsoleto) |
| **Curvas Elípticas** | ❌ No iniciado | - | - | - |---

## 🔄 Plan de Migración

1. ✅ **Fase 1:** Crear estructura `backend/` y `ui/`
2. ✅ **Fase 2:** Migrar Message Digest
3. ✅ **Fase 3:** Migrar Firma Digital
4. ✅ **Fase 4:** Migrar Cifrado RSA
5. ⏳ **Fase 5:** Implementar Curvas Elípticas (nuevo)
6. ⏳ **Fase 6:** Eliminar `modules/` legacy

---

## 🧪 Testing (Próximamente)

Con la nueva estructura, será posible crear tests unitarios:

```
tests/
├── test_message_digest_logic.py
├── test_digital_signature_logic.py
└── ...
```

Ejemplo de test:
```python
import unittest
from backend.message_digest_logic import MessageDigestLogic

class TestMessageDigest(unittest.TestCase):
    def test_sha256_hash(self):
        logic = MessageDigestLogic()
        result = logic.generate_digest("test", "sha256")
        self.assertEqual(result['digest_hex'], 
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")
```

---

## 👨‍💻 Contribución

Al agregar nuevas funcionalidades:

1. **Backend:** Crear archivo en `backend/` con la lógica pura
2. **UI:** Crear archivo en `ui/` que use el backend
3. **Main:** Actualizar `main.py` para importar la nueva UI
4. **Docs:** Actualizar este README

---

## 📚 Referencias

- **Separation of Concerns:** https://en.wikipedia.org/wiki/Separation_of_concerns
- **MVC Pattern:** https://en.wikipedia.org/wiki/Model%E2%80%93view%E2%80%93controller
- **Clean Architecture:** https://blog.cleancoder.com/uncle-bob/2012/08/13/the-clean-architecture.html

---

**✨ Implementado por:** Laboratorio de Programación Segura  
**📅 Fecha:** Diciembre 2025
