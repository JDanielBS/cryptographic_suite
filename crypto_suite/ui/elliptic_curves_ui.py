#!/usr/bin/env python3
"""
Laboratorio de Programación Segura
UI: Elliptic Curves Interface (Punto 1e)

Interfaz gráfica para firma digital con Curvas Elípticas.
Usa la lógica del backend sin mezclar responsabilidades.
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import sys
import os

# Agregar el directorio raíz al path para imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.elliptic_curves_logic import EllipticCurvesLogic


class EllipticCurvesUI:
    """Interfaz gráfica para Curvas Elípticas (ECDSA y Ed25519)"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("📈 Curvas Elípticas - Suite Criptográfica")
        self.root.geometry("1200x800")
        self.root.configure(bg='#1e1e1e')
        
        # Instancia de la lógica de negocio
        self.logic = EllipticCurvesLogic()
        
        # Centrar ventana
        self.center_window()
        
        # Configurar estilos
        self.setup_styles()
        
        # Crear interfaz
        self.create_interface()
        
    def center_window(self):
        """Centrar la ventana en la pantalla"""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
        
    def setup_styles(self):
        """Configurar estilos de la interfaz"""
        style = ttk.Style()
        style.theme_use('clam')
        
        self.colors = {
            'bg_dark': '#1e1e1e',
            'bg_medium': '#2d2d2d',
            'bg_light': '#3d3d3d',
            'accent': '#00d4ff',
            'accent_hover': '#00a8cc',
            'text': '#ffffff',
            'text_secondary': '#b0b0b0',
            'success': '#00ff88',
            'error': '#ff4444',
            'warning': '#ffaa00'
        }
        
        # Estilos para notebook (tabs)
        style.configure('TNotebook', background=self.colors['bg_dark'], borderwidth=0)
        style.configure('TNotebook.Tab', 
                       background=self.colors['bg_medium'],
                       foreground=self.colors['text'],
                       padding=[20, 10],
                       font=('Segoe UI', 10, 'bold'))
        style.map('TNotebook.Tab',
                 background=[('selected', self.colors['bg_light'])],
                 foreground=[('selected', self.colors['accent'])])
        
    def create_interface(self):
        """Crear la interfaz principal"""
        # Header
        self.create_header()
        
        # Notebook con tabs
        self.create_tabs()
        
    def create_header(self):
        """Crear encabezado"""
        header = tk.Frame(self.root, bg=self.colors['bg_dark'])
        header.pack(fill='x', padx=30, pady=(20, 10))
        
        # Botón de regreso
        back_btn = tk.Button(header,
                            text='← Regresar al Home',
                            font=('Segoe UI', 10),
                            bg=self.colors['bg_medium'],
                            fg=self.colors['text'],
                            activebackground=self.colors['accent'],
                            relief='flat',
                            cursor='hand2',
                            padx=15,
                            pady=8,
                            command=self.go_back)
        back_btn.pack(side='left')
        
        # Título y subtítulo
        title_frame = tk.Frame(header, bg=self.colors['bg_dark'])
        title_frame.pack(side='left', padx=20)
        
        title = tk.Label(title_frame,
                        text="📈 CURVAS ELÍPTICAS (ECC)",
                        font=('Segoe UI', 24, 'bold'),
                        bg=self.colors['bg_dark'],
                        fg=self.colors['accent'])
        title.pack(anchor='w')
        
        subtitle = tk.Label(title_frame,
                           text="ECDSA (secp256k1, secp384r1, secp521r1) y Ed25519",
                           font=('Segoe UI', 11),
                           bg=self.colors['bg_dark'],
                           fg=self.colors['text_secondary'])
        subtitle.pack(anchor='w', pady=(5, 0))
        
        # Separador
        separator = tk.Frame(header, height=2, bg=self.colors['accent'])
        separator.pack(fill='x', pady=(15, 0))
        
    def create_tabs(self):
        """Crear sistema de pestañas"""
        container = tk.Frame(self.root, bg=self.colors['bg_dark'])
        container.pack(fill='both', expand=True, padx=30, pady=20)
        
        self.notebook = ttk.Notebook(container)
        self.notebook.pack(fill='both', expand=True)
        
        # Crear las 4 pestañas
        self.tab_ecdsa_keys = tk.Frame(self.notebook, bg=self.colors['bg_medium'])
        self.tab_ecdsa_sign = tk.Frame(self.notebook, bg=self.colors['bg_medium'])
        self.tab_ed25519_keys = tk.Frame(self.notebook, bg=self.colors['bg_medium'])
        self.tab_ed25519_sign = tk.Frame(self.notebook, bg=self.colors['bg_medium'])
        
        self.notebook.add(self.tab_ecdsa_keys, text='🔑 ECDSA - Claves')
        self.notebook.add(self.tab_ecdsa_sign, text='✍️ ECDSA - Firmar')
        self.notebook.add(self.tab_ed25519_keys, text='🔐 Ed25519 - Claves')
        self.notebook.add(self.tab_ed25519_sign, text='✅ Ed25519 - Firmar')
        
        # Crear contenido de cada tab
        self.create_ecdsa_keys_tab()
        self.create_ecdsa_sign_tab()
        self.create_ed25519_keys_tab()
        self.create_ed25519_sign_tab()
    
    # ==================== TABS DE ECDSA ====================
    
    def create_ecdsa_keys_tab(self):
        """Tab de generación de claves ECDSA"""
        main = tk.Frame(self.tab_ecdsa_keys, bg=self.colors['bg_medium'])
        main.pack(fill='both', expand=True, padx=30, pady=30)
        
        # Título
        title = tk.Label(main,
                        text="🔑 GENERAR CLAVES ECDSA",
                        font=('Segoe UI', 14, 'bold'),
                        bg=self.colors['bg_medium'],
                        fg=self.colors['accent'])
        title.pack(pady=(0, 10))
        
        info = tk.Label(main,
                       text="Generación de claves con curvas elípticas NIST. Soporte para secp256k1, secp384r1 y secp521r1",
                       font=('Segoe UI', 9),
                       bg=self.colors['bg_medium'],
                       fg=self.colors['text_secondary'])
        info.pack(pady=(0, 20))
        
        # Selector de curva
        curve_frame = tk.Frame(main, bg=self.colors['bg_light'])
        curve_frame.pack(fill='x', pady=(0, 20))
        
        tk.Label(curve_frame,
                text="Curva Elíptica:",
                font=('Segoe UI', 10, 'bold'),
                bg=self.colors['bg_light'],
                fg=self.colors['text']).pack(side='left', padx=15, pady=10)
        
        self.ecdsa_curve_var = tk.StringVar(value="secp256k1")
        curves = [
            ('secp256k1 (Bitcoin)', 'secp256k1'),
            ('secp384r1 (NIST P-384)', 'secp384r1'),
            ('secp521r1 (NIST P-521)', 'secp521r1')
        ]
        
        for label, value in curves:
            tk.Radiobutton(curve_frame,
                          text=label,
                          variable=self.ecdsa_curve_var,
                          value=value,
                          bg=self.colors['bg_light'],
                          fg=self.colors['text'],
                          selectcolor=self.colors['bg_dark'],
                          activebackground=self.colors['bg_light'],
                          font=('Segoe UI', 9)).pack(side='left', padx=10)
        
        # Botón generar
        tk.Button(main,
                 text="🔑 Generar Par de Claves ECDSA",
                 font=('Segoe UI', 12, 'bold'),
                 bg=self.colors['accent'],
                 fg='#000000',
                 activebackground=self.colors['accent_hover'],
                 relief='flat',
                 cursor='hand2',
                 padx=30,
                 pady=12,
                 command=self.generate_ecdsa_keypair).pack(pady=15)
        
        # Clave Pública
        pub_label = tk.Label(main,
                            text="📤 CLAVE PÚBLICA ECDSA (compartir)",
                            font=('Segoe UI', 11, 'bold'),
                            bg=self.colors['bg_medium'],
                            fg=self.colors['accent'])
        pub_label.pack(anchor='w', pady=(10, 5))
        
        self.ecdsa_public_key_text = scrolledtext.ScrolledText(main,
                                                               height=8,
                                                               font=('Consolas', 8),
                                                               bg=self.colors['bg_dark'],
                                                               fg=self.colors['text'],
                                                               insertbackground=self.colors['text'],
                                                               relief='flat',
                                                               wrap='word')
        self.ecdsa_public_key_text.pack(fill='both', expand=True, pady=(0, 10))
        
        # Botones clave pública
        pub_buttons = tk.Frame(main, bg=self.colors['bg_medium'])
        pub_buttons.pack(fill='x', pady=(0, 15))
        
        tk.Button(pub_buttons,
                 text="💾 Guardar",
                 font=('Segoe UI', 9),
                 bg=self.colors['bg_light'],
                 fg=self.colors['text'],
                 activebackground=self.colors['bg_dark'],
                 relief='flat',
                 cursor='hand2',
                 padx=15,
                 pady=5,
                 command=self.save_ecdsa_public_key).pack(side='left', padx=(0, 10))
        
        tk.Button(pub_buttons,
                 text="📂 Cargar",
                 font=('Segoe UI', 9),
                 bg=self.colors['bg_light'],
                 fg=self.colors['text'],
                 activebackground=self.colors['bg_dark'],
                 relief='flat',
                 cursor='hand2',
                 padx=15,
                 pady=5,
                 command=self.load_ecdsa_public_key).pack(side='left', padx=(0, 10))
        
        tk.Button(pub_buttons,
                 text="📋 Copiar",
                 font=('Segoe UI', 9),
                 bg=self.colors['bg_light'],
                 fg=self.colors['text'],
                 activebackground=self.colors['bg_dark'],
                 relief='flat',
                 cursor='hand2',
                 padx=15,
                 pady=5,
                 command=lambda: self.copy_to_clipboard(self.ecdsa_public_key_text)).pack(side='left')
        
        # Clave Privada
        priv_label = tk.Label(main,
                             text="🔒 CLAVE PRIVADA ECDSA (mantener en secreto)",
                             font=('Segoe UI', 11, 'bold'),
                             bg=self.colors['bg_medium'],
                             fg=self.colors['error'])
        priv_label.pack(anchor='w', pady=(10, 5))
        
        self.ecdsa_private_key_text = scrolledtext.ScrolledText(main,
                                                                height=8,
                                                                font=('Consolas', 8),
                                                                bg=self.colors['bg_dark'],
                                                                fg=self.colors['text'],
                                                                insertbackground=self.colors['text'],
                                                                relief='flat',
                                                                wrap='word')
        self.ecdsa_private_key_text.pack(fill='both', expand=True, pady=(0, 10))
        
        # Botones clave privada
        priv_buttons = tk.Frame(main, bg=self.colors['bg_medium'])
        priv_buttons.pack(fill='x')
        
        tk.Button(priv_buttons,
                 text="💾 Guardar",
                 font=('Segoe UI', 9),
                 bg=self.colors['bg_light'],
                 fg=self.colors['text'],
                 activebackground=self.colors['bg_dark'],
                 relief='flat',
                 cursor='hand2',
                 padx=15,
                 pady=5,
                 command=self.save_ecdsa_private_key).pack(side='left', padx=(0, 10))
        
        tk.Button(priv_buttons,
                 text="📂 Cargar",
                 font=('Segoe UI', 9),
                 bg=self.colors['bg_light'],
                 fg=self.colors['text'],
                 activebackground=self.colors['bg_dark'],
                 relief='flat',
                 cursor='hand2',
                 padx=15,
                 pady=5,
                 command=self.load_ecdsa_private_key).pack(side='left', padx=(0, 10))
        
        tk.Button(priv_buttons,
                 text="📋 Copiar",
                 font=('Segoe UI', 9),
                 bg=self.colors['bg_light'],
                 fg=self.colors['text'],
                 activebackground=self.colors['bg_dark'],
                 relief='flat',
                 cursor='hand2',
                 padx=15,
                 pady=5,
                 command=lambda: self.copy_to_clipboard(self.ecdsa_private_key_text)).pack(side='left')
    
    def create_ecdsa_sign_tab(self):
        """Tab de firma y verificación ECDSA"""
        main = tk.Frame(self.tab_ecdsa_sign, bg=self.colors['bg_medium'])
        main.pack(fill='both', expand=True, padx=30, pady=30)
        
        # Título
        title = tk.Label(main,
                        text="✍️ FIRMAR Y VERIFICAR CON ECDSA",
                        font=('Segoe UI', 14, 'bold'),
                        bg=self.colors['bg_medium'],
                        fg=self.colors['accent'])
        title.pack(pady=(0, 20))
        
        # Selector de hash
        hash_frame = tk.Frame(main, bg=self.colors['bg_light'])
        hash_frame.pack(fill='x', pady=(0, 15))
        
        tk.Label(hash_frame,
                text="Algoritmo Hash:",
                font=('Segoe UI', 10, 'bold'),
                bg=self.colors['bg_light'],
                fg=self.colors['text']).pack(side='left', padx=15, pady=10)
        
        self.ecdsa_hash_var = tk.StringVar(value="SHA256")
        for algo in ['SHA256', 'SHA384', 'SHA512']:
            tk.Radiobutton(hash_frame,
                          text=algo,
                          variable=self.ecdsa_hash_var,
                          value=algo,
                          bg=self.colors['bg_light'],
                          fg=self.colors['text'],
                          selectcolor=self.colors['bg_dark'],
                          activebackground=self.colors['bg_light'],
                          font=('Segoe UI', 9)).pack(side='left', padx=10)
        
        # Mensaje
        msg_label = tk.Label(main,
                            text="📝 Mensaje:",
                            font=('Segoe UI', 11, 'bold'),
                            bg=self.colors['bg_medium'],
                            fg=self.colors['text'])
        msg_label.pack(anchor='w', pady=(10, 5))
        
        self.ecdsa_message_text = scrolledtext.ScrolledText(main,
                                                            height=6,
                                                            font=('Segoe UI', 10),
                                                            bg=self.colors['bg_dark'],
                                                            fg=self.colors['text'],
                                                            insertbackground=self.colors['text'],
                                                            relief='flat',
                                                            wrap='word')
        self.ecdsa_message_text.pack(fill='x', pady=(0, 15))
        self.ecdsa_message_text.insert('1.0', 'Message for ECDSA signing')
        
        # Botones
        btn_frame = tk.Frame(main, bg=self.colors['bg_medium'])
        btn_frame.pack(fill='x', pady=10)
        
        tk.Button(btn_frame,
                 text="✍️ Firmar",
                 font=('Segoe UI', 11, 'bold'),
                 bg=self.colors['accent'],
                 fg='#000000',
                 activebackground=self.colors['accent_hover'],
                 relief='flat',
                 cursor='hand2',
                 padx=25,
                 pady=10,
                 command=self.sign_message_ecdsa).pack(side='left', padx=(0, 10))
        
        tk.Button(btn_frame,
                 text="✅ Verificar",
                 font=('Segoe UI', 11, 'bold'),
                 bg=self.colors['bg_light'],
                 fg=self.colors['text'],
                 activebackground=self.colors['bg_dark'],
                 relief='flat',
                 cursor='hand2',
                 padx=25,
                 pady=10,
                 command=self.verify_signature_ecdsa).pack(side='left')
        
        # Firma
        sig_label = tk.Label(main,
                            text="🔏 Firma ECDSA:",
                            font=('Segoe UI', 11, 'bold'),
                            bg=self.colors['bg_medium'],
                            fg=self.colors['success'])
        sig_label.pack(anchor='w', pady=(15, 5))
        
        self.ecdsa_signature_text = scrolledtext.ScrolledText(main,
                                                              height=6,
                                                              font=('Consolas', 9),
                                                              bg=self.colors['bg_dark'],
                                                              fg=self.colors['success'],
                                                              insertbackground=self.colors['text'],
                                                              relief='flat',
                                                              wrap='word')
        self.ecdsa_signature_text.pack(fill='both', expand=True, pady=(0, 10))
        
        # Resultado de verificación
        self.ecdsa_verify_result = tk.Label(main,
                                           text="",
                                           font=('Segoe UI', 11, 'bold'),
                                           bg=self.colors['bg_medium'],
                                           fg=self.colors['success'])
        self.ecdsa_verify_result.pack(pady=10)
    
    # ==================== TABS DE ED25519 ====================
    
    def create_ed25519_keys_tab(self):
        """Tab de generación de claves Ed25519"""
        main = tk.Frame(self.tab_ed25519_keys, bg=self.colors['bg_medium'])
        main.pack(fill='both', expand=True, padx=30, pady=30)
        
        # Título
        title = tk.Label(main,
                        text="🔐 GENERAR CLAVES ED25519",
                        font=('Segoe UI', 14, 'bold'),
                        bg=self.colors['bg_medium'],
                        fg=self.colors['accent'])
        title.pack(pady=(0, 10))
        
        info_frame = tk.Frame(main, bg=self.colors['bg_light'])
        info_frame.pack(fill='x', pady=(0, 20))
        
        tk.Label(info_frame,
                text="Ed25519: Curva Edwards moderna con Curve25519\n" +
                     "Ampliamente usado en protocolos seguros (SSH, TLS 1.3, Signal)",
                font=('Segoe UI', 9),
                bg=self.colors['bg_light'],
                fg=self.colors['text_secondary'],
                justify='left').pack(padx=15, pady=10)
        
        # Botón generar
        tk.Button(main,
                 text="🔐 Generar Par de Claves Ed25519",
                 font=('Segoe UI', 12, 'bold'),
                 bg=self.colors['accent'],
                 fg='#000000',
                 activebackground=self.colors['accent_hover'],
                 relief='flat',
                 cursor='hand2',
                 padx=30,
                 pady=12,
                 command=self.generate_ed25519_keypair).pack(pady=15)
        
        # Clave Pública
        pub_label = tk.Label(main,
                            text="📤 CLAVE PÚBLICA ED25519 (32 bytes)",
                            font=('Segoe UI', 11, 'bold'),
                            bg=self.colors['bg_medium'],
                            fg=self.colors['accent'])
        pub_label.pack(anchor='w', pady=(10, 5))
        
        self.ed25519_public_key_text = scrolledtext.ScrolledText(main,
                                                                 height=8,
                                                                 font=('Consolas', 9),
                                                                 bg=self.colors['bg_dark'],
                                                                 fg=self.colors['text'],
                                                                 insertbackground=self.colors['text'],
                                                                 relief='flat',
                                                                 wrap='word')
        self.ed25519_public_key_text.pack(fill='both', expand=True, pady=(0, 10))
        
        # Botones clave pública
        pub_buttons = tk.Frame(main, bg=self.colors['bg_medium'])
        pub_buttons.pack(fill='x', pady=(0, 15))
        
        tk.Button(pub_buttons,
                 text="💾 Guardar",
                 font=('Segoe UI', 9),
                 bg=self.colors['bg_light'],
                 fg=self.colors['text'],
                 activebackground=self.colors['bg_dark'],
                 relief='flat',
                 cursor='hand2',
                 padx=15,
                 pady=5,
                 command=self.save_ed25519_public_key).pack(side='left', padx=(0, 10))
        
        tk.Button(pub_buttons,
                 text="📂 Cargar",
                 font=('Segoe UI', 9),
                 bg=self.colors['bg_light'],
                 fg=self.colors['text'],
                 activebackground=self.colors['bg_dark'],
                 relief='flat',
                 cursor='hand2',
                 padx=15,
                 pady=5,
                 command=self.load_ed25519_public_key).pack(side='left', padx=(0, 10))
        
        tk.Button(pub_buttons,
                 text="📋 Copiar",
                 font=('Segoe UI', 9),
                 bg=self.colors['bg_light'],
                 fg=self.colors['text'],
                 activebackground=self.colors['bg_dark'],
                 relief='flat',
                 cursor='hand2',
                 padx=15,
                 pady=5,
                 command=lambda: self.copy_to_clipboard(self.ed25519_public_key_text)).pack(side='left')
        
        # Clave Privada
        priv_label = tk.Label(main,
                             text="🔒 CLAVE PRIVADA ED25519 (64 bytes)",
                             font=('Segoe UI', 11, 'bold'),
                             bg=self.colors['bg_medium'],
                             fg=self.colors['error'])
        priv_label.pack(anchor='w', pady=(10, 5))
        
        self.ed25519_private_key_text = scrolledtext.ScrolledText(main,
                                                                  height=8,
                                                                  font=('Consolas', 9),
                                                                  bg=self.colors['bg_dark'],
                                                                  fg=self.colors['text'],
                                                                  insertbackground=self.colors['text'],
                                                                  relief='flat',
                                                                  wrap='word')
        self.ed25519_private_key_text.pack(fill='both', expand=True, pady=(0, 10))
        
        # Botones clave privada
        priv_buttons = tk.Frame(main, bg=self.colors['bg_medium'])
        priv_buttons.pack(fill='x')
        
        tk.Button(priv_buttons,
                 text="💾 Guardar",
                 font=('Segoe UI', 9),
                 bg=self.colors['bg_light'],
                 fg=self.colors['text'],
                 activebackground=self.colors['bg_dark'],
                 relief='flat',
                 cursor='hand2',
                 padx=15,
                 pady=5,
                 command=self.save_ed25519_private_key).pack(side='left', padx=(0, 10))
        
        tk.Button(priv_buttons,
                 text="📂 Cargar",
                 font=('Segoe UI', 9),
                 bg=self.colors['bg_light'],
                 fg=self.colors['text'],
                 activebackground=self.colors['bg_dark'],
                 relief='flat',
                 cursor='hand2',
                 padx=15,
                 pady=5,
                 command=self.load_ed25519_private_key).pack(side='left', padx=(0, 10))
        
        tk.Button(priv_buttons,
                 text="📋 Copiar",
                 font=('Segoe UI', 9),
                 bg=self.colors['bg_light'],
                 fg=self.colors['text'],
                 activebackground=self.colors['bg_dark'],
                 relief='flat',
                 cursor='hand2',
                 padx=15,
                 pady=5,
                 command=lambda: self.copy_to_clipboard(self.ed25519_private_key_text)).pack(side='left')
    
    def create_ed25519_sign_tab(self):
        """Tab de firma y verificación Ed25519"""
        main = tk.Frame(self.tab_ed25519_sign, bg=self.colors['bg_medium'])
        main.pack(fill='both', expand=True, padx=30, pady=30)
        
        # Título
        title = tk.Label(main,
                        text="✅ FIRMAR Y VERIFICAR CON ED25519",
                        font=('Segoe UI', 14, 'bold'),
                        bg=self.colors['bg_medium'],
                        fg=self.colors['accent'])
        title.pack(pady=(0, 10))
        
        info = tk.Label(main,
                       text="Como en el ejemplo del profesor: privKey.sign(msg) y pubKey.verify(signature, msg)",
                       font=('Segoe UI', 9),
                       bg=self.colors['bg_medium'],
                       fg=self.colors['text_secondary'])
        info.pack(pady=(0, 20))
        
        # Mensaje
        msg_label = tk.Label(main,
                            text="📝 Mensaje:",
                            font=('Segoe UI', 11, 'bold'),
                            bg=self.colors['bg_medium'],
                            fg=self.colors['text'])
        msg_label.pack(anchor='w', pady=(10, 5))
        
        self.ed25519_message_text = scrolledtext.ScrolledText(main,
                                                              height=8,
                                                              font=('Segoe UI', 10),
                                                              bg=self.colors['bg_dark'],
                                                              fg=self.colors['text'],
                                                              insertbackground=self.colors['text'],
                                                              relief='flat',
                                                              wrap='word')
        self.ed25519_message_text.pack(fill='x', pady=(0, 15))
        self.ed25519_message_text.insert('1.0', 'Message for Ed25519 signing')
        
        # Botones
        btn_frame = tk.Frame(main, bg=self.colors['bg_medium'])
        btn_frame.pack(fill='x', pady=15)
        
        tk.Button(btn_frame,
                 text="✍️ Firmar (privKey.sign)",
                 font=('Segoe UI', 11, 'bold'),
                 bg=self.colors['accent'],
                 fg='#000000',
                 activebackground=self.colors['accent_hover'],
                 relief='flat',
                 cursor='hand2',
                 padx=25,
                 pady=10,
                 command=self.sign_message_ed25519).pack(side='left', padx=(0, 10))
        
        tk.Button(btn_frame,
                 text="✅ Verificar (pubKey.verify)",
                 font=('Segoe UI', 11, 'bold'),
                 bg=self.colors['bg_light'],
                 fg=self.colors['text'],
                 activebackground=self.colors['bg_dark'],
                 relief='flat',
                 cursor='hand2',
                 padx=25,
                 pady=10,
                 command=self.verify_signature_ed25519).pack(side='left')
        
        # Firma
        sig_label = tk.Label(main,
                            text="🔏 Firma Ed25519:",
                            font=('Segoe UI', 11, 'bold'),
                            bg=self.colors['bg_medium'],
                            fg=self.colors['success'])
        sig_label.pack(anchor='w', pady=(15, 5))
        
        self.ed25519_signature_text = scrolledtext.ScrolledText(main,
                                                                height=8,
                                                                font=('Consolas', 9),
                                                                bg=self.colors['bg_dark'],
                                                                fg=self.colors['success'],
                                                                insertbackground=self.colors['text'],
                                                                relief='flat',
                                                                wrap='word')
        self.ed25519_signature_text.pack(fill='both', expand=True, pady=(0, 10))
        
        # Resultado de verificación
        self.ed25519_verify_result = tk.Label(main,
                                             text="",
                                             font=('Segoe UI', 12, 'bold'),
                                             bg=self.colors['bg_medium'],
                                             fg=self.colors['success'])
        self.ed25519_verify_result.pack(pady=15)
    
    # ==================== MÉTODOS DE ECDSA ====================
    
    def generate_ecdsa_keypair(self):
        """Generar par de claves ECDSA"""
        curve = self.ecdsa_curve_var.get()
        
        try:
            result = self.logic.generate_ecdsa_keypair(curve)
            
            self.ecdsa_public_key_text.delete('1.0', tk.END)
            self.ecdsa_public_key_text.insert('1.0', result['public_key_pem'])
            
            self.ecdsa_private_key_text.delete('1.0', tk.END)
            self.ecdsa_private_key_text.insert('1.0', result['private_key_pem'])
            
            messagebox.showinfo("Éxito", 
                               f"{result['message']}\n" +
                               f"Curva: {result['curve']}\n" +
                               f"Tamaño: {result['key_size']} bits")
        except ValueError as e:
            messagebox.showerror("Error", str(e))
    
    def sign_message_ecdsa(self):
        """Firmar mensaje con ECDSA"""
        message = self.ecdsa_message_text.get('1.0', tk.END).strip()
        hash_algo = self.ecdsa_hash_var.get()
        
        try:
            result = self.logic.sign_message_ecdsa(message, hash_algo)
            
            output = f"Firma (base64): {result['signature_base64']}\n\n"
            output += f"Firma (hex): {result['signature_hex']}\n\n"
            output += f"Curva: {result['curve']}\n"
            output += f"Hash: {result['hash_algorithm']}"
            
            self.ecdsa_signature_text.delete('1.0', tk.END)
            self.ecdsa_signature_text.insert('1.0', output)
            
            messagebox.showinfo("Éxito", result['message'])
        except ValueError as e:
            messagebox.showerror("Error", str(e))
    
    def verify_signature_ecdsa(self):
        """Verificar firma ECDSA"""
        message = self.ecdsa_message_text.get('1.0', tk.END).strip()
        signature_text = self.ecdsa_signature_text.get('1.0', tk.END).strip()
        hash_algo = self.ecdsa_hash_var.get()
        
        # Extraer firma base64
        lines = signature_text.split('\n')
        signature_b64 = lines[0].replace('Firma (base64): ', '').strip()
        
        try:
            result = self.logic.verify_signature_ecdsa(message, signature_b64, hash_algo)
            
            if result['valid']:
                self.ecdsa_verify_result.config(
                    text=result['message'],
                    fg=self.colors['success']
                )
                messagebox.showinfo("Verificación Exitosa", 
                                   f"{result['message']}\nCurva: {result['curve']}")
            else:
                self.ecdsa_verify_result.config(
                    text=result['message'],
                    fg=self.colors['error']
                )
                messagebox.showerror("Verificación Fallida", result['message'])
        except ValueError as e:
            messagebox.showerror("Error", str(e))
    
    # ==================== MÉTODOS DE ED25519 ====================
    
    def generate_ed25519_keypair(self):
        """Generar par de claves Ed25519"""
        try:
            result = self.logic.generate_ed25519_keypair()
            
            pub_output = f"Hex: {result['public_key_hex']}\n\n"
            pub_output += f"Base64: {result['public_key_base64']}"
            
            priv_output = f"Hex: {result['private_key_hex']}\n\n"
            priv_output += f"Base64: {result['private_key_base64']}"
            
            self.ed25519_public_key_text.delete('1.0', tk.END)
            self.ed25519_public_key_text.insert('1.0', pub_output)
            
            self.ed25519_private_key_text.delete('1.0', tk.END)
            self.ed25519_private_key_text.insert('1.0', priv_output)
            
            messagebox.showinfo("Éxito", 
                               f"{result['message']}\n\n{result['note']}")
        except ValueError as e:
            messagebox.showerror("Error", str(e))
    
    def sign_message_ed25519(self):
        """Firmar mensaje con Ed25519"""
        message = self.ed25519_message_text.get('1.0', tk.END).strip()
        
        try:
            result = self.logic.sign_message_ed25519(message)
            
            output = f"Firma (hex): {result['signature_hex']}\n\n"
            output += f"Firma (base64): {result['signature_base64']}\n\n"
            output += result['note']
            
            self.ed25519_signature_text.delete('1.0', tk.END)
            self.ed25519_signature_text.insert('1.0', output)
            
            messagebox.showinfo("Éxito", result['message'])
        except ValueError as e:
            messagebox.showerror("Error", str(e))
    
    def verify_signature_ed25519(self):
        """Verificar firma Ed25519"""
        message = self.ed25519_message_text.get('1.0', tk.END).strip()
        signature_text = self.ed25519_signature_text.get('1.0', tk.END).strip()
        
        # Extraer firma hex
        lines = signature_text.split('\n')
        signature_hex = lines[0].replace('Firma (hex): ', '').strip()
        
        try:
            result = self.logic.verify_signature_ed25519(message, signature_hex)
            
            if result['valid']:
                self.ed25519_verify_result.config(
                    text=result['message'],
                    fg=self.colors['success']
                )
                messagebox.showinfo("Verificación Exitosa", 
                                   f"{result['message']}\n\n{result['note']}")
            else:
                self.ed25519_verify_result.config(
                    text=result['message'],
                    fg=self.colors['error']
                )
                messagebox.showerror("Verificación Fallida", 
                                    f"{result['message']}\n\n{result['note']}")
        except ValueError as e:
            messagebox.showerror("Error", str(e))
    
    # ==================== FUNCIONES AUXILIARES ====================
    
    def save_ecdsa_public_key(self):
        """Guardar clave pública ECDSA"""
        content = self.ecdsa_public_key_text.get('1.0', tk.END).strip()
        if not content:
            messagebox.showwarning("Advertencia", "No hay clave para guardar")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".pem",
            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write(content)
                messagebox.showinfo("Éxito", "Clave pública guardada")
            except Exception as e:
                messagebox.showerror("Error", f"Error al guardar: {str(e)}")
    
    def save_ecdsa_private_key(self):
        """Guardar clave privada ECDSA"""
        content = self.ecdsa_private_key_text.get('1.0', tk.END).strip()
        if not content:
            messagebox.showwarning("Advertencia", "No hay clave para guardar")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".pem",
            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write(content)
                messagebox.showinfo("Éxito", "Clave privada guardada")
            except Exception as e:
                messagebox.showerror("Error", f"Error al guardar: {str(e)}")
    
    def load_ecdsa_private_key(self):
        """Cargar clave privada ECDSA"""
        filename = filedialog.askopenfilename(
            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'rb') as f:
                    key_data = f.read()
                    result = self.logic.load_ecdsa_private_key_from_pem(key_data)
                
                self.ecdsa_private_key_text.delete('1.0', tk.END)
                self.ecdsa_private_key_text.insert('1.0', key_data.decode('utf-8'))
                
                # Cargar clave pública también
                pub_pem = self.logic.export_ecdsa_public_key_pem()
                self.ecdsa_public_key_text.delete('1.0', tk.END)
                self.ecdsa_public_key_text.insert('1.0', pub_pem)
                
                messagebox.showinfo("Éxito", result['message'])
            except Exception as e:
                messagebox.showerror("Error", str(e))
    
    def load_ecdsa_public_key(self):
        """Cargar clave pública ECDSA"""
        filename = filedialog.askopenfilename(
            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'rb') as f:
                    key_data = f.read()
                    result = self.logic.load_ecdsa_public_key_from_pem(key_data)
                
                self.ecdsa_public_key_text.delete('1.0', tk.END)
                self.ecdsa_public_key_text.insert('1.0', key_data.decode('utf-8'))
                
                messagebox.showinfo("Éxito", result['message'])
            except Exception as e:
                messagebox.showerror("Error", str(e))
    
    def save_ed25519_public_key(self):
        """Guardar clave pública Ed25519"""
        content = self.ed25519_public_key_text.get('1.0', tk.END).strip()
        if not content:
            messagebox.showwarning("Advertencia", "No hay clave para guardar")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write(content)
                messagebox.showinfo("Éxito", "Clave pública guardada")
            except Exception as e:
                messagebox.showerror("Error", f"Error al guardar: {str(e)}")
    
    def save_ed25519_private_key(self):
        """Guardar clave privada Ed25519"""
        content = self.ed25519_private_key_text.get('1.0', tk.END).strip()
        if not content:
            messagebox.showwarning("Advertencia", "No hay clave para guardar")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write(content)
                messagebox.showinfo("Éxito", "Clave privada guardada")
            except Exception as e:
                messagebox.showerror("Error", f"Error al guardar: {str(e)}")
    
    def load_ed25519_private_key(self):
        """Cargar clave privada Ed25519"""
        filename = filedialog.askopenfilename(
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'r') as f:
                    content = f.read()
                
                # Extraer hex
                lines = content.split('\n')
                private_hex = lines[0].replace('Hex: ', '').strip()
                
                result = self.logic.load_ed25519_private_key_from_hex(private_hex)
                
                self.ed25519_private_key_text.delete('1.0', tk.END)
                self.ed25519_private_key_text.insert('1.0', content)
                
                messagebox.showinfo("Éxito", result['message'])
            except Exception as e:
                messagebox.showerror("Error", str(e))
    
    def load_ed25519_public_key(self):
        """Cargar clave pública Ed25519"""
        filename = filedialog.askopenfilename(
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'r') as f:
                    content = f.read()
                
                # Extraer hex
                lines = content.split('\n')
                public_hex = lines[0].replace('Hex: ', '').strip()
                
                result = self.logic.load_ed25519_public_key_from_hex(public_hex)
                
                self.ed25519_public_key_text.delete('1.0', tk.END)
                self.ed25519_public_key_text.insert('1.0', content)
                
                messagebox.showinfo("Éxito", result['message'])
            except Exception as e:
                messagebox.showerror("Error", str(e))
    
    def copy_to_clipboard(self, text_widget):
        """Copiar contenido al portapapeles"""
        content = text_widget.get('1.0', tk.END).strip()
        if content:
            self.root.clipboard_clear()
            self.root.clipboard_append(content)
            messagebox.showinfo("Éxito", "Contenido copiado al portapapeles")
        else:
            messagebox.showwarning("Advertencia", "No hay contenido para copiar")
    
    def go_back(self):
        """Regresar al home"""
        self.root.destroy()


def main():
    """Función principal standalone"""
    root = tk.Tk()
    app = EllipticCurvesUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
