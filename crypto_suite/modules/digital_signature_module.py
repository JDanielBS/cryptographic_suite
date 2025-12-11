#!/usr/bin/env python3
"""
Laboratorio de Programación Segura
MÓDULO: Firma Digital (Punto 1b)

Implementación de firma y verificación digital usando RSA
con interfaz gráfica profesional.
Compatible con Python 3.13+
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
import base64
import os
import datetime
import hashlib


class DigitalSignatureModule:
    """Módulo de Firma Digital con interfaz gráfica"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("✍️ Firma Digital - Suite Criptográfica")
        self.root.geometry("1200x800")
        self.root.configure(bg='#1e1e1e')
        
        # Variables para almacenar las claves
        self.private_key = None
        self.public_key = None
        self.signature = None
        self.certificate = None
        
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
            'accent': '#00ff88',
            'accent_hover': '#00cc6a',
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
        
        # Título
        title = tk.Label(header,
                        text="✍️ FIRMA DIGITAL",
                        font=('Segoe UI', 24, 'bold'),
                        bg=self.colors['bg_dark'],
                        fg=self.colors['accent'])
        title.pack(anchor='w')
        
        # Subtítulo
        subtitle = tk.Label(header,
                           text="Generación, firma y verificación con RSA",
                           font=('Segoe UI', 11),
                           bg=self.colors['bg_dark'],
                           fg=self.colors['text_secondary'])
        subtitle.pack(anchor='w', pady=(5, 0))
        
        # Separador
        separator = tk.Frame(header, height=2, bg=self.colors['accent'])
        separator.pack(fill='x', pady=(15, 0))
        
    def create_tabs(self):
        """Crear sistema de pestañas"""
        # Frame contenedor
        container = tk.Frame(self.root, bg=self.colors['bg_dark'])
        container.pack(fill='both', expand=True, padx=30, pady=20)
        
        # Notebook
        self.notebook = ttk.Notebook(container)
        self.notebook.pack(fill='both', expand=True)
        
        # Crear las 4 pestañas
        self.tab_keys = tk.Frame(self.notebook, bg=self.colors['bg_medium'])
        self.tab_certificate = tk.Frame(self.notebook, bg=self.colors['bg_medium'])
        self.tab_sign = tk.Frame(self.notebook, bg=self.colors['bg_medium'])
        self.tab_verify = tk.Frame(self.notebook, bg=self.colors['bg_medium'])
        
        self.notebook.add(self.tab_keys, text='🔑 Generar Claves')
        self.notebook.add(self.tab_certificate, text='📜 Certificado X.509')
        self.notebook.add(self.tab_sign, text='✍️ Firmar Mensaje')
        self.notebook.add(self.tab_verify, text='✅ Verificar Firma')
        
        # Crear contenido de cada tab
        self.create_keys_tab()
        self.create_certificate_tab()
        self.create_sign_tab()
        self.create_verify_tab()
        
    def create_keys_tab(self):
        """Tab de generación de claves"""
        # Contenedor principal
        main = tk.Frame(self.tab_keys, bg=self.colors['bg_medium'])
        main.pack(fill='both', expand=True, padx=30, pady=30)
        
        # Instrucciones
        instructions = tk.Label(main,
                               text="Genera un par de claves RSA para firmar y verificar mensajes",
                               font=('Segoe UI', 11),
                               bg=self.colors['bg_medium'],
                               fg=self.colors['text_secondary'])
        instructions.pack(pady=(0, 20))
        
        # Frame de configuración
        config_frame = tk.Frame(main, bg=self.colors['bg_light'])
        config_frame.pack(fill='x', pady=(0, 20))
        
        # Tamaño de clave
        size_frame = tk.Frame(config_frame, bg=self.colors['bg_light'])
        size_frame.pack(pady=20)
        
        tk.Label(size_frame,
                text="Tamaño de clave:",
                font=('Segoe UI', 10, 'bold'),
                bg=self.colors['bg_light'],
                fg=self.colors['text']).pack(side='left', padx=(20, 10))
        
        self.key_size_var = tk.StringVar(value="2048")
        for size in ['1024', '2048', '4096']:
            rb = tk.Radiobutton(size_frame,
                               text=f"{size} bits",
                               variable=self.key_size_var,
                               value=size,
                               font=('Segoe UI', 10),
                               bg=self.colors['bg_light'],
                               fg=self.colors['text'],
                               selectcolor=self.colors['bg_medium'],
                               activebackground=self.colors['bg_light'],
                               activeforeground=self.colors['accent'])
            rb.pack(side='left', padx=10)
        
        # Botón generar
        btn_generate = tk.Button(main,
                                text="🔑 Generar Par de Claves",
                                font=('Segoe UI', 12, 'bold'),
                                bg=self.colors['accent'],
                                fg='#000000',
                                activebackground=self.colors['accent_hover'],
                                relief='flat',
                                cursor='hand2',
                                padx=30,
                                pady=12,
                                command=self.generate_keypair)
        btn_generate.pack(pady=10)
        
        # Frame para mostrar claves
        keys_display_frame = tk.Frame(main, bg=self.colors['bg_medium'])
        keys_display_frame.pack(fill='both', expand=True, pady=(20, 0))
        
        # Clave Pública
        pub_label = tk.Label(keys_display_frame,
                            text="📤 CLAVE PÚBLICA (compartir con otros)",
                            font=('Segoe UI', 11, 'bold'),
                            bg=self.colors['bg_medium'],
                            fg=self.colors['accent'])
        pub_label.pack(anchor='w', pady=(0, 5))
        
        self.public_key_text = scrolledtext.ScrolledText(keys_display_frame,
                                                         height=8,
                                                         font=('Consolas', 9),
                                                         bg=self.colors['bg_dark'],
                                                         fg=self.colors['text'],
                                                         insertbackground=self.colors['text'],
                                                         relief='flat',
                                                         wrap='word')
        self.public_key_text.pack(fill='both', expand=True, pady=(0, 10))
        
        # Botones para clave pública
        pub_buttons = tk.Frame(keys_display_frame, bg=self.colors['bg_medium'])
        pub_buttons.pack(fill='x', pady=(0, 15))
        
        tk.Button(pub_buttons,
                 text="💾 Guardar Clave Pública",
                 font=('Segoe UI', 9),
                 bg=self.colors['bg_light'],
                 fg=self.colors['text'],
                 activebackground=self.colors['bg_dark'],
                 relief='flat',
                 cursor='hand2',
                 padx=15,
                 pady=5,
                 command=self.save_public_key).pack(side='left', padx=(0, 10))
        
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
                 command=lambda: self.copy_to_clipboard(self.public_key_text)).pack(side='left')
        
        # Clave Privada
        priv_label = tk.Label(keys_display_frame,
                             text="🔒 CLAVE PRIVADA (mantener en secreto)",
                             font=('Segoe UI', 11, 'bold'),
                             bg=self.colors['bg_medium'],
                             fg=self.colors['error'])
        priv_label.pack(anchor='w', pady=(10, 5))
        
        self.private_key_text = scrolledtext.ScrolledText(keys_display_frame,
                                                          height=8,
                                                          font=('Consolas', 9),
                                                          bg=self.colors['bg_dark'],
                                                          fg=self.colors['text'],
                                                          insertbackground=self.colors['text'],
                                                          relief='flat',
                                                          wrap='word')
        self.private_key_text.pack(fill='both', expand=True, pady=(0, 10))
        
        # Botones para clave privada
        priv_buttons = tk.Frame(keys_display_frame, bg=self.colors['bg_medium'])
        priv_buttons.pack(fill='x')
        
        tk.Button(priv_buttons,
                 text="💾 Guardar Clave Privada",
                 font=('Segoe UI', 9),
                 bg=self.colors['bg_light'],
                 fg=self.colors['text'],
                 activebackground=self.colors['bg_dark'],
                 relief='flat',
                 cursor='hand2',
                 padx=15,
                 pady=5,
                 command=self.save_private_key).pack(side='left', padx=(0, 10))
        
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
                 command=lambda: self.copy_to_clipboard(self.private_key_text)).pack(side='left')
        
    def create_certificate_tab(self):
        """Tab de generación de certificados X.509"""
        # Contenedor principal
        main = tk.Frame(self.tab_certificate, bg=self.colors['bg_medium'])
        main.pack(fill='both', expand=True, padx=30, pady=30)
        
        # Instrucciones
        instructions = tk.Label(main,
                               text="Genera un certificado X.509 auto-firmado con tus claves RSA",
                               font=('Segoe UI', 11),
                               bg=self.colors['bg_medium'],
                               fg=self.colors['text_secondary'])
        instructions.pack(pady=(0, 20))
        
        # Frame de información del certificado
        info_frame = tk.Frame(main, bg=self.colors['bg_light'])
        info_frame.pack(fill='x', pady=(0, 20))
        
        # Título
        tk.Label(info_frame,
                text="Información del Certificado",
                font=('Segoe UI', 12, 'bold'),
                bg=self.colors['bg_light'],
                fg=self.colors['accent']).pack(anchor='w', padx=20, pady=(15, 10))
        
        # Grid para campos
        fields_frame = tk.Frame(info_frame, bg=self.colors['bg_light'])
        fields_frame.pack(fill='x', padx=20, pady=(0, 15))
        
        # Campos del certificado
        self.cert_fields = {}
        fields = [
            ('Nombre Completo (CN):', 'common_name', 'Joe User'),
            ('Unidad Organizacional (OU):', 'organizational_unit', 'Security'),
            ('Organización (O):', 'organization', 'Company, Inc.'),
            ('Ciudad (L):', 'locality', 'User City'),
            ('Estado/Provincia (ST):', 'state', 'MN'),
            ('País (C) [2 letras]:', 'country', 'US')
        ]
        
        for i, (label, key, default) in enumerate(fields):
            tk.Label(fields_frame,
                    text=label,
                    font=('Segoe UI', 9),
                    bg=self.colors['bg_light'],
                    fg=self.colors['text']).grid(row=i, column=0, sticky='w', pady=5)
            
            entry = tk.Entry(fields_frame,
                           font=('Segoe UI', 9),
                           bg=self.colors['bg_dark'],
                           fg=self.colors['text'],
                           insertbackground=self.colors['text'],
                           width=30)
            entry.grid(row=i, column=1, sticky='ew', padx=(10, 0), pady=5)
            entry.insert(0, default)
            self.cert_fields[key] = entry
            
        fields_frame.columnconfigure(1, weight=1)
        
        # Validez del certificado
        validity_frame = tk.Frame(info_frame, bg=self.colors['bg_light'])
        validity_frame.pack(fill='x', padx=20, pady=(10, 15))
        
        tk.Label(validity_frame,
                text="Validez (días):",
                font=('Segoe UI', 9, 'bold'),
                bg=self.colors['bg_light'],
                fg=self.colors['text']).pack(side='left')
        
        self.cert_validity = tk.Entry(validity_frame,
                                     font=('Segoe UI', 9),
                                     bg=self.colors['bg_dark'],
                                     fg=self.colors['text'],
                                     insertbackground=self.colors['text'],
                                     width=10)
        self.cert_validity.pack(side='left', padx=10)
        self.cert_validity.insert(0, '365')
        
        tk.Label(validity_frame,
                text="(De 1 a 3650 días)",
                font=('Segoe UI', 8),
                bg=self.colors['bg_light'],
                fg=self.colors['text_secondary']).pack(side='left')
        
        # Botón generar certificado
        btn_generate = tk.Button(main,
                                text="📜 Generar Certificado Auto-firmado",
                                font=('Segoe UI', 12, 'bold'),
                                bg=self.colors['accent'],
                                fg='#000000',
                                activebackground=self.colors['accent_hover'],
                                relief='flat',
                                cursor='hand2',
                                padx=30,
                                pady=12,
                                command=self.generate_certificate)
        btn_generate.pack(pady=15)
        
        # Frame para mostrar certificado
        cert_display_frame = tk.Frame(main, bg=self.colors['bg_medium'])
        cert_display_frame.pack(fill='both', expand=True, pady=(20, 0))
        
        # Label del certificado
        cert_label = tk.Label(cert_display_frame,
                             text="📜 CERTIFICADO X.509 GENERADO",
                             font=('Segoe UI', 11, 'bold'),
                             bg=self.colors['bg_medium'],
                             fg=self.colors['accent'])
        cert_label.pack(anchor='w', pady=(0, 5))
        
        # Área de texto para certificado
        self.certificate_text = scrolledtext.ScrolledText(cert_display_frame,
                                                         height=12,
                                                         font=('Consolas', 9),
                                                         bg=self.colors['bg_dark'],
                                                         fg=self.colors['text'],
                                                         insertbackground=self.colors['text'],
                                                         relief='flat',
                                                         wrap='word')
        self.certificate_text.pack(fill='both', expand=True, pady=(0, 10))
        
        # Botones para certificado
        cert_buttons = tk.Frame(cert_display_frame, bg=self.colors['bg_medium'])
        cert_buttons.pack(fill='x', pady=(0, 10))
        
        tk.Button(cert_buttons,
                 text="💾 Exportar Certificado (.crt)",
                 font=('Segoe UI', 9),
                 bg=self.colors['bg_light'],
                 fg=self.colors['text'],
                 activebackground=self.colors['bg_dark'],
                 relief='flat',
                 cursor='hand2',
                 padx=15,
                 pady=5,
                 command=self.export_certificate).pack(side='left', padx=(0, 10))
        
        tk.Button(cert_buttons,
                 text="📂 Importar Certificado (.crt)",
                 font=('Segoe UI', 9),
                 bg=self.colors['bg_light'],
                 fg=self.colors['text'],
                 activebackground=self.colors['bg_dark'],
                 relief='flat',
                 cursor='hand2',
                 padx=15,
                 pady=5,
                 command=self.import_certificate).pack(side='left', padx=(0, 10))
        
        tk.Button(cert_buttons,
                 text="🔍 Ver Detalles",
                 font=('Segoe UI', 9),
                 bg=self.colors['bg_light'],
                 fg=self.colors['text'],
                 activebackground=self.colors['bg_dark'],
                 relief='flat',
                 cursor='hand2',
                 padx=15,
                 pady=5,
                 command=self.show_certificate_details).pack(side='left', padx=(0, 10))
        
        tk.Button(cert_buttons,
                 text="📋 Copiar",
                 font=('Segoe UI', 9),
                 bg=self.colors['bg_light'],
                 fg=self.colors['text'],
                 activebackground=self.colors['bg_dark'],
                 relief='flat',
                 cursor='hand2',
                 padx=15,
                 pady=5,
                 command=lambda: self.copy_to_clipboard(self.certificate_text)).pack(side='left')
        
    def create_sign_tab(self):
        """Tab de firma de mensajes"""
        # Contenedor principal
        main = tk.Frame(self.tab_sign, bg=self.colors['bg_medium'])
        main.pack(fill='both', expand=True, padx=30, pady=30)
        
        # Instrucciones
        instructions = tk.Label(main,
                               text="Firma un mensaje usando tu clave privada",
                               font=('Segoe UI', 11),
                               bg=self.colors['bg_medium'],
                               fg=self.colors['text_secondary'])
        instructions.pack(pady=(0, 20))
        
        # Botón cargar clave privada
        load_frame = tk.Frame(main, bg=self.colors['bg_medium'])
        load_frame.pack(fill='x', pady=(0, 15))
        
        tk.Button(load_frame,
                 text="📂 Cargar Clave Privada",
                 font=('Segoe UI', 10, 'bold'),
                 bg=self.colors['bg_light'],
                 fg=self.colors['text'],
                 activebackground=self.colors['bg_dark'],
                 relief='flat',
                 cursor='hand2',
                 padx=20,
                 pady=8,
                 command=self.load_private_key).pack(side='left')
        
        self.private_key_status = tk.Label(load_frame,
                                          text="❌ Clave privada no cargada",
                                          font=('Segoe UI', 10),
                                          bg=self.colors['bg_medium'],
                                          fg=self.colors['error'])
        self.private_key_status.pack(side='left', padx=20)
        
        # Mensaje a firmar
        msg_label = tk.Label(main,
                            text="📝 Mensaje a firmar:",
                            font=('Segoe UI', 11, 'bold'),
                            bg=self.colors['bg_medium'],
                            fg=self.colors['text'])
        msg_label.pack(anchor='w', pady=(10, 5))
        
        self.sign_message_text = scrolledtext.ScrolledText(main,
                                                           height=8,
                                                           font=('Segoe UI', 10),
                                                           bg=self.colors['bg_dark'],
                                                           fg=self.colors['text'],
                                                           insertbackground=self.colors['text'],
                                                           relief='flat',
                                                           wrap='word')
        self.sign_message_text.pack(fill='both', expand=True, pady=(0, 15))
        
        # Algoritmo hash
        hash_frame = tk.Frame(main, bg=self.colors['bg_medium'])
        hash_frame.pack(fill='x', pady=(0, 15))
        
        tk.Label(hash_frame,
                text="Algoritmo Hash:",
                font=('Segoe UI', 10, 'bold'),
                bg=self.colors['bg_medium'],
                fg=self.colors['text']).pack(side='left', padx=(0, 10))
        
        self.hash_algo_var = tk.StringVar(value="SHA256")
        for algo in ['SHA256', 'SHA384', 'SHA512']:
            rb = tk.Radiobutton(hash_frame,
                               text=algo,
                               variable=self.hash_algo_var,
                               value=algo,
                               font=('Segoe UI', 10),
                               bg=self.colors['bg_medium'],
                               fg=self.colors['text'],
                               selectcolor=self.colors['bg_light'],
                               activebackground=self.colors['bg_medium'],
                               activeforeground=self.colors['accent'])
            rb.pack(side='left', padx=10)
        
        # Botón firmar
        btn_sign = tk.Button(main,
                            text="✍️ Firmar Mensaje",
                            font=('Segoe UI', 12, 'bold'),
                            bg=self.colors['accent'],
                            fg='#000000',
                            activebackground=self.colors['accent_hover'],
                            relief='flat',
                            cursor='hand2',
                            padx=30,
                            pady=12,
                            command=self.sign_message)
        btn_sign.pack(pady=15)
        
        # Firma generada
        sig_label = tk.Label(main,
                            text="🔏 Firma Digital Generada:",
                            font=('Segoe UI', 11, 'bold'),
                            bg=self.colors['bg_medium'],
                            fg=self.colors['accent'])
        sig_label.pack(anchor='w', pady=(10, 5))
        
        self.signature_text = scrolledtext.ScrolledText(main,
                                                       height=6,
                                                       font=('Consolas', 9),
                                                       bg=self.colors['bg_dark'],
                                                       fg=self.colors['text'],
                                                       insertbackground=self.colors['text'],
                                                       relief='flat',
                                                       wrap='word')
        self.signature_text.pack(fill='both', pady=(0, 10))
        
        # Botones para firma
        sig_buttons = tk.Frame(main, bg=self.colors['bg_medium'])
        sig_buttons.pack(fill='x')
        
        tk.Button(sig_buttons,
                 text="💾 Guardar Firma",
                 font=('Segoe UI', 9),
                 bg=self.colors['bg_light'],
                 fg=self.colors['text'],
                 activebackground=self.colors['bg_dark'],
                 relief='flat',
                 cursor='hand2',
                 padx=15,
                 pady=5,
                 command=self.save_signature).pack(side='left', padx=(0, 10))
        
        tk.Button(sig_buttons,
                 text="📋 Copiar",
                 font=('Segoe UI', 9),
                 bg=self.colors['bg_light'],
                 fg=self.colors['text'],
                 activebackground=self.colors['bg_dark'],
                 relief='flat',
                 cursor='hand2',
                 padx=15,
                 pady=5,
                 command=lambda: self.copy_to_clipboard(self.signature_text)).pack(side='left')
        
    def create_verify_tab(self):
        """Tab de verificación de firmas"""
        # Contenedor principal
        main = tk.Frame(self.tab_verify, bg=self.colors['bg_medium'])
        main.pack(fill='both', expand=True, padx=30, pady=30)
        
        # Instrucciones
        instructions = tk.Label(main,
                               text="Verifica la autenticidad de un mensaje firmado",
                               font=('Segoe UI', 11),
                               bg=self.colors['bg_medium'],
                               fg=self.colors['text_secondary'])
        instructions.pack(pady=(0, 20))
        
        # Botón cargar clave pública
        load_frame = tk.Frame(main, bg=self.colors['bg_medium'])
        load_frame.pack(fill='x', pady=(0, 15))
        
        tk.Button(load_frame,
                 text="📂 Cargar Clave Pública",
                 font=('Segoe UI', 10, 'bold'),
                 bg=self.colors['bg_light'],
                 fg=self.colors['text'],
                 activebackground=self.colors['bg_dark'],
                 relief='flat',
                 cursor='hand2',
                 padx=20,
                 pady=8,
                 command=self.load_public_key).pack(side='left')
        
        self.public_key_status = tk.Label(load_frame,
                                         text="❌ Clave pública no cargada",
                                         font=('Segoe UI', 10),
                                         bg=self.colors['bg_medium'],
                                         fg=self.colors['error'])
        self.public_key_status.pack(side='left', padx=20)
        
        # Mensaje original
        msg_label = tk.Label(main,
                            text="📝 Mensaje Original:",
                            font=('Segoe UI', 11, 'bold'),
                            bg=self.colors['bg_medium'],
                            fg=self.colors['text'])
        msg_label.pack(anchor='w', pady=(10, 5))
        
        self.verify_message_text = scrolledtext.ScrolledText(main,
                                                             height=6,
                                                             font=('Segoe UI', 10),
                                                             bg=self.colors['bg_dark'],
                                                             fg=self.colors['text'],
                                                             insertbackground=self.colors['text'],
                                                             relief='flat',
                                                             wrap='word')
        self.verify_message_text.pack(fill='both', pady=(0, 15))
        
        # Firma a verificar
        sig_label = tk.Label(main,
                            text="🔏 Firma Digital:",
                            font=('Segoe UI', 11, 'bold'),
                            bg=self.colors['bg_medium'],
                            fg=self.colors['text'])
        sig_label.pack(anchor='w', pady=(10, 5))
        
        self.verify_signature_text = scrolledtext.ScrolledText(main,
                                                               height=4,
                                                               font=('Consolas', 9),
                                                               bg=self.colors['bg_dark'],
                                                               fg=self.colors['text'],
                                                               insertbackground=self.colors['text'],
                                                               relief='flat',
                                                               wrap='word')
        self.verify_signature_text.pack(fill='both', pady=(0, 15))
        
        # Botón con carga de firma
        tk.Button(main,
                 text="📂 Cargar Firma desde Archivo",
                 font=('Segoe UI', 9),
                 bg=self.colors['bg_light'],
                 fg=self.colors['text'],
                 activebackground=self.colors['bg_dark'],
                 relief='flat',
                 cursor='hand2',
                 padx=15,
                 pady=5,
                 command=self.load_signature).pack(pady=(0, 15))
        
        # Botón verificar
        btn_verify = tk.Button(main,
                              text="✅ Verificar Firma",
                              font=('Segoe UI', 12, 'bold'),
                              bg=self.colors['accent'],
                              fg='#000000',
                              activebackground=self.colors['accent_hover'],
                              relief='flat',
                              cursor='hand2',
                              padx=30,
                              pady=12,
                              command=self.verify_signature)
        btn_verify.pack(pady=15)
        
        # Resultado de verificación
        self.verify_result_frame = tk.Frame(main, bg=self.colors['bg_light'])
        self.verify_result_frame.pack(fill='x', pady=(10, 0))
        
        self.verify_result_label = tk.Label(self.verify_result_frame,
                                           text="",
                                           font=('Segoe UI', 12, 'bold'),
                                           bg=self.colors['bg_light'],
                                           fg=self.colors['text'])
        self.verify_result_label.pack(pady=20)
        
    # ==================== FUNCIONES DE LÓGICA ====================
    
    def generate_keypair(self):
        """Generar par de claves RSA"""
        try:
            key_size = int(self.key_size_var.get())
            
            # Generar clave privada
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size,
                backend=default_backend()
            )
            
            # Obtener clave pública
            self.public_key = self.private_key.public_key()
            
            # Serializar clave pública (PEM)
            public_pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
            
            # Serializar clave privada (PEM)
            private_pem = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')
            
            # Mostrar en interfaz
            self.public_key_text.delete('1.0', tk.END)
            self.public_key_text.insert('1.0', public_pem)
            
            self.private_key_text.delete('1.0', tk.END)
            self.private_key_text.insert('1.0', private_pem)
            
            # Actualizar estados
            self.private_key_status.config(text="✅ Clave privada cargada",
                                          fg=self.colors['success'])
            self.public_key_status.config(text="✅ Clave pública cargada",
                                         fg=self.colors['success'])
            
            messagebox.showinfo("Éxito", 
                               f"Par de claves RSA-{key_size} generado correctamente")
            
        except Exception as e:
            messagebox.showerror("Error", f"Error al generar claves: {str(e)}")
    
    def sign_message(self):
        """Firmar un mensaje"""
        if not self.private_key:
            messagebox.showwarning("Advertencia", 
                                  "Primero debes generar o cargar una clave privada")
            return
        
        message = self.sign_message_text.get('1.0', tk.END).strip()
        if not message:
            messagebox.showwarning("Advertencia", "Ingresa un mensaje para firmar")
            return
        
        try:
            # Seleccionar algoritmo hash
            hash_algo = self.hash_algo_var.get()
            if hash_algo == 'SHA256':
                hash_func = hashes.SHA256()
            elif hash_algo == 'SHA384':
                hash_func = hashes.SHA384()
            else:
                hash_func = hashes.SHA512()
            
            # Firmar mensaje
            self.signature = self.private_key.sign(
                message.encode('utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hash_func),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hash_func
            )
            
            # Convertir a base64 para visualización
            signature_b64 = base64.b64encode(self.signature).decode('utf-8')
            
            # Mostrar firma
            self.signature_text.delete('1.0', tk.END)
            self.signature_text.insert('1.0', signature_b64)
            
            messagebox.showinfo("Éxito", 
                               f"Mensaje firmado con {hash_algo}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Error al firmar: {str(e)}")
    
    def verify_signature(self):
        """Verificar una firma digital"""
        if not self.public_key:
            messagebox.showwarning("Advertencia", 
                                  "Primero debes cargar una clave pública")
            return
        
        message = self.verify_message_text.get('1.0', tk.END).strip()
        signature_b64 = self.verify_signature_text.get('1.0', tk.END).strip()
        
        if not message or not signature_b64:
            messagebox.showwarning("Advertencia", 
                                  "Ingresa el mensaje y la firma")
            return
        
        try:
            # Decodificar firma de base64
            signature = base64.b64decode(signature_b64)
            
            # Intentar verificar con diferentes algoritmos hash
            verified = False
            hash_used = None
            
            for hash_name, hash_func in [('SHA256', hashes.SHA256()),
                                         ('SHA384', hashes.SHA384()),
                                         ('SHA512', hashes.SHA512())]:
                try:
                    self.public_key.verify(
                        signature,
                        message.encode('utf-8'),
                        padding.PSS(
                            mgf=padding.MGF1(hash_func),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hash_func
                    )
                    verified = True
                    hash_used = hash_name
                    break
                except:
                    continue
            
            if verified:
                self.verify_result_label.config(
                    text=f"✅ FIRMA VÁLIDA (Hash: {hash_used})",
                    fg=self.colors['success']
                )
                messagebox.showinfo("Verificación Exitosa", 
                                   f"La firma es válida\nAlgoritmo: {hash_used}")
            else:
                self.verify_result_label.config(
                    text="❌ FIRMA INVÁLIDA",
                    fg=self.colors['error']
                )
                messagebox.showerror("Verificación Fallida", 
                                    "La firma no es válida o el mensaje fue alterado")
            
        except Exception as e:
            self.verify_result_label.config(
                text="❌ ERROR EN VERIFICACIÓN",
                fg=self.colors['error']
            )
            messagebox.showerror("Error", f"Error al verificar: {str(e)}")
    
    # ==================== FUNCIONES DE ARCHIVO ====================
    
    def save_public_key(self):
        """Guardar clave pública en archivo"""
        if not self.public_key:
            messagebox.showwarning("Advertencia", "No hay clave pública para guardar")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".pem",
            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")],
            initialfile="public_key.pem"
        )
        
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write(self.public_key_text.get('1.0', tk.END))
                messagebox.showinfo("Éxito", "Clave pública guardada")
            except Exception as e:
                messagebox.showerror("Error", f"Error al guardar: {str(e)}")
    
    def save_private_key(self):
        """Guardar clave privada en archivo"""
        if not self.private_key:
            messagebox.showwarning("Advertencia", "No hay clave privada para guardar")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".pem",
            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")],
            initialfile="private_key.pem"
        )
        
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write(self.private_key_text.get('1.0', tk.END))
                messagebox.showinfo("Éxito", "Clave privada guardada")
            except Exception as e:
                messagebox.showerror("Error", f"Error al guardar: {str(e)}")
    
    def save_signature(self):
        """Guardar firma en archivo"""
        signature = self.signature_text.get('1.0', tk.END).strip()
        if not signature:
            messagebox.showwarning("Advertencia", "No hay firma para guardar")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".sig",
            filetypes=[("Signature files", "*.sig"), ("Text files", "*.txt"), 
                      ("All files", "*.*")],
            initialfile="signature.sig"
        )
        
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write(signature)
                messagebox.showinfo("Éxito", "Firma guardada")
            except Exception as e:
                messagebox.showerror("Error", f"Error al guardar: {str(e)}")
    
    def load_private_key(self):
        """Cargar clave privada desde archivo"""
        filename = filedialog.askopenfilename(
            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'rb') as f:
                    key_data = f.read()
                    self.private_key = serialization.load_pem_private_key(
                        key_data,
                        password=None,
                        backend=default_backend()
                    )
                    self.public_key = self.private_key.public_key()
                    
                self.private_key_status.config(text="✅ Clave privada cargada",
                                              fg=self.colors['success'])
                messagebox.showinfo("Éxito", "Clave privada cargada")
            except Exception as e:
                messagebox.showerror("Error", f"Error al cargar: {str(e)}")
    
    def load_public_key(self):
        """Cargar clave pública desde archivo"""
        filename = filedialog.askopenfilename(
            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'rb') as f:
                    key_data = f.read()
                    self.public_key = serialization.load_pem_public_key(
                        key_data,
                        backend=default_backend()
                    )
                    
                self.public_key_status.config(text="✅ Clave pública cargada",
                                             fg=self.colors['success'])
                messagebox.showinfo("Éxito", "Clave pública cargada")
            except Exception as e:
                messagebox.showerror("Error", f"Error al cargar: {str(e)}")
    
    def load_signature(self):
        """Cargar firma desde archivo"""
        filename = filedialog.askopenfilename(
            filetypes=[("Signature files", "*.sig"), ("Text files", "*.txt"),
                      ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'r') as f:
                    signature = f.read()
                    self.verify_signature_text.delete('1.0', tk.END)
                    self.verify_signature_text.insert('1.0', signature)
                messagebox.showinfo("Éxito", "Firma cargada")
            except Exception as e:
                messagebox.showerror("Error", f"Error al cargar: {str(e)}")
    
    def copy_to_clipboard(self, text_widget):
        """Copiar contenido al portapapeles"""
        content = text_widget.get('1.0', tk.END).strip()
        if content:
            self.root.clipboard_clear()
            self.root.clipboard_append(content)
            messagebox.showinfo("Éxito", "Contenido copiado al portapapeles")
        else:
            messagebox.showwarning("Advertencia", "No hay contenido para copiar")
    
    # ==================== FUNCIONES DE CERTIFICADOS ====================
    
    def generate_certificate(self):
        """Generar certificado X.509 auto-firmado"""
        if not self.private_key:
            messagebox.showwarning("Advertencia", 
                                  "Primero debes generar o cargar un par de claves RSA")
            self.notebook.select(0)  # Cambiar a pestaña de claves
            return
        
        try:
            # Obtener datos del formulario
            common_name = self.cert_fields['common_name'].get().strip()
            organizational_unit = self.cert_fields['organizational_unit'].get().strip()
            organization = self.cert_fields['organization'].get().strip()
            locality = self.cert_fields['locality'].get().strip()
            state = self.cert_fields['state'].get().strip()
            country = self.cert_fields['country'].get().strip()
            validity_days = int(self.cert_validity.get())
            
            # Validaciones
            if not common_name:
                messagebox.showwarning("Advertencia", "El nombre completo (CN) es obligatorio")
                return
            
            if len(country) != 2:
                messagebox.showwarning("Advertencia", "El código de país debe tener 2 letras")
                return
            
            if validity_days < 1 or validity_days > 3650:
                messagebox.showwarning("Advertencia", "La validez debe estar entre 1 y 3650 días")
                return
            
            # Crear el subject (información del titular)
            subject_components = []
            if country:
                subject_components.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country.upper()))
            if state:
                subject_components.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state))
            if locality:
                subject_components.append(x509.NameAttribute(NameOID.LOCALITY_NAME, locality))
            if organization:
                subject_components.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization))
            if organizational_unit:
                subject_components.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit))
            subject_components.append(x509.NameAttribute(NameOID.COMMON_NAME, common_name))
            
            subject = issuer = x509.Name(subject_components)
            
            # Generar número de serie aleatorio
            serial_number = x509.random_serial_number()
            
            # Fechas de validez
            not_valid_before = datetime.datetime.utcnow()
            not_valid_after = not_valid_before + datetime.timedelta(days=validity_days)
            
            # Construir el certificado
            cert_builder = x509.CertificateBuilder()
            cert_builder = cert_builder.subject_name(subject)
            cert_builder = cert_builder.issuer_name(issuer)
            cert_builder = cert_builder.public_key(self.public_key)
            cert_builder = cert_builder.serial_number(serial_number)
            cert_builder = cert_builder.not_valid_before(not_valid_before)
            cert_builder = cert_builder.not_valid_after(not_valid_after)
            
            # Agregar extensiones
            cert_builder = cert_builder.add_extension(
                x509.SubjectKeyIdentifier.from_public_key(self.public_key),
                critical=False
            )
            
            cert_builder = cert_builder.add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True
            )
            
            cert_builder = cert_builder.add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    key_cert_sign=True,
                    crl_sign=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True
            )
            
            # Firmar el certificado con la clave privada (auto-firmado)
            self.certificate = cert_builder.sign(self.private_key, hashes.SHA256(), default_backend())
            
            # Serializar a PEM
            cert_pem = self.certificate.public_bytes(serialization.Encoding.PEM).decode('utf-8')
            
            # Mostrar en interfaz
            self.certificate_text.delete('1.0', tk.END)
            self.certificate_text.insert('1.0', cert_pem)
            
            messagebox.showinfo("Éxito", 
                               f"Certificado X.509 generado exitosamente\n" +
                               f"Válido desde: {not_valid_before.strftime('%Y-%m-%d %H:%M:%S')} UTC\n" +
                               f"Válido hasta: {not_valid_after.strftime('%Y-%m-%d %H:%M:%S')} UTC\n" +
                               f"Serial: {hex(serial_number)}")
            
        except ValueError as e:
            messagebox.showerror("Error", f"Error en los datos ingresados: {str(e)}")
        except Exception as e:
            messagebox.showerror("Error", f"Error al generar certificado: {str(e)}")
    
    def export_certificate(self):
        """Exportar certificado a archivo .crt"""
        if not self.certificate:
            messagebox.showwarning("Advertencia", "No hay certificado para exportar")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".crt",
            filetypes=[("Certificate files", "*.crt"), ("PEM files", "*.pem"), 
                      ("All files", "*.*")],
            initialfile="certificate.crt"
        )
        
        if filename:
            try:
                cert_pem = self.certificate.public_bytes(serialization.Encoding.PEM)
                with open(filename, 'wb') as f:
                    f.write(cert_pem)
                messagebox.showinfo("Éxito", f"Certificado exportado a:\n{filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Error al exportar: {str(e)}")
    
    def import_certificate(self):
        """Importar certificado desde archivo .crt"""
        filename = filedialog.askopenfilename(
            filetypes=[("Certificate files", "*.crt"), ("PEM files", "*.pem"),
                      ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'rb') as f:
                    cert_data = f.read()
                    self.certificate = x509.load_pem_x509_certificate(cert_data, default_backend())
                
                # Extraer clave pública del certificado
                self.public_key = self.certificate.public_key()
                
                # Mostrar certificado
                cert_pem = self.certificate.public_bytes(serialization.Encoding.PEM).decode('utf-8')
                self.certificate_text.delete('1.0', tk.END)
                self.certificate_text.insert('1.0', cert_pem)
                
                # Actualizar estado
                self.public_key_status.config(text="✅ Clave pública cargada (desde certificado)",
                                             fg=self.colors['success'])
                
                messagebox.showinfo("Éxito", 
                                   f"Certificado importado exitosamente\n" +
                                   f"Subject: {self.certificate.subject.rfc4514_string()}")
            except Exception as e:
                messagebox.showerror("Error", f"Error al importar certificado: {str(e)}")
    
    def show_certificate_details(self):
        """Mostrar detalles del certificado en una ventana emergente"""
        if not self.certificate:
            messagebox.showwarning("Advertencia", "No hay certificado cargado")
            return
        
        try:
            # Crear ventana de detalles
            details_window = tk.Toplevel(self.root)
            details_window.title("Detalles del Certificado X.509")
            details_window.geometry("700x600")
            details_window.configure(bg=self.colors['bg_dark'])
            
            # Frame principal
            main_frame = tk.Frame(details_window, bg=self.colors['bg_dark'])
            main_frame.pack(fill='both', expand=True, padx=20, pady=20)
            
            # Título
            tk.Label(main_frame,
                    text="📜 INFORMACIÓN DEL CERTIFICADO",
                    font=('Segoe UI', 14, 'bold'),
                    bg=self.colors['bg_dark'],
                    fg=self.colors['accent']).pack(pady=(0, 15))
            
            # Área de texto con detalles
            details_text = scrolledtext.ScrolledText(main_frame,
                                                     font=('Consolas', 9),
                                                     bg=self.colors['bg_medium'],
                                                     fg=self.colors['text'],
                                                     wrap='word')
            details_text.pack(fill='both', expand=True)
            
            # Recopilar información
            details = "=" * 70 + "\n"
            details += "INFORMACIÓN DEL TITULAR (SUBJECT)\n"
            details += "=" * 70 + "\n\n"
            
            subject = self.certificate.subject
            for attr in subject:
                details += f"{attr.oid._name}: {attr.value}\n"
            
            details += "\n" + "=" * 70 + "\n"
            details += "INFORMACIÓN DEL EMISOR (ISSUER)\n"
            details += "=" * 70 + "\n\n"
            
            issuer = self.certificate.issuer
            for attr in issuer:
                details += f"{attr.oid._name}: {attr.value}\n"
            
            details += "\n" + "=" * 70 + "\n"
            details += "INFORMACIÓN DE VALIDEZ\n"
            details += "=" * 70 + "\n\n"
            
            details += f"Número de Serie: {hex(self.certificate.serial_number)}\n"
            details += f"Válido desde: {self.certificate.not_valid_before.strftime('%Y-%m-%d %H:%M:%S')} UTC\n"
            details += f"Válido hasta: {self.certificate.not_valid_after.strftime('%Y-%m-%d %H:%M:%S')} UTC\n"
            
            # Calcular si está vigente
            now = datetime.datetime.utcnow()
            if now < self.certificate.not_valid_before:
                status = "⏳ Aún no válido"
            elif now > self.certificate.not_valid_after:
                status = "❌ Expirado"
            else:
                status = "✅ Vigente"
            details += f"Estado: {status}\n"
            
            details += "\n" + "=" * 70 + "\n"
            details += "ALGORITMO DE FIRMA\n"
            details += "=" * 70 + "\n\n"
            
            details += f"Algoritmo: {self.certificate.signature_algorithm_oid._name}\n"
            
            details += "\n" + "=" * 70 + "\n"
            details += "HUELLAS DIGITALES (FINGERPRINTS)\n"
            details += "=" * 70 + "\n\n"
            
            # Calcular fingerprints
            cert_der = self.certificate.public_bytes(serialization.Encoding.DER)
            
            md5_hash = hashlib.md5(cert_der).hexdigest()
            details += f"MD5:    {':'.join([md5_hash[i:i+2] for i in range(0, len(md5_hash), 2)]).upper()}\n"
            
            sha1_hash = hashlib.sha1(cert_der).hexdigest()
            details += f"SHA-1:  {':'.join([sha1_hash[i:i+2] for i in range(0, len(sha1_hash), 2)]).upper()}\n"
            
            sha256_hash = hashlib.sha256(cert_der).hexdigest()
            details += f"SHA-256: {':'.join([sha256_hash[i:i+2] for i in range(0, len(sha256_hash), 2)]).upper()}\n"
            
            details += "\n" + "=" * 70 + "\n"
            details += "INFORMACIÓN DE LA CLAVE PÚBLICA\n"
            details += "=" * 70 + "\n\n"
            
            public_key = self.certificate.public_key()
            if isinstance(public_key, rsa.RSAPublicKey):
                details += f"Tipo: RSA\n"
                details += f"Tamaño: {public_key.key_size} bits\n"
                details += f"Exponente público: {public_key.public_numbers().e}\n"
            
            # Extensiones
            details += "\n" + "=" * 70 + "\n"
            details += "EXTENSIONES\n"
            details += "=" * 70 + "\n\n"
            
            for ext in self.certificate.extensions:
                details += f"• {ext.oid._name}\n"
                details += f"  Crítica: {'Sí' if ext.critical else 'No'}\n"
                details += f"  Valor: {ext.value}\n\n"
            
            details += "=" * 70 + "\n"
            
            # Insertar detalles
            details_text.insert('1.0', details)
            details_text.config(state='disabled')
            
            # Botón cerrar
            tk.Button(main_frame,
                     text="Cerrar",
                     font=('Segoe UI', 10, 'bold'),
                     bg=self.colors['accent'],
                     fg='#000000',
                     activebackground=self.colors['accent_hover'],
                     relief='flat',
                     cursor='hand2',
                     padx=30,
                     pady=8,
                     command=details_window.destroy).pack(pady=(15, 0))
            
        except Exception as e:
            messagebox.showerror("Error", f"Error al mostrar detalles: {str(e)}")


# Para pruebas independientes
if __name__ == "__main__":
    root = tk.Tk()
    app = DigitalSignatureModule(root)
    root.mainloop()
