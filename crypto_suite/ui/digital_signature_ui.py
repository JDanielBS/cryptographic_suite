#!/usr/bin/env python3
"""
Laboratorio de Programación Segura
UI: Digital Signature Interface (Punto 1b)

Interfaz gráfica para el módulo de Firma Digital.
Usa la lógica del backend sin mezclar responsabilidades.
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import sys
import os

# Agregar el directorio raíz al path para imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.digital_signature_logic import DigitalSignatureLogic


class DigitalSignatureUI:
    """Interfaz gráfica para Firma Digital"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("✍️ Firma Digital - Suite Criptográfica")
        self.root.geometry("1200x800")
        self.root.configure(bg='#1e1e1e')
        
        # Instancia de la lógica de negocio
        self.logic = DigitalSignatureLogic()
        
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
                        text="✍️ FIRMA DIGITAL",
                        font=('Segoe UI', 24, 'bold'),
                        bg=self.colors['bg_dark'],
                        fg=self.colors['accent'])
        title.pack(anchor='w')
        
        subtitle = tk.Label(title_frame,
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
        container = tk.Frame(self.root, bg=self.colors['bg_dark'])
        container.pack(fill='both', expand=True, padx=30, pady=20)
        
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
        main = tk.Frame(self.tab_keys, bg=self.colors['bg_medium'])
        main.pack(fill='both', expand=True, padx=30, pady=30)
        
        instructions = tk.Label(main,
                               text="Genera un par de claves RSA para firmar y verificar mensajes",
                               font=('Segoe UI', 11),
                               bg=self.colors['bg_medium'],
                               fg=self.colors['text_secondary'])
        instructions.pack(pady=(0, 20))
        
        # Frame de configuración
        config_frame = tk.Frame(main, bg=self.colors['bg_light'])
        config_frame.pack(fill='x', pady=(0, 20))
        
        size_frame = tk.Frame(config_frame, bg=self.colors['bg_light'])
        size_frame.pack(pady=20)
        
        tk.Label(size_frame,
                text="Tamaño de clave:",
                font=('Segoe UI', 10, 'bold'),
                bg=self.colors['bg_light'],
                fg=self.colors['text']).pack(side='left', padx=(20, 10))
        
        self.key_size_var = tk.StringVar(value="2048")
        for size in ['1024', '2048', '4096']:
            tk.Radiobutton(size_frame,
                          text=f"{size} bits",
                          variable=self.key_size_var,
                          value=size,
                          bg=self.colors['bg_light'],
                          fg=self.colors['text'],
                          selectcolor=self.colors['bg_dark'],
                          activebackground=self.colors['bg_light'],
                          font=('Segoe UI', 10)).pack(side='left', padx=10)
        
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
        main = tk.Frame(self.tab_certificate, bg=self.colors['bg_medium'])
        main.pack(fill='both', expand=True, padx=30, pady=30)
        
        instructions = tk.Label(main,
                               text="Genera un certificado X.509 auto-firmado con tus claves RSA",
                               font=('Segoe UI', 11),
                               bg=self.colors['bg_medium'],
                               fg=self.colors['text_secondary'])
        instructions.pack(pady=(0, 20))
        
        # Frame de información del certificado
        info_frame = tk.Frame(main, bg=self.colors['bg_light'])
        info_frame.pack(fill='x', pady=(0, 20))
        
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
                    font=('Segoe UI', 9, 'bold'),
                    bg=self.colors['bg_light'],
                    fg=self.colors['text']).grid(row=i, column=0, sticky='w', pady=5)
            
            entry = tk.Entry(fields_frame,
                           font=('Segoe UI', 9),
                           bg=self.colors['bg_dark'],
                           fg=self.colors['text'],
                           insertbackground=self.colors['text'])
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
        
        cert_label = tk.Label(cert_display_frame,
                             text="📜 CERTIFICADO X.509 GENERADO",
                             font=('Segoe UI', 11, 'bold'),
                             bg=self.colors['bg_medium'],
                             fg=self.colors['accent'])
        cert_label.pack(anchor='w', pady=(0, 5))
        
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
        main = tk.Frame(self.tab_sign, bg=self.colors['bg_medium'])
        main.pack(fill='both', expand=True, padx=30, pady=30)
        
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
            tk.Radiobutton(hash_frame,
                          text=algo,
                          variable=self.hash_algo_var,
                          value=algo,
                          bg=self.colors['bg_medium'],
                          fg=self.colors['text'],
                          selectcolor=self.colors['bg_dark'],
                          activebackground=self.colors['bg_medium'],
                          font=('Segoe UI', 10)).pack(side='left', padx=10)
        
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
        main = tk.Frame(self.tab_verify, bg=self.colors['bg_medium'])
        main.pack(fill='both', expand=True, padx=30, pady=30)
        
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
        
        # Botón cargar firma
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
        self.verify_result_label = tk.Label(main,
                                           text="",
                                           font=('Segoe UI', 14, 'bold'),
                                           bg=self.colors['bg_medium'])
        self.verify_result_label.pack(pady=20)
    
    # ==================== MÉTODOS DE EVENTOS (Llaman al backend) ====================
    
    def generate_keypair(self):
        """Generar par de claves usando la lógica del backend"""
        try:
            key_size = int(self.key_size_var.get())
            
            # Llamar al backend
            result = self.logic.generate_keypair(key_size)
            
            # Mostrar claves
            self.public_key_text.delete('1.0', tk.END)
            self.public_key_text.insert('1.0', result['public_key_pem'])
            
            self.private_key_text.delete('1.0', tk.END)
            self.private_key_text.insert('1.0', result['private_key_pem'])
            
            # Actualizar estados
            self.private_key_status.config(text="✅ Clave privada cargada",
                                          fg=self.colors['success'])
            self.public_key_status.config(text="✅ Clave pública cargada",
                                         fg=self.colors['success'])
            
            messagebox.showinfo("Éxito", 
                               f"Par de claves RSA-{key_size} generado correctamente")
            
        except ValueError as e:
            messagebox.showerror("Error", str(e))
        except Exception as e:
            messagebox.showerror("Error", f"Error al generar claves: {str(e)}")
    
    def sign_message(self):
        """Firmar mensaje usando la lógica del backend"""
        message = self.sign_message_text.get('1.0', tk.END).strip()
        hash_algorithm = self.hash_algo_var.get()
        
        try:
            # Llamar al backend
            result = self.logic.sign_message(message, hash_algorithm)
            
            # Mostrar firma
            self.signature_text.delete('1.0', tk.END)
            self.signature_text.insert('1.0', result['signature_base64'])
            
            messagebox.showinfo("Éxito", 
                               f"Mensaje firmado con {hash_algorithm}")
            
        except ValueError as e:
            messagebox.showwarning("Advertencia", str(e))
        except Exception as e:
            messagebox.showerror("Error", f"Error al firmar: {str(e)}")
    
    def verify_signature(self):
        """Verificar firma usando la lógica del backend"""
        message = self.verify_message_text.get('1.0', tk.END).strip()
        signature_b64 = self.verify_signature_text.get('1.0', tk.END).strip()
        
        try:
            # Llamar al backend
            result = self.logic.verify_signature(message, signature_b64)
            
            if result['valid']:
                self.verify_result_label.config(
                    text=f"✅ FIRMA VÁLIDA (Hash: {result['hash_algorithm_used']})",
                    fg=self.colors['success']
                )
                messagebox.showinfo("Verificación Exitosa", result['message'])
            else:
                self.verify_result_label.config(
                    text="❌ FIRMA INVÁLIDA",
                    fg=self.colors['error']
                )
                messagebox.showerror("Verificación Fallida", result['message'])
            
        except ValueError as e:
            self.verify_result_label.config(
                text="❌ ERROR EN VERIFICACIÓN",
                fg=self.colors['error']
            )
            messagebox.showwarning("Advertencia", str(e))
        except Exception as e:
            messagebox.showerror("Error", f"Error al verificar: {str(e)}")
    
    def generate_certificate(self):
        """Generar certificado usando la lógica del backend"""
        try:
            # Obtener datos del formulario
            common_name = self.cert_fields['common_name'].get().strip()
            organizational_unit = self.cert_fields['organizational_unit'].get().strip()
            organization = self.cert_fields['organization'].get().strip()
            locality = self.cert_fields['locality'].get().strip()
            state = self.cert_fields['state'].get().strip()
            country = self.cert_fields['country'].get().strip()
            validity_days = int(self.cert_validity.get())
            
            # Llamar al backend
            result = self.logic.generate_certificate(
                common_name=common_name,
                organization=organization,
                organizational_unit=organizational_unit,
                locality=locality,
                state=state,
                country=country,
                validity_days=validity_days
            )
            
            # Mostrar certificado
            self.certificate_text.delete('1.0', tk.END)
            self.certificate_text.insert('1.0', result['certificate_pem'])
            
            messagebox.showinfo("Éxito", 
                               f"Certificado X.509 generado exitosamente\n" +
                               f"Válido desde: {result['not_valid_before']}\n" +
                               f"Válido hasta: {result['not_valid_after']}\n" +
                               f"Serial: {result['serial_number']}")
            
        except ValueError as e:
            messagebox.showwarning("Advertencia", str(e))
        except Exception as e:
            messagebox.showerror("Error", f"Error al generar certificado: {str(e)}")
    
    def show_certificate_details(self):
        """Mostrar detalles del certificado"""
        try:
            # Obtener detalles del backend
            details = self.logic.get_certificate_details()
            
            # Crear ventana de detalles
            details_window = tk.Toplevel(self.root)
            details_window.title("Detalles del Certificado X.509")
            details_window.geometry("700x600")
            details_window.configure(bg=self.colors['bg_dark'])
            
            main_frame = tk.Frame(details_window, bg=self.colors['bg_dark'])
            main_frame.pack(fill='both', expand=True, padx=20, pady=20)
            
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
            
            # Formatear información
            output = "=" * 70 + "\n"
            output += "INFORMACIÓN DEL TITULAR (SUBJECT)\n"
            output += "=" * 70 + "\n\n"
            
            for key, value in details['subject'].items():
                output += f"{key}: {value}\n"
            
            output += "\n" + "=" * 70 + "\n"
            output += "INFORMACIÓN DEL EMISOR (ISSUER)\n"
            output += "=" * 70 + "\n\n"
            
            for key, value in details['issuer'].items():
                output += f"{key}: {value}\n"
            
            output += "\n" + "=" * 70 + "\n"
            output += "INFORMACIÓN DE VALIDEZ\n"
            output += "=" * 70 + "\n\n"
            
            output += f"Número de Serie: {details['serial_number']}\n"
            output += f"Válido desde: {details['not_valid_before']}\n"
            output += f"Válido hasta: {details['not_valid_after']}\n"
            
            status_text = {
                'valid': '✅ Vigente',
                'expired': '❌ Expirado',
                'not_yet_valid': '⏳ Aún no válido'
            }
            output += f"Estado: {status_text.get(details['status'], 'Desconocido')}\n"
            
            output += "\n" + "=" * 70 + "\n"
            output += "ALGORITMO DE FIRMA\n"
            output += "=" * 70 + "\n\n"
            output += f"Algoritmo: {details['signature_algorithm']}\n"
            
            output += "\n" + "=" * 70 + "\n"
            output += "HUELLAS DIGITALES (FINGERPRINTS)\n"
            output += "=" * 70 + "\n\n"
            output += f"MD5:     {details['fingerprints']['md5']}\n"
            output += f"SHA-1:   {details['fingerprints']['sha1']}\n"
            output += f"SHA-256: {details['fingerprints']['sha256']}\n"
            
            output += "\n" + "=" * 70 + "\n"
            output += "INFORMACIÓN DE LA CLAVE PÚBLICA\n"
            output += "=" * 70 + "\n\n"
            output += f"Tipo: {details['public_key']['type']}\n"
            output += f"Tamaño: {details['public_key']['size']} bits\n"
            output += f"Exponente público: {details['public_key']['exponent']}\n"
            
            output += "\n" + "=" * 70 + "\n"
            output += "EXTENSIONES\n"
            output += "=" * 70 + "\n\n"
            
            for ext in details['extensions']:
                output += f"• {ext['name']}\n"
                output += f"  Crítica: {'Sí' if ext['critical'] else 'No'}\n"
                output += f"  Valor: {ext['value']}\n\n"
            
            output += "=" * 70 + "\n"
            
            details_text.insert('1.0', output)
            details_text.config(state='disabled')
            
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
            
        except ValueError as e:
            messagebox.showwarning("Advertencia", str(e))
        except Exception as e:
            messagebox.showerror("Error", f"Error al mostrar detalles: {str(e)}")
    
    # ==================== FUNCIONES DE ARCHIVO ====================
    
    def save_public_key(self):
        """Guardar clave pública en archivo"""
        if not self.logic.has_public_key():
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
        if not self.logic.has_private_key():
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
            filetypes=[("Signature files", "*.sig"), ("Text files", "*.txt"), ("All files", "*.*")],
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
                    result = self.logic.load_private_key_from_pem(key_data)
                    
                self.private_key_status.config(text="✅ Clave privada cargada",
                                              fg=self.colors['success'])
                self.public_key_status.config(text="✅ Clave pública cargada",
                                             fg=self.colors['success'])
                messagebox.showinfo("Éxito", f"Clave privada cargada ({result['key_size']} bits)")
            except ValueError as e:
                messagebox.showerror("Error", str(e))
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
                    result = self.logic.load_public_key_from_pem(key_data)
                    
                self.public_key_status.config(text="✅ Clave pública cargada",
                                             fg=self.colors['success'])
                messagebox.showinfo("Éxito", f"Clave pública cargada ({result['key_size']} bits)")
            except ValueError as e:
                messagebox.showerror("Error", str(e))
            except Exception as e:
                messagebox.showerror("Error", f"Error al cargar: {str(e)}")
    
    def load_signature(self):
        """Cargar firma desde archivo"""
        filename = filedialog.askopenfilename(
            filetypes=[("Signature files", "*.sig"), ("Text files", "*.txt"), ("All files", "*.*")]
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
    
    def export_certificate(self):
        """Exportar certificado a archivo"""
        try:
            cert_pem = self.logic.export_certificate_pem()
            
            filename = filedialog.asksaveasfilename(
                defaultextension=".crt",
                filetypes=[("Certificate files", "*.crt"), ("PEM files", "*.pem"), ("All files", "*.*")],
                initialfile="certificate.crt"
            )
            
            if filename:
                with open(filename, 'w') as f:
                    f.write(cert_pem)
                messagebox.showinfo("Éxito", f"Certificado exportado a:\n{filename}")
        except ValueError as e:
            messagebox.showwarning("Advertencia", str(e))
        except Exception as e:
            messagebox.showerror("Error", f"Error al exportar: {str(e)}")
    
    def import_certificate(self):
        """Importar certificado desde archivo"""
        filename = filedialog.askopenfilename(
            filetypes=[("Certificate files", "*.crt"), ("PEM files", "*.pem"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'rb') as f:
                    cert_data = f.read()
                    result = self.logic.load_certificate_from_pem(cert_data)
                
                # Mostrar certificado
                cert_pem = self.logic.export_certificate_pem()
                self.certificate_text.delete('1.0', tk.END)
                self.certificate_text.insert('1.0', cert_pem)
                
                # Actualizar estado
                self.public_key_status.config(text="✅ Clave pública cargada (desde certificado)",
                                             fg=self.colors['success'])
                
                messagebox.showinfo("Éxito", 
                                   f"Certificado importado exitosamente\n" +
                                   f"Subject: {result['subject']}")
            except ValueError as e:
                messagebox.showerror("Error", str(e))
            except Exception as e:
                messagebox.showerror("Error", f"Error al importar certificado: {str(e)}")
    
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
    app = DigitalSignatureUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
