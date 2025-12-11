#!/usr/bin/env python3
"""
Laboratorio de Programación Segura
UI: Encryption Interface (Punto 1c y 1d)

Interfaz gráfica para cifrado/descifrado RSA.
Usa la lógica del backend sin mezclar responsabilidades.
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import sys
import os

# Agregar el directorio raíz al path para imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.encryption_logic import EncryptionLogic


class EncryptionUI:
    """Interfaz gráfica para Cifrado/Descifrado RSA"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Cifrado RSA - Suite Criptográfica")
        self.root.geometry("1200x800")
        self.root.configure(bg='#1e1e1e')
        
        # Instancia de la lógica de negocio
        self.logic = EncryptionLogic()
        
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
            'accent': '#ff6b35',
            'accent_hover': '#e55a2b',
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
                        text="🔐 CIFRADO Y DESCIFRADO RSA",
                        font=('Segoe UI', 24, 'bold'),
                        bg=self.colors['bg_dark'],
                        fg=self.colors['accent'])
        title.pack(anchor='w')
        
        subtitle = tk.Label(title_frame,
                           text="Cifrado con Clave Privada (1c) y Clave Pública (1d)",
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
        
        # Crear las pestañas (RSA + Simétrico + Híbrido)
        self.tab_keys = tk.Frame(self.notebook, bg=self.colors['bg_medium'])
        self.tab_encrypt_public = tk.Frame(self.notebook, bg=self.colors['bg_medium'])
        self.tab_decrypt_private = tk.Frame(self.notebook, bg=self.colors['bg_medium'])
        self.tab_encrypt_private = tk.Frame(self.notebook, bg=self.colors['bg_medium'])
        self.tab_decrypt_public = tk.Frame(self.notebook, bg=self.colors['bg_medium'])
        self.tab_symmetric = tk.Frame(self.notebook, bg=self.colors['bg_medium'])
        self.tab_hybrid = tk.Frame(self.notebook, bg=self.colors['bg_medium'])
        
        self.notebook.add(self.tab_keys, text='🔑 Generar Claves RSA')
        self.notebook.add(self.tab_encrypt_public, text='🔐 Cifrar (Pública) - 1d')
        self.notebook.add(self.tab_decrypt_private, text='🔓 Descifrar (Privada) - 1d')
        self.notebook.add(self.tab_encrypt_private, text='🔒 Cifrar (Privada) - 1c')
        self.notebook.add(self.tab_decrypt_public, text='✅ Verificar (Pública) - 1c')
        self.notebook.add(self.tab_symmetric, text='🔑 Simétrico (DES/AES/ARC4)')
        self.notebook.add(self.tab_hybrid, text='🔐🔑 Híbrido (RSA+AES)')
        
        # Crear contenido de cada tab
        self.create_keys_tab()
        self.create_encrypt_public_tab()
        self.create_decrypt_private_tab()
        self.create_encrypt_private_tab()
        self.create_decrypt_public_tab()
        self.create_symmetric_tab()
        self.create_hybrid_tab()
        
    def create_keys_tab(self):
        """Tab de generación de claves"""
        main = tk.Frame(self.tab_keys, bg=self.colors['bg_medium'])
        main.pack(fill='both', expand=True, padx=30, pady=30)
        
        instructions = tk.Label(main,
                               text="Genera un par de claves RSA para cifrar y descifrar mensajes",
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
                                fg='#ffffff',
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
                 text="📂 Cargar Clave Pública",
                 font=('Segoe UI', 9),
                 bg=self.colors['bg_light'],
                 fg=self.colors['text'],
                 activebackground=self.colors['bg_dark'],
                 relief='flat',
                 cursor='hand2',
                 padx=15,
                 pady=5,
                 command=self.load_public_key).pack(side='left', padx=(0, 10))
        
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
                 text="📂 Cargar Clave Privada",
                 font=('Segoe UI', 9),
                 bg=self.colors['bg_light'],
                 fg=self.colors['text'],
                 activebackground=self.colors['bg_dark'],
                 relief='flat',
                 cursor='hand2',
                 padx=15,
                 pady=5,
                 command=self.load_private_key).pack(side='left', padx=(0, 10))
        
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
    
    def create_encrypt_public_tab(self):
        """Tab de cifrado con clave pública (Punto 1d - Estándar)"""
        main = tk.Frame(self.tab_encrypt_public, bg=self.colors['bg_medium'])
        main.pack(fill='both', expand=True, padx=30, pady=30)
        
        # Instrucciones
        info_frame = tk.Frame(main, bg=self.colors['bg_light'])
        info_frame.pack(fill='x', pady=(0, 20))
        
        tk.Label(info_frame,
                text="🔐 CIFRADO CON CLAVE PÚBLICA (Punto 1d - Método Estándar)",
                font=('Segoe UI', 12, 'bold'),
                bg=self.colors['bg_light'],
                fg=self.colors['accent']).pack(anchor='w', padx=15, pady=(15, 5))
        
        tk.Label(info_frame,
                text="Cifra un mensaje usando la clave pública del destinatario. Solo quien tenga la clave privada podrá descifrarlo.\n" +
                     "Este es el método estándar de criptografía asimétrica (RSA-OAEP).",
                font=('Segoe UI', 9),
                bg=self.colors['bg_light'],
                fg=self.colors['text_secondary'],
                wraplength=1000,
                justify='left').pack(anchor='w', padx=15, pady=(0, 15))
        
        # Mensaje a cifrar
        msg_label = tk.Label(main,
                            text="📝 Mensaje a cifrar:",
                            font=('Segoe UI', 11, 'bold'),
                            bg=self.colors['bg_medium'],
                            fg=self.colors['text'])
        msg_label.pack(anchor='w', pady=(10, 5))
        
        self.encrypt_public_text = scrolledtext.ScrolledText(main,
                                                             height=8,
                                                             font=('Segoe UI', 10),
                                                             bg=self.colors['bg_dark'],
                                                             fg=self.colors['text'],
                                                             insertbackground=self.colors['text'],
                                                             relief='flat',
                                                             wrap='word')
        self.encrypt_public_text.pack(fill='both', expand=True, pady=(0, 15))
        self.encrypt_public_text.insert('1.0', 'Mensaje secreto para el destinatario')
        
        # Botón cifrar
        btn_encrypt = tk.Button(main,
                               text="🔐 Cifrar con Clave Pública",
                               font=('Segoe UI', 12, 'bold'),
                               bg=self.colors['accent'],
                               fg='#ffffff',
                               activebackground=self.colors['accent_hover'],
                               relief='flat',
                               cursor='hand2',
                               padx=30,
                               pady=12,
                               command=self.encrypt_with_public_key)
        btn_encrypt.pack(pady=15)
        
        # Mensaje cifrado
        cipher_label = tk.Label(main,
                               text="🔐 Mensaje Cifrado (RSA-OAEP):",
                               font=('Segoe UI', 11, 'bold'),
                               bg=self.colors['bg_medium'],
                               fg=self.colors['success'])
        cipher_label.pack(anchor='w', pady=(10, 5))
        
        self.encrypted_public_text = scrolledtext.ScrolledText(main,
                                                               height=8,
                                                               font=('Consolas', 9),
                                                               bg=self.colors['bg_dark'],
                                                               fg=self.colors['success'],
                                                               insertbackground=self.colors['text'],
                                                               relief='flat',
                                                               wrap='word')
        self.encrypted_public_text.pack(fill='both', expand=True, pady=(0, 10))
        
        # Botones
        buttons_frame = tk.Frame(main, bg=self.colors['bg_medium'])
        buttons_frame.pack(fill='x')
        
        tk.Button(buttons_frame,
                 text="💾 Guardar Cifrado",
                 font=('Segoe UI', 9),
                 bg=self.colors['bg_light'],
                 fg=self.colors['text'],
                 activebackground=self.colors['bg_dark'],
                 relief='flat',
                 cursor='hand2',
                 padx=15,
                 pady=5,
                 command=lambda: self.save_to_file(self.encrypted_public_text, "encrypted_public.txt")).pack(side='left', padx=(0, 10))
        
        tk.Button(buttons_frame,
                 text="📋 Copiar",
                 font=('Segoe UI', 9),
                 bg=self.colors['bg_light'],
                 fg=self.colors['text'],
                 activebackground=self.colors['bg_dark'],
                 relief='flat',
                 cursor='hand2',
                 padx=15,
                 pady=5,
                 command=lambda: self.copy_to_clipboard(self.encrypted_public_text)).pack(side='left', padx=(0, 10))
        
        tk.Button(buttons_frame,
                 text="➡️ Copiar a Descifrar",
                 font=('Segoe UI', 9),
                 bg=self.colors['accent'],
                 fg='#ffffff',
                 activebackground=self.colors['accent_hover'],
                 relief='flat',
                 cursor='hand2',
                 padx=15,
                 pady=5,
                 command=self.copy_to_decrypt_private).pack(side='left')
    
    def create_decrypt_private_tab(self):
        """Tab de descifrado con clave privada (Punto 1d)"""
        main = tk.Frame(self.tab_decrypt_private, bg=self.colors['bg_medium'])
        main.pack(fill='both', expand=True, padx=30, pady=30)
        
        # Instrucciones
        info_frame = tk.Frame(main, bg=self.colors['bg_light'])
        info_frame.pack(fill='x', pady=(0, 20))
        
        tk.Label(info_frame,
                text="🔓 DESCIFRADO CON CLAVE PRIVADA (Punto 1d)",
                font=('Segoe UI', 12, 'bold'),
                bg=self.colors['bg_light'],
                fg=self.colors['accent']).pack(anchor='w', padx=15, pady=(15, 5))
        
        tk.Label(info_frame,
                text="Descifra mensajes que fueron cifrados con tu clave pública. Solo tú, con tu clave privada, puedes leerlos.",
                font=('Segoe UI', 9),
                bg=self.colors['bg_light'],
                fg=self.colors['text_secondary'],
                wraplength=1000,
                justify='left').pack(anchor='w', padx=15, pady=(0, 15))
        
        # Mensaje cifrado
        cipher_label = tk.Label(main,
                               text="🔐 Mensaje Cifrado:",
                               font=('Segoe UI', 11, 'bold'),
                               bg=self.colors['bg_medium'],
                               fg=self.colors['text'])
        cipher_label.pack(anchor='w', pady=(10, 5))
        
        self.decrypt_private_text = scrolledtext.ScrolledText(main,
                                                             height=8,
                                                             font=('Consolas', 9),
                                                             bg=self.colors['bg_dark'],
                                                             fg=self.colors['text'],
                                                             insertbackground=self.colors['text'],
                                                             relief='flat',
                                                             wrap='word')
        self.decrypt_private_text.pack(fill='both', expand=True, pady=(0, 15))
        
        # Botones para cargar
        load_frame = tk.Frame(main, bg=self.colors['bg_medium'])
        load_frame.pack(fill='x', pady=(0, 15))
        
        tk.Button(load_frame,
                 text="📂 Cargar desde Archivo",
                 font=('Segoe UI', 9),
                 bg=self.colors['bg_light'],
                 fg=self.colors['text'],
                 activebackground=self.colors['bg_dark'],
                 relief='flat',
                 cursor='hand2',
                 padx=15,
                 pady=5,
                 command=lambda: self.load_from_file(self.decrypt_private_text)).pack(side='left')
        
        # Botón descifrar
        btn_decrypt = tk.Button(main,
                               text="🔓 Descifrar con Clave Privada",
                               font=('Segoe UI', 12, 'bold'),
                               bg=self.colors['accent'],
                               fg='#ffffff',
                               activebackground=self.colors['accent_hover'],
                               relief='flat',
                               cursor='hand2',
                               padx=30,
                               pady=12,
                               command=self.decrypt_with_private_key)
        btn_decrypt.pack(pady=15)
        
        # Mensaje descifrado
        plain_label = tk.Label(main,
                              text="📝 Mensaje Descifrado:",
                              font=('Segoe UI', 11, 'bold'),
                              bg=self.colors['bg_medium'],
                              fg=self.colors['success'])
        plain_label.pack(anchor='w', pady=(10, 5))
        
        self.decrypted_private_text = scrolledtext.ScrolledText(main,
                                                               height=8,
                                                               font=('Segoe UI', 10),
                                                               bg=self.colors['bg_dark'],
                                                               fg=self.colors['success'],
                                                               insertbackground=self.colors['text'],
                                                               relief='flat',
                                                               wrap='word')
        self.decrypted_private_text.pack(fill='both', expand=True, pady=(0, 10))
        
        # Botón copiar
        tk.Button(main,
                 text="📋 Copiar Mensaje",
                 font=('Segoe UI', 9),
                 bg=self.colors['bg_light'],
                 fg=self.colors['text'],
                 activebackground=self.colors['bg_dark'],
                 relief='flat',
                 cursor='hand2',
                 padx=15,
                 pady=5,
                 command=lambda: self.copy_to_clipboard(self.decrypted_private_text)).pack()
    
    def create_encrypt_private_tab(self):
        """Tab de cifrado con clave privada (Punto 1c - Firma)"""
        main = tk.Frame(self.tab_encrypt_private, bg=self.colors['bg_medium'])
        main.pack(fill='both', expand=True, padx=30, pady=30)
        
        # Instrucciones
        info_frame = tk.Frame(main, bg=self.colors['bg_light'])
        info_frame.pack(fill='x', pady=(0, 20))
        
        tk.Label(info_frame,
                text="🔒 CIFRADO CON CLAVE PRIVADA (Punto 1c - Firma Digital)",
                font=('Segoe UI', 12, 'bold'),
                bg=self.colors['bg_light'],
                fg=self.colors['accent']).pack(anchor='w', padx=15, pady=(15, 5))
        
        tk.Label(info_frame,
                text="Cifra (firma) un mensaje usando tu clave privada. Cualquiera con tu clave pública podrá verificar su autenticidad.\n" +
                     "Esto demuestra que tú creaste el mensaje (autenticación).",
                font=('Segoe UI', 9),
                bg=self.colors['bg_light'],
                fg=self.colors['text_secondary'],
                wraplength=1000,
                justify='left').pack(anchor='w', padx=15, pady=(0, 15))
        
        # Mensaje a cifrar
        msg_label = tk.Label(main,
                            text="📝 Mensaje a cifrar/firmar:",
                            font=('Segoe UI', 11, 'bold'),
                            bg=self.colors['bg_medium'],
                            fg=self.colors['text'])
        msg_label.pack(anchor='w', pady=(10, 5))
        
        self.encrypt_private_text = scrolledtext.ScrolledText(main,
                                                              height=8,
                                                              font=('Segoe UI', 10),
                                                              bg=self.colors['bg_dark'],
                                                              fg=self.colors['text'],
                                                              insertbackground=self.colors['text'],
                                                              relief='flat',
                                                              wrap='word')
        self.encrypt_private_text.pack(fill='both', expand=True, pady=(0, 15))
        self.encrypt_private_text.insert('1.0', 'Mensaje autenticado con mi clave privada')
        
        # Algoritmo hash
        hash_frame = tk.Frame(main, bg=self.colors['bg_medium'])
        hash_frame.pack(fill='x', pady=(0, 15))
        
        tk.Label(hash_frame,
                text="Algoritmo Hash:",
                font=('Segoe UI', 10, 'bold'),
                bg=self.colors['bg_medium'],
                fg=self.colors['text']).pack(side='left', padx=(0, 10))
        
        self.encrypt_hash_var = tk.StringVar(value="SHA256")
        for algo in ['SHA256', 'SHA384', 'SHA512']:
            tk.Radiobutton(hash_frame,
                          text=algo,
                          variable=self.encrypt_hash_var,
                          value=algo,
                          bg=self.colors['bg_medium'],
                          fg=self.colors['text'],
                          selectcolor=self.colors['bg_dark'],
                          activebackground=self.colors['bg_medium'],
                          font=('Segoe UI', 10)).pack(side='left', padx=10)
        
        # Botón cifrar
        btn_encrypt = tk.Button(main,
                               text="🔒 Cifrar con Clave Privada",
                               font=('Segoe UI', 12, 'bold'),
                               bg=self.colors['accent'],
                               fg='#ffffff',
                               activebackground=self.colors['accent_hover'],
                               relief='flat',
                               cursor='hand2',
                               padx=30,
                               pady=12,
                               command=self.encrypt_with_private_key)
        btn_encrypt.pack(pady=15)
        
        # Mensaje cifrado
        cipher_label = tk.Label(main,
                               text="🔐 Mensaje Cifrado/Firmado:",
                               font=('Segoe UI', 11, 'bold'),
                               bg=self.colors['bg_medium'],
                               fg=self.colors['success'])
        cipher_label.pack(anchor='w', pady=(10, 5))
        
        self.encrypted_private_text = scrolledtext.ScrolledText(main,
                                                                height=6,
                                                                font=('Consolas', 9),
                                                                bg=self.colors['bg_dark'],
                                                                fg=self.colors['success'],
                                                                insertbackground=self.colors['text'],
                                                                relief='flat',
                                                                wrap='word')
        self.encrypted_private_text.pack(fill='both', pady=(0, 10))
        
        # Botones
        buttons_frame = tk.Frame(main, bg=self.colors['bg_medium'])
        buttons_frame.pack(fill='x')
        
        tk.Button(buttons_frame,
                 text="💾 Guardar",
                 font=('Segoe UI', 9),
                 bg=self.colors['bg_light'],
                 fg=self.colors['text'],
                 activebackground=self.colors['bg_dark'],
                 relief='flat',
                 cursor='hand2',
                 padx=15,
                 pady=5,
                 command=lambda: self.save_to_file(self.encrypted_private_text, "encrypted_private.txt")).pack(side='left', padx=(0, 10))
        
        tk.Button(buttons_frame,
                 text="📋 Copiar",
                 font=('Segoe UI', 9),
                 bg=self.colors['bg_light'],
                 fg=self.colors['text'],
                 activebackground=self.colors['bg_dark'],
                 relief='flat',
                 cursor='hand2',
                 padx=15,
                 pady=5,
                 command=lambda: self.copy_to_clipboard(self.encrypted_private_text)).pack(side='left', padx=(0, 10))
        
        tk.Button(buttons_frame,
                 text="➡️ Copiar a Verificar",
                 font=('Segoe UI', 9),
                 bg=self.colors['accent'],
                 fg='#ffffff',
                 activebackground=self.colors['accent_hover'],
                 relief='flat',
                 cursor='hand2',
                 padx=15,
                 pady=5,
                 command=self.copy_to_decrypt_public).pack(side='left')
    
    def create_decrypt_public_tab(self):
        """Tab de verificación con clave pública (Punto 1c)"""
        main = tk.Frame(self.tab_decrypt_public, bg=self.colors['bg_medium'])
        main.pack(fill='both', expand=True, padx=30, pady=30)
        
        # Instrucciones
        info_frame = tk.Frame(main, bg=self.colors['bg_light'])
        info_frame.pack(fill='x', pady=(0, 20))
        
        tk.Label(info_frame,
                text="✅ VERIFICACIÓN CON CLAVE PÚBLICA (Punto 1c)",
                font=('Segoe UI', 12, 'bold'),
                bg=self.colors['bg_light'],
                fg=self.colors['accent']).pack(anchor='w', padx=15, pady=(15, 5))
        
        tk.Label(info_frame,
                text="Verifica mensajes cifrados con clave privada usando la clave pública del emisor.\n" +
                     "Si la verificación es exitosa, confirmas la autenticidad del mensaje.",
                font=('Segoe UI', 9),
                bg=self.colors['bg_light'],
                fg=self.colors['text_secondary'],
                wraplength=1000,
                justify='left').pack(anchor='w', padx=15, pady=(0, 15))
        
        # Mensaje original
        msg_label = tk.Label(main,
                            text="📝 Mensaje Original (para verificar):",
                            font=('Segoe UI', 11, 'bold'),
                            bg=self.colors['bg_medium'],
                            fg=self.colors['text'])
        msg_label.pack(anchor='w', pady=(10, 5))
        
        self.decrypt_public_message_text = scrolledtext.ScrolledText(main,
                                                                     height=6,
                                                                     font=('Segoe UI', 10),
                                                                     bg=self.colors['bg_dark'],
                                                                     fg=self.colors['text'],
                                                                     insertbackground=self.colors['text'],
                                                                     relief='flat',
                                                                     wrap='word')
        self.decrypt_public_message_text.pack(fill='both', pady=(0, 15))
        
        # Firma/Cifrado
        cipher_label = tk.Label(main,
                               text="🔐 Firma/Cifrado a Verificar:",
                               font=('Segoe UI', 11, 'bold'),
                               bg=self.colors['bg_medium'],
                               fg=self.colors['text'])
        cipher_label.pack(anchor='w', pady=(10, 5))
        
        self.decrypt_public_cipher_text = scrolledtext.ScrolledText(main,
                                                                    height=4,
                                                                    font=('Consolas', 9),
                                                                    bg=self.colors['bg_dark'],
                                                                    fg=self.colors['text'],
                                                                    insertbackground=self.colors['text'],
                                                                    relief='flat',
                                                                    wrap='word')
        self.decrypt_public_cipher_text.pack(fill='both', pady=(0, 15))
        
        # Algoritmo hash
        hash_frame = tk.Frame(main, bg=self.colors['bg_medium'])
        hash_frame.pack(fill='x', pady=(0, 15))
        
        tk.Label(hash_frame,
                text="Algoritmo Hash usado:",
                font=('Segoe UI', 10, 'bold'),
                bg=self.colors['bg_medium'],
                fg=self.colors['text']).pack(side='left', padx=(0, 10))
        
        self.decrypt_hash_var = tk.StringVar(value="SHA256")
        for algo in ['SHA256', 'SHA384', 'SHA512']:
            tk.Radiobutton(hash_frame,
                          text=algo,
                          variable=self.decrypt_hash_var,
                          value=algo,
                          bg=self.colors['bg_medium'],
                          fg=self.colors['text'],
                          selectcolor=self.colors['bg_dark'],
                          activebackground=self.colors['bg_medium'],
                          font=('Segoe UI', 10)).pack(side='left', padx=10)
        
        # Botón verificar
        btn_verify = tk.Button(main,
                              text="✅ Verificar con Clave Pública",
                              font=('Segoe UI', 12, 'bold'),
                              bg=self.colors['accent'],
                              fg='#ffffff',
                              activebackground=self.colors['accent_hover'],
                              relief='flat',
                              cursor='hand2',
                              padx=30,
                              pady=12,
                              command=self.decrypt_with_public_key)
        btn_verify.pack(pady=15)
        
        # Resultado
        self.verify_result_label = tk.Label(main,
                                           text="",
                                           font=('Segoe UI', 14, 'bold'),
                                           bg=self.colors['bg_medium'])
        self.verify_result_label.pack(pady=20)
    
    # ==================== MÉTODOS DE EVENTOS ====================
    
    def generate_keypair(self):
        """Generar par de claves usando la lógica del backend"""
        try:
            key_size = int(self.key_size_var.get())
            
            # Llamar al backend
            result = self.logic.generate_keypair(key_size)
            
            # Mostrar claves en interfaz
            self.public_key_text.delete('1.0', tk.END)
            self.public_key_text.insert('1.0', result['public_key_pem'])
            
            self.private_key_text.delete('1.0', tk.END)
            self.private_key_text.insert('1.0', result['private_key_pem'])
            
            messagebox.showinfo("Éxito", result['message'])
            
        except ValueError as e:
            messagebox.showerror("Error", str(e))
        except Exception as e:
            messagebox.showerror("Error", f"Error inesperado: {str(e)}")
    
    def encrypt_with_public_key(self):
        """Cifrar con clave pública (Punto 1d)"""
        message = self.encrypt_public_text.get('1.0', tk.END).strip()
        
        try:
            # Llamar al backend
            result = self.logic.encrypt_with_public_key(message)
            
            # Mostrar resultado
            self.encrypted_public_text.delete('1.0', tk.END)
            self.encrypted_public_text.insert('1.0', result['ciphertext_base64'])
            
            messagebox.showinfo("Éxito", 
                               f"{result['message']}\n\n" +
                               f"Método: {result['method']}\n" +
                               f"Longitud original: {result['original_length']} bytes\n" +
                               f"Longitud cifrada: {result['encrypted_length']} bytes")
            
        except ValueError as e:
            messagebox.showwarning("Advertencia", str(e))
        except Exception as e:
            messagebox.showerror("Error", f"Error al cifrar: {str(e)}")
    
    def decrypt_with_private_key(self):
        """Descifrar con clave privada (Punto 1d)"""
        ciphertext = self.decrypt_private_text.get('1.0', tk.END).strip()
        
        try:
            # Llamar al backend
            result = self.logic.decrypt_with_private_key(ciphertext)
            
            # Mostrar resultado
            self.decrypted_private_text.delete('1.0', tk.END)
            self.decrypted_private_text.insert('1.0', result['plaintext'])
            
            messagebox.showinfo("Éxito", 
                               f"{result['message']}\n\n" +
                               f"Método: {result['method']}\n" +
                               f"Longitud: {result['length']} bytes")
            
        except ValueError as e:
            messagebox.showwarning("Advertencia", str(e))
        except Exception as e:
            messagebox.showerror("Error", f"Error al descifrar: {str(e)}")
    
    def encrypt_with_private_key(self):
        """Cifrar con clave privada (Punto 1c - Firma)"""
        message = self.encrypt_private_text.get('1.0', tk.END).strip()
        hash_algorithm = self.encrypt_hash_var.get()
        
        try:
            # Llamar al backend
            result = self.logic.encrypt_with_private_key(message, hash_algorithm)
            
            # Mostrar resultado
            self.encrypted_private_text.delete('1.0', tk.END)
            self.encrypted_private_text.insert('1.0', result['ciphertext_base64'])
            
            messagebox.showinfo("Éxito", 
                               f"{result['message']}\n\n" +
                               f"Método: {result['method']}\n" +
                               f"Algoritmo: {result['hash_algorithm']}\n\n" +
                               f"Nota: {result['note']}")
            
        except ValueError as e:
            messagebox.showwarning("Advertencia", str(e))
        except Exception as e:
            messagebox.showerror("Error", f"Error al cifrar: {str(e)}")
    
    def decrypt_with_public_key(self):
        """Verificar con clave pública (Punto 1c)"""
        original_message = self.decrypt_public_message_text.get('1.0', tk.END).strip()
        ciphertext = self.decrypt_public_cipher_text.get('1.0', tk.END).strip()
        hash_algorithm = self.decrypt_hash_var.get()
        
        try:
            # Llamar al backend
            result = self.logic.decrypt_with_public_key(ciphertext, original_message, hash_algorithm)
            
            if result['valid']:
                self.verify_result_label.config(
                    text=f"✅ VERIFICACIÓN EXITOSA",
                    fg=self.colors['success']
                )
                messagebox.showinfo("Verificación Exitosa", 
                                   f"{result['message']}\n\n" +
                                   f"Método: {result['method']}\n\n" +
                                   f"{result['note']}")
            else:
                self.verify_result_label.config(
                    text="❌ VERIFICACIÓN FALLIDA",
                    fg=self.colors['error']
                )
                messagebox.showerror("Verificación Fallida", 
                                    f"{result['message']}\n\n" +
                                    f"{result['note']}")
            
        except ValueError as e:
            self.verify_result_label.config(
                text="❌ ERROR",
                fg=self.colors['error']
            )
            messagebox.showwarning("Advertencia", str(e))
        except Exception as e:
            messagebox.showerror("Error", f"Error al verificar: {str(e)}")
    
    # ==================== FUNCIONES AUXILIARES ====================
    
    def copy_to_decrypt_private(self):
        """Copiar texto cifrado a la pestaña de descifrado"""
        cipher = self.encrypted_public_text.get('1.0', tk.END).strip()
        if cipher:
            self.decrypt_private_text.delete('1.0', tk.END)
            self.decrypt_private_text.insert('1.0', cipher)
            self.notebook.select(2)  # Ir a pestaña de descifrado
            messagebox.showinfo("Copiado", "Texto cifrado copiado a la pestaña de descifrado")
    
    def copy_to_decrypt_public(self):
        """Copiar texto y firma a la pestaña de verificación"""
        message = self.encrypt_private_text.get('1.0', tk.END).strip()
        cipher = self.encrypted_private_text.get('1.0', tk.END).strip()
        
        if message and cipher:
            self.decrypt_public_message_text.delete('1.0', tk.END)
            self.decrypt_public_message_text.insert('1.0', message)
            
            self.decrypt_public_cipher_text.delete('1.0', tk.END)
            self.decrypt_public_cipher_text.insert('1.0', cipher)
            
            self.notebook.select(4)  # Ir a pestaña de verificación
            messagebox.showinfo("Copiado", "Mensaje y firma copiados a la pestaña de verificación")
    
    def save_public_key(self):
        """Guardar clave pública"""
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
        """Guardar clave privada"""
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
    
    def load_private_key(self):
        """Cargar clave privada"""
        filename = filedialog.askopenfilename(
            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'rb') as f:
                    key_data = f.read()
                    result = self.logic.load_private_key_from_pem(key_data)
                    
                messagebox.showinfo("Éxito", result['message'])
            except ValueError as e:
                messagebox.showerror("Error", str(e))
            except Exception as e:
                messagebox.showerror("Error", f"Error al cargar: {str(e)}")
    
    def load_public_key(self):
        """Cargar clave pública"""
        filename = filedialog.askopenfilename(
            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'rb') as f:
                    key_data = f.read()
                    result = self.logic.load_public_key_from_pem(key_data)
                    
                messagebox.showinfo("Éxito", result['message'])
            except ValueError as e:
                messagebox.showerror("Error", str(e))
            except Exception as e:
                messagebox.showerror("Error", f"Error al cargar: {str(e)}")
    
    def save_to_file(self, text_widget, default_name):
        """Guardar contenido a archivo"""
        content = text_widget.get('1.0', tk.END).strip()
        if not content:
            messagebox.showwarning("Advertencia", "No hay contenido para guardar")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile=default_name
        )
        
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write(content)
                messagebox.showinfo("Éxito", "Archivo guardado")
            except Exception as e:
                messagebox.showerror("Error", f"Error al guardar: {str(e)}")
    
    def load_from_file(self, text_widget):
        """Cargar contenido desde archivo"""
        filename = filedialog.askopenfilename(
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'r') as f:
                    content = f.read()
                    text_widget.delete('1.0', tk.END)
                    text_widget.insert('1.0', content)
                messagebox.showinfo("Éxito", "Archivo cargado")
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
    
    def go_back(self):
        """Regresar al home"""
        self.root.destroy()
    
    # ==================== TABS DE CIFRADO SIMÉTRICO ====================
    
    def create_symmetric_tab(self):
        """Tab de cifrado simétrico (DES, AES, ARC4)"""
        main = tk.Frame(self.tab_symmetric, bg=self.colors['bg_medium'])
        main.pack(fill='both', expand=True, padx=30, pady=30)
        
        # Título
        title = tk.Label(main,
                        text="🔑 CIFRADO SIMÉTRICO",
                        font=('Segoe UI', 14, 'bold'),
                        bg=self.colors['bg_medium'],
                        fg=self.colors['accent'])
        title.pack(pady=(0, 10))
        
        info = tk.Label(main,
                       text="Algoritmos: DES (ECB/CFB), AES (CBC), ARC4 - Como en los ejemplos del profesor",
                       font=('Segoe UI', 9),
                       bg=self.colors['bg_medium'],
                       fg=self.colors['text_secondary'])
        info.pack(pady=(0, 20))
        
        # Selector de algoritmo
        algo_frame = tk.Frame(main, bg=self.colors['bg_light'])
        algo_frame.pack(fill='x', pady=(0, 15))
        
        tk.Label(algo_frame,
                text="Algoritmo:",
                font=('Segoe UI', 10, 'bold'),
                bg=self.colors['bg_light'],
                fg=self.colors['text']).pack(side='left', padx=15, pady=10)
        
        self.sym_algo_var = tk.StringVar(value="AES-CBC")
        algorithms = ['DES-ECB', 'DES-CFB', 'AES-CBC', 'ARC4']
        for algo in algorithms:
            tk.Radiobutton(algo_frame,
                          text=algo,
                          variable=self.sym_algo_var,
                          value=algo,
                          bg=self.colors['bg_light'],
                          fg=self.colors['text'],
                          selectcolor=self.colors['bg_dark'],
                          activebackground=self.colors['bg_light'],
                          font=('Segoe UI', 9),
                          command=self.update_sym_key_hint).pack(side='left', padx=10)
        
        # Clave simétrica
        key_label = tk.Label(main,
                            text="🔑 Clave:",
                            font=('Segoe UI', 10, 'bold'),
                            bg=self.colors['bg_medium'],
                            fg=self.colors['text'])
        key_label.pack(anchor='w', pady=(10, 5))
        
        self.sym_key_entry = tk.Entry(main,
                                      font=('Segoe UI', 10),
                                      bg=self.colors['bg_dark'],
                                      fg=self.colors['text'],
                                      insertbackground=self.colors['text'],
                                      relief='flat')
        self.sym_key_entry.pack(fill='x', pady=(0, 5))
        self.sym_key_entry.insert(0, 'This is a keyabc')  # 16 bytes para AES
        
        self.sym_key_hint = tk.Label(main,
                                     text="AES: 16/24/32 bytes",
                                     font=('Segoe UI', 8),
                                     bg=self.colors['bg_medium'],
                                     fg=self.colors['text_secondary'])
        self.sym_key_hint.pack(anchor='w', pady=(0, 10))
        
        # Texto plano
        plain_label = tk.Label(main,
                              text="📝 Texto Plano:",
                              font=('Segoe UI', 10, 'bold'),
                              bg=self.colors['bg_medium'],
                              fg=self.colors['text'])
        plain_label.pack(anchor='w', pady=(10, 5))
        
        self.sym_plaintext = scrolledtext.ScrolledText(main,
                                                       height=6,
                                                       font=('Segoe UI', 10),
                                                       bg=self.colors['bg_dark'],
                                                       fg=self.colors['text'],
                                                       insertbackground=self.colors['text'],
                                                       relief='flat')
        self.sym_plaintext.pack(fill='x', pady=(0, 10))
        self.sym_plaintext.insert('1.0', 'Text Plain Test1')
        
        # Botones de cifrado/descifrado
        btn_frame = tk.Frame(main, bg=self.colors['bg_medium'])
        btn_frame.pack(fill='x', pady=10)
        
        tk.Button(btn_frame,
                 text="🔐 Cifrar",
                 font=('Segoe UI', 10, 'bold'),
                 bg=self.colors['accent'],
                 fg='#ffffff',
                 activebackground=self.colors['accent_hover'],
                 relief='flat',
                 cursor='hand2',
                 padx=20,
                 pady=8,
                 command=self.encrypt_symmetric).pack(side='left', padx=(0, 10))
        
        tk.Button(btn_frame,
                 text="🔓 Descifrar",
                 font=('Segoe UI', 10, 'bold'),
                 bg=self.colors['bg_light'],
                 fg=self.colors['text'],
                 activebackground=self.colors['bg_dark'],
                 relief='flat',
                 cursor='hand2',
                 padx=20,
                 pady=8,
                 command=self.decrypt_symmetric).pack(side='left')
        
        # Resultado
        result_label = tk.Label(main,
                               text="📤 Resultado:",
                               font=('Segoe UI', 10, 'bold'),
                               bg=self.colors['bg_medium'],
                               fg=self.colors['success'])
        result_label.pack(anchor='w', pady=(15, 5))
        
        self.sym_result = scrolledtext.ScrolledText(main,
                                                    height=6,
                                                    font=('Consolas', 9),
                                                    bg=self.colors['bg_dark'],
                                                    fg=self.colors['success'],
                                                    insertbackground=self.colors['text'],
                                                    relief='flat')
        self.sym_result.pack(fill='both', expand=True, pady=(0, 10))
        
        # IV (para modos que lo requieren)
        iv_label = tk.Label(main,
                           text="🔢 IV (para DES-CFB/AES-CBC):",
                           font=('Segoe UI', 9, 'bold'),
                           bg=self.colors['bg_medium'],
                           fg=self.colors['text_secondary'])
        iv_label.pack(anchor='w', pady=(5, 5))
        
        self.sym_iv_entry = tk.Entry(main,
                                     font=('Consolas', 9),
                                     bg=self.colors['bg_dark'],
                                     fg=self.colors['text_secondary'],
                                     insertbackground=self.colors['text'],
                                     relief='flat')
        self.sym_iv_entry.pack(fill='x', pady=(0, 5))
        
        tk.Label(main,
                text="Se generará automáticamente al cifrar. Copiar para descifrar.",
                font=('Segoe UI', 8, 'italic'),
                bg=self.colors['bg_medium'],
                fg=self.colors['text_secondary']).pack(anchor='w')
    
    def create_hybrid_tab(self):
        """Tab de cifrado híbrido (RSA + AES)"""
        main = tk.Frame(self.tab_hybrid, bg=self.colors['bg_medium'])
        main.pack(fill='both', expand=True, padx=30, pady=30)
        
        # Título
        title = tk.Label(main,
                        text="🔐🔑 CIFRADO HÍBRIDO (RSA + AES)",
                        font=('Segoe UI', 14, 'bold'),
                        bg=self.colors['bg_medium'],
                        fg=self.colors['accent'])
        title.pack(pady=(0, 10))
        
        info_frame = tk.Frame(main, bg=self.colors['bg_light'])
        info_frame.pack(fill='x', pady=(0, 20))
        
        tk.Label(info_frame,
                text="Como en el ejemplo del profesor: RSA-OAEP cifra clave de sesión AES, AES-GCM cifra los datos",
                font=('Segoe UI', 9),
                bg=self.colors['bg_light'],
                fg=self.colors['text_secondary'],
                wraplength=1000,
                justify='left').pack(padx=15, pady=10)
        
        # Texto a cifrar
        plain_label = tk.Label(main,
                              text="📝 Mensaje a Cifrar:",
                              font=('Segoe UI', 10, 'bold'),
                              bg=self.colors['bg_medium'],
                              fg=self.colors['text'])
        plain_label.pack(anchor='w', pady=(10, 5))
        
        self.hybrid_plaintext = scrolledtext.ScrolledText(main,
                                                         height=8,
                                                         font=('Segoe UI', 10),
                                                         bg=self.colors['bg_dark'],
                                                         fg=self.colors['text'],
                                                         insertbackground=self.colors['text'],
                                                         relief='flat')
        self.hybrid_plaintext.pack(fill='x', pady=(0, 10))
        self.hybrid_plaintext.insert('1.0', 'Conozco alinenígenas')
        
        # Botones
        btn_frame = tk.Frame(main, bg=self.colors['bg_medium'])
        btn_frame.pack(fill='x', pady=10)
        
        tk.Button(btn_frame,
                 text="🔐 Cifrar Híbrido",
                 font=('Segoe UI', 11, 'bold'),
                 bg=self.colors['accent'],
                 fg='#ffffff',
                 activebackground=self.colors['accent_hover'],
                 relief='flat',
                 cursor='hand2',
                 padx=25,
                 pady=10,
                 command=self.encrypt_hybrid).pack(side='left', padx=(0, 10))
        
        tk.Button(btn_frame,
                 text="🔓 Descifrar Híbrido",
                 font=('Segoe UI', 11, 'bold'),
                 bg=self.colors['bg_light'],
                 fg=self.colors['text'],
                 activebackground=self.colors['bg_dark'],
                 relief='flat',
                 cursor='hand2',
                 padx=25,
                 pady=10,
                 command=self.decrypt_hybrid).pack(side='left')
        
        # Resultados
        result_label = tk.Label(main,
                               text="📤 Datos Cifrados:",
                               font=('Segoe UI', 10, 'bold'),
                               bg=self.colors['bg_medium'],
                               fg=self.colors['success'])
        result_label.pack(anchor='w', pady=(15, 5))
        
        self.hybrid_result = scrolledtext.ScrolledText(main,
                                                       height=12,
                                                       font=('Consolas', 8),
                                                       bg=self.colors['bg_dark'],
                                                       fg=self.colors['success'],
                                                       insertbackground=self.colors['text'],
                                                       relief='flat')
        self.hybrid_result.pack(fill='both', expand=True)
    
    # ==================== MÉTODOS DE CIFRADO SIMÉTRICO ====================
    
    def update_sym_key_hint(self):
        """Actualizar hint de longitud de clave según algoritmo"""
        algo = self.sym_algo_var.get()
        hints = {
            'DES-ECB': 'DES: Exactamente 8 bytes',
            'DES-CFB': 'DES: Exactamente 8 bytes',
            'AES-CBC': 'AES: 16/24/32 bytes (AES-128/192/256)',
            'ARC4': 'RC4: 5-256 bytes (longitud variable)'
        }
        self.sym_key_hint.config(text=hints.get(algo, ''))
        
        # Actualizar clave de ejemplo
        examples = {
            'DES-ECB': '01234567',
            'DES-CFB': '01234567',
            'AES-CBC': 'This is a keyabc',
            'ARC4': '01234567'
        }
        self.sym_key_entry.delete(0, tk.END)
        self.sym_key_entry.insert(0, examples.get(algo, ''))
    
    def encrypt_symmetric(self):
        """Cifrar con algoritmo simétrico seleccionado"""
        algo = self.sym_algo_var.get()
        key = self.sym_key_entry.get()
        plaintext = self.sym_plaintext.get('1.0', tk.END).strip()
        
        if not key or not plaintext:
            messagebox.showwarning("Advertencia", "Ingresa clave y texto plano")
            return
        
        try:
            result = None
            
            if algo == 'DES-ECB':
                result = self.logic.encrypt_des_ecb(plaintext, key)
                output = f"🔐 Cifrado: {result['ciphertext_base64']}\n"
                output += f"Hex: {result['ciphertext_hex']}\n"
                output += f"\n⚠️ {result['warning']}"
                
            elif algo == 'DES-CFB':
                result = self.logic.encrypt_des_cfb(plaintext, key)
                output = f"🔐 Cifrado: {result['ciphertext_base64']}\n"
                output += f"IV (base64): {result['iv_base64']}\n"
                output += f"IV (hex): {result['iv_hex']}"
                self.sym_iv_entry.delete(0, tk.END)
                self.sym_iv_entry.insert(0, result['iv_base64'])
                
            elif algo == 'AES-CBC':
                result = self.logic.encrypt_aes_cbc(plaintext, key)
                output = f"🔐 Cifrado: {result['ciphertext_base64']}\n"
                output += f"IV (base64): {result['iv_base64']}\n"
                output += f"IV (hex): {result['iv_hex']}\n"
                output += f"Método: {result['method']}"
                self.sym_iv_entry.delete(0, tk.END)
                self.sym_iv_entry.insert(0, result['iv_base64'])
                
            elif algo == 'ARC4':
                result = self.logic.encrypt_arc4(plaintext, key)
                output = f"🔐 Cifrado: {result['ciphertext_base64']}\n"
                output += f"Hex: {result['ciphertext_hex']}\n"
                output += f"\n⚠️ {result['warning']}"
            
            self.sym_result.delete('1.0', tk.END)
            self.sym_result.insert('1.0', output)
            messagebox.showinfo("Éxito", f"Cifrado {algo} exitoso")
            
        except ValueError as e:
            messagebox.showerror("Error", str(e))
    
    def decrypt_symmetric(self):
        """Descifrar con algoritmo simétrico seleccionado"""
        algo = self.sym_algo_var.get()
        key = self.sym_key_entry.get()
        ciphertext = self.sym_result.get('1.0', tk.END).strip()
        
        if not key or not ciphertext:
            messagebox.showwarning("Advertencia", "Ingresa clave y texto cifrado")
            return
        
        # Extraer solo el base64 del resultado
        lines = ciphertext.split('\n')
        cipher_b64 = lines[0].replace('🔐 Cifrado: ', '').strip()
        
        try:
            result = None
            
            if algo == 'DES-ECB':
                result = self.logic.decrypt_des_ecb(cipher_b64, key)
                
            elif algo == 'DES-CFB':
                iv_b64 = self.sym_iv_entry.get()
                if not iv_b64:
                    messagebox.showwarning("Advertencia", "Ingresa el IV para descifrar")
                    return
                result = self.logic.decrypt_des_cfb(cipher_b64, key, iv_b64)
                
            elif algo == 'AES-CBC':
                iv_b64 = self.sym_iv_entry.get()
                if not iv_b64:
                    messagebox.showwarning("Advertencia", "Ingresa el IV para descifrar")
                    return
                result = self.logic.decrypt_aes_cbc(cipher_b64, key, iv_b64)
                
            elif algo == 'ARC4':
                result = self.logic.decrypt_arc4(cipher_b64, key)
            
            output = f"✅ Texto Descifrado:\n{result['plaintext']}\n\n"
            output += f"Método: {result['method']}"
            
            self.sym_plaintext.delete('1.0', tk.END)
            self.sym_plaintext.insert('1.0', result['plaintext'])
            
            messagebox.showinfo("Éxito", f"Descifrado {algo} exitoso")
            
        except ValueError as e:
            messagebox.showerror("Error", str(e))
    
    def encrypt_hybrid(self):
        """Cifrar con método híbrido (RSA + AES)"""
        plaintext = self.hybrid_plaintext.get('1.0', tk.END).strip()
        
        if not plaintext:
            messagebox.showwarning("Advertencia", "Ingresa texto a cifrar")
            return
        
        try:
            result = self.logic.encrypt_hybrid(plaintext)
            
            output = "=== CIFRADO HÍBRIDO (RSA + AES) ===\n\n"
            output += f"1️⃣ Clave de Sesión AES cifrada con RSA:\n{result['encrypted_session_key_base64']}\n\n"
            output += f"2️⃣ Datos cifrados con AES-GCM:\n{result['ciphertext_base64']}\n\n"
            output += f"3️⃣ Nonce:\n{result['nonce_base64']}\n\n"
            output += f"4️⃣ Tag de Autenticación:\n{result['tag_base64']}\n\n"
            output += f"Método: {result['method']}"
            
            self.hybrid_result.delete('1.0', tk.END)
            self.hybrid_result.insert('1.0', output)
            
            messagebox.showinfo("Éxito", "Cifrado híbrido exitoso\n\n" + result['note'])
            
        except ValueError as e:
            messagebox.showerror("Error", str(e))
    
    def decrypt_hybrid(self):
        """Descifrar con método híbrido (RSA + AES)"""
        result_text = self.hybrid_result.get('1.0', tk.END).strip()
        
        if not result_text or 'CIFRADO HÍBRIDO' not in result_text:
            messagebox.showwarning("Advertencia", "Primero cifra un mensaje híbrido")
            return
        
        try:
            # Parsear el resultado
            lines = result_text.split('\n')
            encrypted_key = lines[2].strip()
            ciphertext = lines[5].strip()
            nonce = lines[8].strip()
            tag = lines[11].strip()
            
            result = self.logic.decrypt_hybrid(encrypted_key, ciphertext, nonce, tag)
            
            self.hybrid_plaintext.delete('1.0', tk.END)
            self.hybrid_plaintext.insert('1.0', result['plaintext'])
            
            messagebox.showinfo("Éxito", f"Descifrado híbrido exitoso\n\n{result['message']}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Error en descifrado híbrido: {str(e)}")


def main():
    """Función principal standalone"""
    root = tk.Tk()
    app = EncryptionUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
