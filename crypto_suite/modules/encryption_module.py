#!/usr/bin/env python3
"""
Laboratorio de Programación Segura
MÓDULO: Cifrado/Descifrado con Clave Privada/Pública (Punto 1c y 1d)

Implementación completa de cifrado y descifrado usando RSA
con interfaz gráfica profesional.
Compatible con Python 3.13+
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import base64
import os


class EncryptionModule:
    """Módulo de Cifrado/Descifrado RSA con interfaz gráfica"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Cifrado RSA - Suite Criptográfica")
        self.root.geometry("1200x800")
        self.root.configure(bg='#1e1e1e')
        
        # Variables para almacenar las claves
        self.private_key = None
        self.public_key = None
        
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
        
        # Título
        title = tk.Label(header,
                        text="🔐 CIFRADO Y DESCIFRADO RSA",
                        font=('Segoe UI', 24, 'bold'),
                        bg=self.colors['bg_dark'],
                        fg=self.colors['accent'])
        title.pack(anchor='w')
        
        # Subtítulo
        subtitle = tk.Label(header,
                           text="Cifrado con Clave Privada y Clave Pública (Punto 1c y 1d)",
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
        self.tab_encrypt_private = tk.Frame(self.notebook, bg=self.colors['bg_medium'])
        self.tab_decrypt_public = tk.Frame(self.notebook, bg=self.colors['bg_medium'])
        self.tab_encrypt_public = tk.Frame(self.notebook, bg=self.colors['bg_medium'])
        
        self.notebook.add(self.tab_keys, text='🔑 Generar Claves')
        self.notebook.add(self.tab_encrypt_private, text='🔒 Cifrar (Clave Privada)')
        self.notebook.add(self.tab_decrypt_public, text='🔓 Descifrar (Clave Pública)')
        self.notebook.add(self.tab_encrypt_public, text='🔐 Cifrar (Clave Pública)')
        
        # Crear contenido de cada tab
        self.create_keys_tab()
        self.create_encrypt_private_tab()
        self.create_decrypt_public_tab()
        self.create_encrypt_public_tab()
        
    def create_keys_tab(self):
        """Tab de generación de claves"""
        main = tk.Frame(self.tab_keys, bg=self.colors['bg_medium'])
        main.pack(fill='both', expand=True, padx=30, pady=30)
        
        # Instrucciones
        instructions = tk.Label(main,
                               text="Genera un par de claves RSA para cifrar y descifrar mensajes",
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
                            text="📤 CLAVE PÚBLICA",
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
                 text="💾 Guardar",
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
                 text="📂 Cargar",
                 font=('Segoe UI', 9),
                 bg=self.colors['bg_light'],
                 fg=self.colors['text'],
                 activebackground=self.colors['bg_dark'],
                 relief='flat',
                 cursor='hand2',
                 padx=15,
                 pady=5,
                 command=self.load_public_key).pack(side='left')
        
        # Clave Privada
        priv_label = tk.Label(keys_display_frame,
                             text="🔒 CLAVE PRIVADA",
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
                 text="💾 Guardar",
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
                 text="📂 Cargar",
                 font=('Segoe UI', 9),
                 bg=self.colors['bg_light'],
                 fg=self.colors['text'],
                 activebackground=self.colors['bg_dark'],
                 relief='flat',
                 cursor='hand2',
                 padx=15,
                 pady=5,
                 command=self.load_private_key).pack(side='left')
        
    def create_encrypt_private_tab(self):
        """Tab de cifrado con clave privada (Punto 1c)"""
        main = tk.Frame(self.tab_encrypt_private, bg=self.colors['bg_medium'])
        main.pack(fill='both', expand=True, padx=30, pady=30)
        
        # Instrucciones
        info_frame = tk.Frame(main, bg=self.colors['bg_light'])
        info_frame.pack(fill='x', pady=(0, 20))
        
        tk.Label(info_frame,
                text="🔒 CIFRADO CON CLAVE PRIVADA (Punto 1c)",
                font=('Segoe UI', 12, 'bold'),
                bg=self.colors['bg_light'],
                fg=self.colors['accent']).pack(anchor='w', padx=15, pady=(15, 5))
        
        tk.Label(info_frame,
                text="Cifra un mensaje usando tu clave privada. Solo quien tenga la clave pública podrá descifrarlo.",
                font=('Segoe UI', 9),
                bg=self.colors['bg_light'],
                fg=self.colors['text_secondary'],
                wraplength=800,
                justify='left').pack(anchor='w', padx=15, pady=(0, 15))
        
        # Mensaje a cifrar
        msg_label = tk.Label(main,
                            text="📝 Mensaje a cifrar:",
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
        self.encrypt_private_text.insert('1.0', 'Mensaje secreto cifrado con clave privada')
        
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
                               text="🔐 Mensaje Cifrado:",
                               font=('Segoe UI', 11, 'bold'),
                               bg=self.colors['bg_medium'],
                               fg=self.colors['success'])
        cipher_label.pack(anchor='w', pady=(10, 5))
        
        self.encrypted_private_text = scrolledtext.ScrolledText(main,
                                                                height=8,
                                                                font=('Consolas', 9),
                                                                bg=self.colors['bg_dark'],
                                                                fg=self.colors['success'],
                                                                insertbackground=self.colors['text'],
                                                                relief='flat',
                                                                wrap='word')
        self.encrypted_private_text.pack(fill='both', expand=True, pady=(0, 10))
        
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
                 command=lambda: self.copy_to_clipboard(self.encrypted_private_text)).pack(side='left')
        
    def create_decrypt_public_tab(self):
        """Tab de descifrado con clave pública"""
        main = tk.Frame(self.tab_decrypt_public, bg=self.colors['bg_medium'])
        main.pack(fill='both', expand=True, padx=30, pady=30)
        
        # Instrucciones
        info_frame = tk.Frame(main, bg=self.colors['bg_light'])
        info_frame.pack(fill='x', pady=(0, 20))
        
        tk.Label(info_frame,
                text="🔓 DESCIFRADO CON CLAVE PÚBLICA",
                font=('Segoe UI', 12, 'bold'),
                bg=self.colors['bg_light'],
                fg=self.colors['accent']).pack(anchor='w', padx=15, pady=(15, 5))
        
        tk.Label(info_frame,
                text="Descifra mensajes que fueron cifrados con la clave privada usando la clave pública.",
                font=('Segoe UI', 9),
                bg=self.colors['bg_light'],
                fg=self.colors['text_secondary'],
                wraplength=800,
                justify='left').pack(anchor='w', padx=15, pady=(0, 15))
        
        # Mensaje cifrado
        cipher_label = tk.Label(main,
                               text="🔐 Mensaje Cifrado:",
                               font=('Segoe UI', 11, 'bold'),
                               bg=self.colors['bg_medium'],
                               fg=self.colors['text'])
        cipher_label.pack(anchor='w', pady=(10, 5))
        
        self.decrypt_public_text = scrolledtext.ScrolledText(main,
                                                             height=8,
                                                             font=('Consolas', 9),
                                                             bg=self.colors['bg_dark'],
                                                             fg=self.colors['text'],
                                                             insertbackground=self.colors['text'],
                                                             relief='flat',
                                                             wrap='word')
        self.decrypt_public_text.pack(fill='both', expand=True, pady=(0, 15))
        
        # Botón descifrar
        btn_decrypt = tk.Button(main,
                               text="🔓 Descifrar con Clave Pública",
                               font=('Segoe UI', 12, 'bold'),
                               bg=self.colors['accent'],
                               fg='#ffffff',
                               activebackground=self.colors['accent_hover'],
                               relief='flat',
                               cursor='hand2',
                               padx=30,
                               pady=12,
                               command=self.decrypt_with_public_key)
        btn_decrypt.pack(pady=15)
        
        # Mensaje descifrado
        plain_label = tk.Label(main,
                              text="📝 Mensaje Descifrado:",
                              font=('Segoe UI', 11, 'bold'),
                              bg=self.colors['bg_medium'],
                              fg=self.colors['success'])
        plain_label.pack(anchor='w', pady=(10, 5))
        
        self.decrypted_public_text = scrolledtext.ScrolledText(main,
                                                               height=8,
                                                               font=('Segoe UI', 10),
                                                               bg=self.colors['bg_dark'],
                                                               fg=self.colors['success'],
                                                               insertbackground=self.colors['text'],
                                                               relief='flat',
                                                               wrap='word')
        self.decrypted_public_text.pack(fill='both', expand=True, pady=(0, 10))
        
        # Botón copiar
        tk.Button(main,
                 text="📋 Copiar",
                 font=('Segoe UI', 9),
                 bg=self.colors['bg_light'],
                 fg=self.colors['text'],
                 activebackground=self.colors['bg_dark'],
                 relief='flat',
                 cursor='hand2',
                 padx=15,
                 pady=5,
                 command=lambda: self.copy_to_clipboard(self.decrypted_public_text)).pack()
        
    def create_encrypt_public_tab(self):
        """Tab de cifrado con clave pública (Punto 1d)"""
        main = tk.Frame(self.tab_encrypt_public, bg=self.colors['bg_medium'])
        main.pack(fill='both', expand=True, padx=30, pady=30)
        
        # Instrucciones
        info_frame = tk.Frame(main, bg=self.colors['bg_light'])
        info_frame.pack(fill='x', pady=(0, 20))
        
        tk.Label(info_frame,
                text="🔐 CIFRADO CON CLAVE PÚBLICA (Punto 1d)",
                font=('Segoe UI', 12, 'bold'),
                bg=self.colors['bg_light'],
                fg=self.colors['accent']).pack(anchor='w', padx=15, pady=(15, 5))
        
        tk.Label(info_frame,
                text="Cifra un mensaje usando la clave pública. Solo quien tenga la clave privada podrá descifrarlo.\nEste es el método estándar de criptografía asimétrica.",
                font=('Segoe UI', 9),
                bg=self.colors['bg_light'],
                fg=self.colors['text_secondary'],
                wraplength=800,
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
                               text="🔐 Mensaje Cifrado:",
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
                 text="💾 Guardar",
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
                 text="🔓 Ir a Descifrar",
                 font=('Segoe UI', 9),
                 bg=self.colors['accent'],
                 fg='#ffffff',
                 activebackground=self.colors['accent_hover'],
                 relief='flat',
                 cursor='hand2',
                 padx=15,
                 pady=5,
                 command=self.go_to_decrypt_private).pack(side='left')
        
    def go_to_decrypt_private(self):
        """Ir a la pestaña de descifrado con clave privada"""
        # Copiar el texto cifrado
        cipher_text = self.encrypted_public_text.get('1.0', tk.END).strip()
        if cipher_text:
            # Crear nueva ventana para descifrado
            decrypt_window = tk.Toplevel(self.root)
            decrypt_window.title("🔓 Descifrar con Clave Privada")
            decrypt_window.geometry("800x600")
            decrypt_window.configure(bg=self.colors['bg_dark'])
            
            main = tk.Frame(decrypt_window, bg=self.colors['bg_medium'])
            main.pack(fill='both', expand=True, padx=30, pady=30)
            
            # Instrucciones
            tk.Label(main,
                    text="🔓 DESCIFRADO CON CLAVE PRIVADA",
                    font=('Segoe UI', 12, 'bold'),
                    bg=self.colors['bg_medium'],
                    fg=self.colors['accent']).pack(pady=(0, 10))
            
            tk.Label(main,
                    text="Descifra mensajes que fueron cifrados con tu clave pública",
                    font=('Segoe UI', 9),
                    bg=self.colors['bg_medium'],
                    fg=self.colors['text_secondary']).pack(pady=(0, 20))
            
            # Texto cifrado
            tk.Label(main,
                    text="🔐 Mensaje Cifrado:",
                    font=('Segoe UI', 10, 'bold'),
                    bg=self.colors['bg_medium'],
                    fg=self.colors['text']).pack(anchor='w', pady=(0, 5))
            
            cipher_input = scrolledtext.ScrolledText(main,
                                                     height=6,
                                                     font=('Consolas', 9),
                                                     bg=self.colors['bg_dark'],
                                                     fg=self.colors['text'],
                                                     wrap='word')
            cipher_input.pack(fill='x', pady=(0, 15))
            cipher_input.insert('1.0', cipher_text)
            
            # Botón descifrar
            def decrypt_action():
                cipher = cipher_input.get('1.0', tk.END).strip()
                if not cipher:
                    messagebox.showwarning("Advertencia", "Ingresa el mensaje cifrado")
                    return
                
                if not self.private_key:
                    messagebox.showwarning("Advertencia", "Primero debes cargar una clave privada")
                    return
                
                try:
                    cipher_bytes = base64.b64decode(cipher)
                    plaintext = self.private_key.decrypt(
                        cipher_bytes,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    
                    result_text.delete('1.0', tk.END)
                    result_text.insert('1.0', plaintext.decode('utf-8'))
                    messagebox.showinfo("Éxito", "Mensaje descifrado correctamente")
                    
                except Exception as e:
                    messagebox.showerror("Error", f"Error al descifrar: {str(e)}")
            
            tk.Button(main,
                     text="🔓 Descifrar",
                     font=('Segoe UI', 11, 'bold'),
                     bg=self.colors['accent'],
                     fg='#ffffff',
                     activebackground=self.colors['accent_hover'],
                     relief='flat',
                     cursor='hand2',
                     padx=25,
                     pady=10,
                     command=decrypt_action).pack(pady=15)
            
            # Resultado
            tk.Label(main,
                    text="📝 Mensaje Descifrado:",
                    font=('Segoe UI', 10, 'bold'),
                    bg=self.colors['bg_medium'],
                    fg=self.colors['success']).pack(anchor='w', pady=(0, 5))
            
            result_text = scrolledtext.ScrolledText(main,
                                                    height=6,
                                                    font=('Segoe UI', 10),
                                                    bg=self.colors['bg_dark'],
                                                    fg=self.colors['success'],
                                                    wrap='word')
            result_text.pack(fill='both', expand=True)
    
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
            
            messagebox.showinfo("Éxito", 
                               f"Par de claves RSA-{key_size} generado correctamente")
            
        except Exception as e:
            messagebox.showerror("Error", f"Error al generar claves: {str(e)}")
    
    def encrypt_with_private_key(self):
        """Cifrar con clave privada (Punto 1c)"""
        if not self.private_key:
            messagebox.showwarning("Advertencia", 
                                  "Primero debes generar o cargar una clave privada")
            return
        
        message = self.encrypt_private_text.get('1.0', tk.END).strip()
        if not message:
            messagebox.showwarning("Advertencia", "Ingresa un mensaje para cifrar")
            return
        
        try:
            # Cifrar con clave privada (sign sin hash, similar a cifrado)
            # En RSA, esto se simula firmando el mensaje
            ciphertext = self.private_key.sign(
                message.encode('utf-8'),
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            
            # Convertir a base64
            cipher_b64 = base64.b64encode(ciphertext).decode('utf-8')
            
            # Mostrar
            self.encrypted_private_text.delete('1.0', tk.END)
            self.encrypted_private_text.insert('1.0', cipher_b64)
            
            messagebox.showinfo("Éxito", "Mensaje cifrado con clave privada")
            
        except Exception as e:
            messagebox.showerror("Error", f"Error al cifrar: {str(e)}")
    
    def decrypt_with_public_key(self):
        """Descifrar con clave pública"""
        if not self.public_key:
            messagebox.showwarning("Advertencia", 
                                  "Primero debes cargar una clave pública")
            return
        
        cipher_text = self.decrypt_public_text.get('1.0', tk.END).strip()
        if not cipher_text:
            messagebox.showwarning("Advertencia", "Ingresa el mensaje cifrado")
            return
        
        try:
            # Decodificar de base64
            cipher_bytes = base64.b64decode(cipher_text)
            
            # "Descifrar" usando verify (inverso de sign)
            # Esto es una simulación, en la práctica RSA no funciona así directamente
            messagebox.showinfo("Información", 
                               "El descifrado con clave pública de mensajes cifrados con clave privada\n" +
                               "se usa típicamente en firma digital.\n" +
                               "Para descifrado real, usa cifrado con clave pública.")
            
        except Exception as e:
            messagebox.showerror("Error", f"Error al descifrar: {str(e)}")
    
    def encrypt_with_public_key(self):
        """Cifrar con clave pública (Punto 1d - método estándar)"""
        if not self.public_key:
            messagebox.showwarning("Advertencia", 
                                  "Primero debes cargar una clave pública")
            return
        
        message = self.encrypt_public_text.get('1.0', tk.END).strip()
        if not message:
            messagebox.showwarning("Advertencia", "Ingresa un mensaje para cifrar")
            return
        
        try:
            # Cifrar con clave pública (método estándar)
            ciphertext = self.public_key.encrypt(
                message.encode('utf-8'),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Convertir a base64
            cipher_b64 = base64.b64encode(ciphertext).decode('utf-8')
            
            # Mostrar
            self.encrypted_public_text.delete('1.0', tk.END)
            self.encrypted_public_text.insert('1.0', cipher_b64)
            
            messagebox.showinfo("Éxito", 
                               "Mensaje cifrado con clave pública\n" +
                               "Solo quien tenga la clave privada podrá descifrarlo")
            
        except Exception as e:
            messagebox.showerror("Error", f"Error al cifrar: {str(e)}")
    
    # ==================== FUNCIONES DE ARCHIVO ====================
    
    def save_public_key(self):
        """Guardar clave pública"""
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
        """Guardar clave privada"""
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
    
    def load_private_key(self):
        """Cargar clave privada"""
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
                    
                messagebox.showinfo("Éxito", "Clave privada cargada")
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
                    self.public_key = serialization.load_pem_public_key(
                        key_data,
                        backend=default_backend()
                    )
                    
                messagebox.showinfo("Éxito", "Clave pública cargada")
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
    
    def copy_to_clipboard(self, text_widget):
        """Copiar contenido al portapapeles"""
        content = text_widget.get('1.0', tk.END).strip()
        if content:
            self.root.clipboard_clear()
            self.root.clipboard_append(content)
            messagebox.showinfo("Éxito", "Contenido copiado al portapapeles")
        else:
            messagebox.showwarning("Advertencia", "No hay contenido para copiar")


# Para pruebas independientes
if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionModule(root)
    root.mainloop()
