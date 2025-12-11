#!/usr/bin/env python3
"""
Laboratorio de Programación Segura
HOME PRINCIPAL - Suite Criptográfica Modular

Punto de entrada centralizado para acceder a todas las funcionalidades
del laboratorio de criptografía.
"""

import tkinter as tk
from tkinter import ttk
import sys
import os

# Agregar el directorio padre al path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


class CryptoSuiteHome:
    """Pantalla principal de la Suite Criptográfica"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Suite Criptográfica - Laboratorio de Seguridad")
        self.root.geometry("1000x700")
        self.root.configure(bg='#0a0a0a')
        
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
        
        # Colores del tema
        self.colors = {
            'bg_dark': '#0a0a0a',
            'bg_medium': '#1a1a1a',
            'bg_card': '#252525',
            'bg_card_hover': '#2f2f2f',
            'accent_blue': '#0078d4',
            'accent_cyan': '#00d4ff',
            'accent_green': '#00ff88',
            'accent_purple': '#b042ff',
            'accent_orange': '#ff6b35',
            'text_primary': '#ffffff',
            'text_secondary': '#b0b0b0'
        }
        
        # Estilo del frame principal
        style.configure('TFrame', background=self.colors['bg_dark'])
        style.configure('Card.TFrame', background=self.colors['bg_card'])
        
        # Estilos de etiquetas
        style.configure('TLabel',
                       background=self.colors['bg_dark'],
                       foreground=self.colors['text_primary'],
                       font=('Segoe UI', 10))
        
    def create_interface(self):
        """Crear la interfaz principal"""
        # Header
        self.create_header()
        
        # Cards de módulos
        self.create_modules_grid()
        
        # Footer
        self.create_footer()
        
    def create_header(self):
        """Crear encabezado con título y descripción"""
        header_frame = tk.Frame(self.root, bg=self.colors['bg_dark'])
        header_frame.pack(fill='x', padx=40, pady=(40, 20))
        
        # Título principal con efecto
        title_frame = tk.Frame(header_frame, bg=self.colors['bg_dark'])
        title_frame.pack()
        
        title = tk.Label(title_frame,
                        text="🔐 SUITE CRIPTOGRÁFICA",
                        font=('Segoe UI', 32, 'bold'),
                        bg=self.colors['bg_dark'],
                        fg=self.colors['accent_cyan'])
        title.pack()
        
        subtitle = tk.Label(title_frame,
                           text="Laboratorio de Programación Segura",
                           font=('Segoe UI', 14),
                           bg=self.colors['bg_dark'],
                           fg=self.colors['text_secondary'])
        subtitle.pack(pady=(5, 0))
        
        # Línea decorativa
        separator = tk.Canvas(header_frame, height=2, bg=self.colors['bg_dark'],
                             highlightthickness=0)
        separator.pack(fill='x', pady=(20, 0))
        separator.create_line(0, 1, 1000, 1, fill=self.colors['accent_cyan'], width=2)
        
    def create_modules_grid(self):
        """Crear grid de tarjetas de módulos"""
        # Frame contenedor con scroll
        main_container = tk.Frame(self.root, bg=self.colors['bg_dark'])
        main_container.pack(fill='both', expand=True, padx=40, pady=20)
        
        # Canvas para scroll
        canvas = tk.Canvas(main_container, bg=self.colors['bg_dark'],
                          highlightthickness=0)
        scrollbar = ttk.Scrollbar(main_container, orient='vertical',
                                 command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg=self.colors['bg_dark'])
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor='nw')
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Definir módulos del laboratorio
        modules = [
            {
                'id': '1a',
                'title': 'Message Digest',
                'icon': '📝',
                'description': 'Genera resúmenes digitales usando MD5, SHA-1, SHA-256, SHA-384 y SHA-512',
                'color': self.colors['accent_blue'],
                'status': 'Implementado'
            },
            {
                'id': '1b',
                'title': 'Firma Digital',
                'icon': '✍️',
                'description': 'Firma y verifica documentos usando algoritmos de firma digital (RSA, DSA)',
                'color': self.colors['accent_green'],
                'status': 'Implementado'
            },
            {
                'id': '1c-1d',
                'title': 'Cifrado RSA',
                'icon': '🔐',
                'description': 'Cifrado y descifrado con clave privada y clave pública usando RSA (Punto 1c y 1d)',
                'color': self.colors['accent_orange'],
                'status': 'Implementado'
            },
            {
                'id': '1e',
                'title': 'Curvas Elípticas',
                'icon': '📈',
                'description': 'Firma y verificación usando criptografía de curvas elípticas (ECC)',
                'color': self.colors['accent_cyan'],
                'status': 'Próximamente'
            },
            {
                'id': '2',
                'title': 'SQL Injection',
                'icon': '💉',
                'description': 'Demuestra vulnerabilidades SQLi y técnicas de prevención',
                'color': '#ff4444',
                'status': 'Próximamente'
            }
        ]
        
        # Crear cards en grid 2x3
        row = 0
        col = 0
        for module in modules:
            card = self.create_module_card(scrollable_frame, module)
            card.grid(row=row, column=col, padx=15, pady=15, sticky='nsew')
            
            col += 1
            if col > 1:  # 2 columnas
                col = 0
                row += 1
        
        # Configurar peso de columnas
        scrollable_frame.grid_columnconfigure(0, weight=1)
        scrollable_frame.grid_columnconfigure(1, weight=1)
        
        canvas.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
    def create_module_card(self, parent, module):
        """Crear tarjeta individual de módulo - VERSION OPTIMIZADA SIN PARPADEO"""
        # Frame principal de la card
        card = tk.Frame(parent, bg=self.colors['bg_card'],
                       relief='flat', bd=0)
        card.configure(width=400, height=200)
        card.grid_propagate(False)
        
        # Variable para controlar hover
        card.hover_active = False
        
        # Frame interno con padding
        inner_frame = tk.Frame(card, bg=self.colors['bg_card'])
        inner_frame.pack(fill='both', expand=True, padx=25, pady=20)
        
        # Header de la card con icono y título
        header = tk.Frame(inner_frame, bg=self.colors['bg_card'])
        header.pack(fill='x', pady=(0, 10))
        
        icon_label = tk.Label(header,
                             text=module['icon'],
                             font=('Segoe UI', 32),
                             bg=self.colors['bg_card'])
        icon_label.pack(side='left', padx=(0, 15))
        
        title_frame = tk.Frame(header, bg=self.colors['bg_card'])
        title_frame.pack(side='left', fill='x', expand=True)
        
        title = tk.Label(title_frame,
                        text=module['title'],
                        font=('Segoe UI', 16, 'bold'),
                        bg=self.colors['bg_card'],
                        fg=module['color'],
                        anchor='w')
        title.pack(fill='x')
        
        point_id = tk.Label(title_frame,
                           text=f"Punto {module['id']}",
                           font=('Segoe UI', 9),
                           bg=self.colors['bg_card'],
                           fg=self.colors['text_secondary'],
                           anchor='w')
        point_id.pack(fill='x')
        
        # Descripción
        desc = tk.Label(inner_frame,
                       text=module['description'],
                       font=('Segoe UI', 10),
                       bg=self.colors['bg_card'],
                       fg=self.colors['text_secondary'],
                       wraplength=350,
                       justify='left')
        desc.pack(fill='x', pady=(0, 15))
        
        # Footer con status y botón
        footer = tk.Frame(inner_frame, bg=self.colors['bg_card'])
        footer.pack(fill='x', side='bottom')
        
        # Badge de status
        status_badge = tk.Label(footer,
                               text=module['status'],
                               font=('Segoe UI', 9, 'bold'),
                               bg=module['color'] if module['status'] == 'Implementado' else '#444444',
                               fg='#ffffff',
                               padx=10,
                               pady=3)
        status_badge.pack(side='left')
        
        # Botón de acción
        if module['status'] == 'Implementado':
            btn = tk.Button(footer,
                          text='Abrir →',
                          font=('Segoe UI', 10, 'bold'),
                          bg=module['color'],
                          fg='#ffffff',
                          activebackground=module['color'],
                          activeforeground='#ffffff',
                          relief='flat',
                          cursor='hand2',
                          padx=20,
                          pady=5,
                          command=lambda m=module: self.open_module(m['id']))
            btn.pack(side='right')
        else:
            btn = tk.Label(footer,
                          text='Próximamente',
                          font=('Segoe UI', 9),
                          bg=self.colors['bg_card'],
                          fg=self.colors['text_secondary'])
            btn.pack(side='right')
        
        # Lista de todos los widgets para aplicar hover
        all_widgets = [card, inner_frame, header, icon_label, title_frame, 
                      title, point_id, desc, footer, status_badge]
        
        # Función para cambiar color de todos los widgets
        def set_card_color(color):
            """Cambiar color de fondo de todos los widgets de la card"""
            for widget in all_widgets:
                try:
                    widget.config(bg=color)
                except:
                    pass
        
        # Hover desactivado para evitar agitación
        
        return card
    
    def adjust_color(self, color, amount):
        """Ajustar brillo de un color hex"""
        color = color.lstrip('#')
        r, g, b = int(color[0:2], 16), int(color[2:4], 16), int(color[4:6], 16)
        r = max(0, min(255, r + amount))
        g = max(0, min(255, g + amount))
        b = max(0, min(255, b + amount))
        return f'#{r:02x}{g:02x}{b:02x}'
    
    def create_footer(self):
        """Crear pie de página"""
        footer = tk.Frame(self.root, bg=self.colors['bg_dark'])
        footer.pack(fill='x', padx=40, pady=(10, 30))
        
        # Información del proyecto
        info_frame = tk.Frame(footer, bg=self.colors['bg_dark'])
        info_frame.pack()
        
        version = tk.Label(info_frame,
                          text="v1.0.0",
                          font=('Segoe UI', 9),
                          bg=self.colors['bg_dark'],
                          fg=self.colors['text_secondary'])
        version.pack(side='left', padx=(0, 20))
        
        copyright_text = tk.Label(info_frame,
                                 text="💻 Laboratorio de Programación Segura | Universidad 2025",
                                 font=('Segoe UI', 9),
                                 bg=self.colors['bg_dark'],
                                 fg=self.colors['text_secondary'])
        copyright_text.pack(side='left')
        
    def open_module(self, module_id):
        """Abrir el módulo seleccionado"""
        if module_id == '1a':
            # Importar y abrir el módulo de Message Digest
            try:
                from modules.message_digest_module import MessageDigestModule
                
                # Crear nueva ventana
                module_window = tk.Toplevel(self.root)
                MessageDigestModule(module_window)
                
            except ImportError as e:
                print(f"Error al importar módulo: {e}")
                self.show_error_window("Message Digest")
                
        elif module_id == '1b':
            # Importar y abrir el módulo de Firma Digital
            try:
                from modules.digital_signature_module import DigitalSignatureModule
                
                # Crear nueva ventana
                module_window = tk.Toplevel(self.root)
                DigitalSignatureModule(module_window)
                
            except ImportError as e:
                print(f"Error al importar módulo: {e}")
                self.show_error_window("Firma Digital")
                
        elif module_id == '1c-1d':
            # Importar y abrir el módulo de Cifrado RSA
            try:
                from modules.encryption_module import EncryptionModule
                
                # Crear nueva ventana
                module_window = tk.Toplevel(self.root)
                EncryptionModule(module_window)
                
            except ImportError as e:
                print(f"Error al importar módulo: {e}")
                self.show_error_window("Cifrado RSA")
    
    def show_error_window(self, module_name):
        """Mostrar ventana de error al cargar módulo"""
        error_window = tk.Toplevel(self.root)
        error_window.title("Error")
        error_window.geometry("400x200")
        error_window.configure(bg=self.colors['bg_card'])
                
        tk.Label(error_window,
                text="❌ Error al cargar el módulo",
                font=('Segoe UI', 14, 'bold'),
                bg=self.colors['bg_card'],
                fg='#ff4444').pack(pady=30)
        
        tk.Label(error_window,
                text="El módulo no se encuentra disponible.",
                font=('Segoe UI', 10),
                bg=self.colors['bg_card'],
                fg=self.colors['text_secondary']).pack()
        
        tk.Button(error_window,
                    text="Cerrar",
                    command=error_window.destroy,
                    bg='#ff4444',
                    fg='#ffffff',
                    font=('Segoe UI', 10, 'bold'),
                    relief='flat',
                    padx=20,
                    pady=5).pack(pady=30)


def main():
    """Función principal"""
    root = tk.Tk()
    app = CryptoSuiteHome(root)
    root.mainloop()


if __name__ == "__main__":
    main()