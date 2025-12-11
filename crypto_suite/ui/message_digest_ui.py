#!/usr/bin/env python3
"""
Laboratorio de Programación Segura
UI: Message Digest Interface (Punto 1a)

Interfaz gráfica para el módulo de Message Digest.
Usa la lógica del backend sin mezclar responsabilidades.
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import sys
import os

# Agregar el directorio raíz al path para imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.message_digest_logic import MessageDigestLogic


class MessageDigestUI:
    """Interfaz gráfica para Message Digest"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("📝 Message Digest - Suite Criptográfica")
        self.root.geometry("1200x800")
        self.root.configure(bg='#1e1e1e')
        
        # Instancia de la lógica de negocio
        self.logic = MessageDigestLogic()
        
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
        """Configurar estilos"""
        style = ttk.Style()
        style.theme_use('clam')
        
        self.colors = {
            'bg_dark': '#1e1e1e',
            'bg_medium': '#2d2d2d',
            'bg_card': '#252525',
            'accent': '#0078d4',
            'accent_hover': '#005a9e',
            'text_primary': '#ffffff',
            'text_secondary': '#b0b0b0'
        }
        
        # Configurar estilos de ttk
        style.configure('TNotebook', background=self.colors['bg_dark'], borderwidth=0)
        style.configure('TNotebook.Tab',
                       background=self.colors['bg_medium'],
                       foreground=self.colors['text_primary'],
                       padding=[20, 10],
                       font=('Segoe UI', 10, 'bold'))
        style.map('TNotebook.Tab',
                 background=[('selected', self.colors['accent'])])
        
        style.configure('TFrame', background=self.colors['bg_dark'])
        style.configure('Card.TFrame', background=self.colors['bg_medium'])
        
        style.configure('TLabel',
                       background=self.colors['bg_dark'],
                       foreground=self.colors['text_primary'],
                       font=('Segoe UI', 10))
        
        style.configure('Title.TLabel',
                       font=('Segoe UI', 16, 'bold'),
                       foreground=self.colors['accent'])
        
        style.configure('Accent.TButton',
                       background=self.colors['accent'],
                       foreground=self.colors['text_primary'],
                       borderwidth=0,
                       font=('Segoe UI', 10, 'bold'),
                       padding=[20, 10])
        style.map('Accent.TButton',
                 background=[('active', self.colors['accent_hover'])])
        
    def create_interface(self):
        """Crear interfaz principal"""
        # Header
        self.create_header()
        
        # Notebook con pestañas
        self.create_notebook()
        
        # Footer
        self.create_footer()
        
    def create_header(self):
        """Crear encabezado"""
        header = ttk.Frame(self.root)
        header.pack(fill='x', padx=20, pady=20)
        
        # Botón de regreso
        back_btn = tk.Button(header,
                            text='← Regresar al Home',
                            font=('Segoe UI', 10),
                            bg=self.colors['bg_medium'],
                            fg=self.colors['text_primary'],
                            activebackground=self.colors['accent'],
                            relief='flat',
                            cursor='hand2',
                            padx=15,
                            pady=8,
                            command=self.go_back)
        back_btn.pack(side='left')
        
        # Título
        title_frame = tk.Frame(header, bg=self.colors['bg_dark'])
        title_frame.pack(side='left', padx=20)
        
        ttk.Label(title_frame,
                 text="📝 Message Digest",
                 style='Title.TLabel').pack(anchor='w')
        
        ttk.Label(title_frame,
                 text="Punto 1a - Generación de Resúmenes Digitales",
                 foreground=self.colors['text_secondary']).pack(anchor='w')
        
    def create_notebook(self):
        """Crear pestañas de funcionalidades"""
        notebook_frame = ttk.Frame(self.root)
        notebook_frame.pack(fill='both', expand=True, padx=20, pady=(0, 20))
        
        self.notebook = ttk.Notebook(notebook_frame)
        self.notebook.pack(fill='both', expand=True)
        
        # Pestañas
        self.notebook.add(self.create_digest_tab(), text='📝 Message Digest')
        self.notebook.add(self.create_hmac_tab(), text='🔑 HMAC')
        self.notebook.add(self.create_visualization_tab(), text='📊 Visualización')
        self.notebook.add(self.create_comparison_tab(), text='⚖️ Comparación')
        
    def create_digest_tab(self):
        """Pestaña de Message Digest básico"""
        frame = ttk.Frame(self.notebook)
        
        # Input
        input_frame = ttk.Frame(frame, style='Card.TFrame')
        input_frame.pack(fill='x', padx=20, pady=20)
        
        ttk.Label(input_frame, text="Mensaje de Entrada:").pack(anchor='w', padx=15, pady=(15, 5))
        
        self.digest_input = scrolledtext.ScrolledText(input_frame, height=4,
                                                      font=('Consolas', 10),
                                                      bg='#2d2d2d', fg='#ffffff',
                                                      insertbackground='#ffffff',
                                                      padx=10, pady=10)
        self.digest_input.pack(fill='x', padx=15, pady=(0, 15))
        self.digest_input.insert('1.0', 'This is a test message!')
        
        # Algoritmos
        algo_frame = ttk.Frame(frame, style='Card.TFrame')
        algo_frame.pack(fill='x', padx=20, pady=(0, 20))
        
        ttk.Label(algo_frame, text="Algoritmo:").pack(anchor='w', padx=15, pady=(15, 10))
        
        algo_buttons = ttk.Frame(algo_frame, style='Card.TFrame')
        algo_buttons.pack(fill='x', padx=15, pady=(0, 15))
        
        self.digest_algo = tk.StringVar(value='sha256')
        algorithms = [
            ('MD5 (128 bits)', 'md5'),
            ('SHA-1 (160 bits)', 'sha1'),
            ('SHA-256 (256 bits)', 'sha256'),
            ('SHA-384 (384 bits)', 'sha384'),
            ('SHA-512 (512 bits)', 'sha512')
        ]
        
        for i, (label, value) in enumerate(algorithms):
            tk.Radiobutton(algo_buttons, text=label,
                          variable=self.digest_algo, value=value,
                          bg='#2d2d2d', fg='#ffffff',
                          selectcolor='#007acc',
                          activebackground='#2d2d2d',
                          font=('Segoe UI', 10)).grid(row=i//3, column=i%3,
                                                       sticky='w', padx=10, pady=5)
        
        # Botón
        ttk.Button(frame, text="🔄 Generar Digest",
                  style='Accent.TButton',
                  command=self.generate_digest).pack(pady=(0, 20))
        
        # Output
        result_frame = ttk.Frame(frame, style='Card.TFrame')
        result_frame.pack(fill='both', expand=True, padx=20, pady=(0, 20))
        
        ttk.Label(result_frame, text="Resultado:").pack(anchor='w', padx=15, pady=(15, 5))
        
        self.digest_output = scrolledtext.ScrolledText(result_frame, height=8,
                                                       font=('Consolas', 10),
                                                       bg='#1a1a1a', fg='#00ff00',
                                                       padx=10, pady=10, state='disabled')
        self.digest_output.pack(fill='both', expand=True, padx=15, pady=(0, 15))
        
        return frame
    
    def create_hmac_tab(self):
        """Pestaña de HMAC"""
        frame = ttk.Frame(self.notebook)
        
        # Mensaje
        msg_frame = ttk.Frame(frame, style='Card.TFrame')
        msg_frame.pack(fill='x', padx=20, pady=20)
        
        ttk.Label(msg_frame, text="Mensaje:").pack(anchor='w', padx=15, pady=(15, 5))
        
        self.hmac_input = scrolledtext.ScrolledText(msg_frame, height=3,
                                                    font=('Consolas', 10),
                                                    bg='#2d2d2d', fg='#ffffff',
                                                    padx=10, pady=10)
        self.hmac_input.pack(fill='x', padx=15, pady=(0, 15))
        self.hmac_input.insert('1.0', 'Secret message for authentication')
        
        # Clave
        key_frame = ttk.Frame(frame, style='Card.TFrame')
        key_frame.pack(fill='x', padx=20, pady=(0, 20))
        
        ttk.Label(key_frame, text="Clave Secreta:").pack(anchor='w', padx=15, pady=(15, 5))
        
        self.hmac_key = tk.Entry(key_frame, font=('Consolas', 11),
                                bg='#2d2d2d', fg='#ffffff', show='•')
        self.hmac_key.pack(fill='x', padx=15, pady=(0, 5))
        self.hmac_key.insert(0, 'mi_clave_super_secreta_123')
        
        self.show_key = tk.BooleanVar()
        tk.Checkbutton(key_frame, text="Mostrar clave",
                      variable=self.show_key,
                      command=self.toggle_key_visibility,
                      bg='#2d2d2d', fg='#b0b0b0',
                      selectcolor='#007acc').pack(anchor='w', padx=15, pady=(0, 15))
        
        # Algoritmo
        algo_frame = ttk.Frame(frame, style='Card.TFrame')
        algo_frame.pack(fill='x', padx=20, pady=(0, 20))
        
        ttk.Label(algo_frame, text="Algoritmo:").pack(anchor='w', padx=15, pady=(15, 10))
        
        self.hmac_algo = tk.StringVar(value='sha256')
        algo_buttons = ttk.Frame(algo_frame, style='Card.TFrame')
        algo_buttons.pack(fill='x', padx=15, pady=(0, 15))
        
        for i, algo in enumerate(['MD5', 'SHA-1', 'SHA-256', 'SHA-512']):
            tk.Radiobutton(algo_buttons, text=f"HMAC-{algo}",
                          variable=self.hmac_algo,
                          value=algo.lower().replace('-', ''),
                          bg='#2d2d2d', fg='#ffffff',
                          selectcolor='#007acc').grid(row=0, column=i, padx=10, pady=5)
        
        # Botón
        ttk.Button(frame, text="🔐 Generar HMAC",
                  style='Accent.TButton',
                  command=self.generate_hmac).pack(pady=(0, 20))
        
        # Output
        result_frame = ttk.Frame(frame, style='Card.TFrame')
        result_frame.pack(fill='both', expand=True, padx=20, pady=(0, 20))
        
        ttk.Label(result_frame, text="Resultado:").pack(anchor='w', padx=15, pady=(15, 5))
        
        self.hmac_output = scrolledtext.ScrolledText(result_frame, height=6,
                                                     font=('Consolas', 10),
                                                     bg='#1a1a1a', fg='#ffaa00',
                                                     padx=10, pady=10, state='disabled')
        self.hmac_output.pack(fill='both', expand=True, padx=15, pady=(0, 15))
        
        return frame
    
    def create_visualization_tab(self):
        """Pestaña de visualización"""
        frame = ttk.Frame(self.notebook)
        
        # Info
        info_frame = ttk.Frame(frame, style='Card.TFrame')
        info_frame.pack(fill='x', padx=20, pady=20)
        
        ttk.Label(info_frame, text="🌊 Efecto Avalancha",
                 style='Title.TLabel').pack(anchor='w', padx=15, pady=(15, 5))
        ttk.Label(info_frame,
                 text="Un pequeño cambio en el input produce un cambio drástico en el hash",
                 foreground='#b0b0b0').pack(anchor='w', padx=15, pady=(0, 15))
        
        # Input
        input_frame = ttk.Frame(frame, style='Card.TFrame')
        input_frame.pack(fill='x', padx=20, pady=(0, 20))
        
        ttk.Label(input_frame, text="Mensaje:").pack(anchor='w', padx=15, pady=(15, 5))
        
        self.avalanche_input = tk.Entry(input_frame, font=('Consolas', 11),
                                       bg='#2d2d2d', fg='#ffffff')
        self.avalanche_input.pack(fill='x', padx=15, pady=(0, 15))
        self.avalanche_input.insert(0, 'Hello World!')
        
        # Botón
        ttk.Button(frame, text="🔍 Analizar",
                  style='Accent.TButton',
                  command=self.analyze_avalanche).pack(pady=(0, 20))
        
        # Canvas
        viz_frame = ttk.Frame(frame, style='Card.TFrame')
        viz_frame.pack(fill='both', expand=True, padx=20, pady=(0, 20))
        
        self.avalanche_canvas = tk.Canvas(viz_frame, bg='#1a1a1a',
                                         highlightthickness=0)
        self.avalanche_canvas.pack(fill='both', expand=True, padx=15, pady=15)
        
        return frame
    
    def create_comparison_tab(self):
        """Pestaña de comparación"""
        frame = ttk.Frame(self.notebook)
        
        # Mensajes
        messages_frame = ttk.Frame(frame)
        messages_frame.pack(fill='both', expand=True, padx=20, pady=20)
        
        # Mensaje 1
        msg1_frame = ttk.Frame(messages_frame, style='Card.TFrame')
        msg1_frame.pack(side='left', fill='both', expand=True, padx=(0, 10))
        
        ttk.Label(msg1_frame, text="Mensaje 1:").pack(anchor='w', padx=15, pady=(15, 5))
        
        self.compare_msg1 = scrolledtext.ScrolledText(msg1_frame, height=10,
                                                      font=('Consolas', 10),
                                                      bg='#2d2d2d', fg='#ffffff',
                                                      padx=10, pady=10)
        self.compare_msg1.pack(fill='both', expand=True, padx=15, pady=(0, 15))
        self.compare_msg1.insert('1.0', 'Mensaje para comparación')
        
        # Mensaje 2
        msg2_frame = ttk.Frame(messages_frame, style='Card.TFrame')
        msg2_frame.pack(side='left', fill='both', expand=True, padx=(10, 0))
        
        ttk.Label(msg2_frame, text="Mensaje 2:").pack(anchor='w', padx=15, pady=(15, 5))
        
        self.compare_msg2 = scrolledtext.ScrolledText(msg2_frame, height=10,
                                                      font=('Consolas', 10),
                                                      bg='#2d2d2d', fg='#ffffff',
                                                      padx=10, pady=10)
        self.compare_msg2.pack(fill='both', expand=True, padx=15, pady=(0, 15))
        self.compare_msg2.insert('1.0', 'Mensaje para comparación')
        
        # Botón
        ttk.Button(frame, text="⚖️ Comparar",
                  style='Accent.TButton',
                  command=self.compare_messages).pack(pady=(0, 20))
        
        # Output
        result_frame = ttk.Frame(frame, style='Card.TFrame')
        result_frame.pack(fill='x', padx=20, pady=(0, 20))
        
        self.compare_output = scrolledtext.ScrolledText(result_frame, height=8,
                                                        font=('Consolas', 10),
                                                        bg='#1a1a1a', fg='#00aaff',
                                                        padx=10, pady=10, state='disabled')
        self.compare_output.pack(fill='both', expand=True, padx=15, pady=15)
        
        return frame
    
    def create_footer(self):
        """Crear footer"""
        footer = ttk.Frame(self.root)
        footer.pack(fill='x', padx=20, pady=(0, 20))
        
        ttk.Label(footer,
                 text="Punto 1a: Message Digest | Laboratorio de Programación Segura",
                 foreground='#b0b0b0').pack()
        
    # ==================== MÉTODOS DE EVENTOS (Llaman al backend) ====================
    
    def generate_digest(self):
        """Generar digest usando la lógica del backend"""
        message = self.digest_input.get('1.0', 'end-1c')
        algorithm = self.digest_algo.get()
        
        try:
            # Llamar a la lógica del backend
            result = self.logic.generate_digest(message, algorithm)
            
            # Formatear salida
            self.digest_output.config(state='normal')
            self.digest_output.delete('1.0', 'end')
            
            output = f"Algoritmo: {result['algorithm']}\n"
            output += f"Tamaño: {result['digest_size']} bytes ({result['digest_size_bits']} bits)\n"
            output += f"Bloque: {result['block_size']} bytes\n\n{'='*60}\n\n"
            output += f"Digest (Hex):\n{result['digest_hex']}\n\n{'='*60}\n"
            
            self.digest_output.insert('1.0', output)
            self.digest_output.config(state='disabled')
            
        except ValueError as e:
            messagebox.showwarning("Advertencia", str(e))
        except Exception as e:
            messagebox.showerror("Error", f"Error al generar digest: {str(e)}")
    
    def generate_hmac(self):
        """Generar HMAC usando la lógica del backend"""
        message = self.hmac_input.get('1.0', 'end-1c')
        key = self.hmac_key.get()
        algorithm = self.hmac_algo.get()
        
        try:
            # Llamar a la lógica del backend
            result = self.logic.generate_hmac(message, key, algorithm)
            
            # Formatear salida
            self.hmac_output.config(state='normal')
            self.hmac_output.delete('1.0', 'end')
            
            output = f"{result['algorithm']}\n"
            output += f"Tamaño: {result['digest_size']} bytes\n\n{'='*60}\n\n"
            output += f"{result['hmac_hex']}\n\n{'='*60}\n"
            
            self.hmac_output.insert('1.0', output)
            self.hmac_output.config(state='disabled')
            
        except ValueError as e:
            messagebox.showwarning("Advertencia", str(e))
        except Exception as e:
            messagebox.showerror("Error", f"Error al generar HMAC: {str(e)}")
    
    def analyze_avalanche(self):
        """Analizar efecto avalancha usando la lógica del backend"""
        message = self.avalanche_input.get()
        
        try:
            # Llamar a la lógica del backend
            result = self.logic.analyze_avalanche_effect(message, 'sha256')
            
            # Visualizar resultados
            self.visualize_avalanche(
                result['original_hash'],
                result['modified_hash'],
                result['bits_changed'],
                result['total_bits'],
                result['percentage'],
                result['original_message'],
                result['modified_message']
            )
            
        except ValueError as e:
            messagebox.showwarning("Advertencia", str(e))
        except Exception as e:
            messagebox.showerror("Error", f"Error al analizar: {str(e)}")
    
    def compare_messages(self):
        """Comparar mensajes usando la lógica del backend"""
        msg1 = self.compare_msg1.get('1.0', 'end-1c')
        msg2 = self.compare_msg2.get('1.0', 'end-1c')
        
        try:
            # Llamar a la lógica del backend
            results = self.logic.compare_messages(msg1, msg2)
            
            # Formatear salida
            self.compare_output.config(state='normal')
            self.compare_output.delete('1.0', 'end')
            
            output = "COMPARACIÓN DE MENSAJES\n" + "=" * 60 + "\n\n"
            
            for algo in ['md5', 'sha1', 'sha256', 'sha512']:
                if algo in results:
                    data = results[algo]
                    output += f"{data['algorithm']}:\n"
                    output += f"  Msg 1: {data['hash1']}\n"
                    output += f"  Msg 2: {data['hash2']}\n"
                    output += f"  Match: {'✓ SÍ' if data['match'] else '✗ NO'}\n\n"
            
            output += "=" * 60 + "\n"
            output += f"RESULTADO: {'IDÉNTICOS ✓' if results['messages_identical'] else 'DIFERENTES ✗'}"
            
            self.compare_output.insert('1.0', output)
            self.compare_output.config(state='disabled')
            
        except ValueError as e:
            messagebox.showwarning("Advertencia", str(e))
        except Exception as e:
            messagebox.showerror("Error", f"Error al comparar: {str(e)}")
    
    # ==================== MÉTODOS DE VISUALIZACIÓN ====================
    
    def visualize_avalanche(self, hash1, hash2, diff_bits, total_bits, percentage, msg1, msg2):
        """Visualizar en canvas"""
        canvas = self.avalanche_canvas
        canvas.delete('all')
        
        width = max(canvas.winfo_width(), 800)
        height = max(canvas.winfo_height(), 400)
        
        canvas.create_text(width/2, 30,
                          text=f"Bits cambiados: {diff_bits}/{total_bits} ({percentage:.2f}%)",
                          fill='#00ff00', font=('Segoe UI', 14, 'bold'))
        
        canvas.create_text(width/2, 70,
                          text=f'Original: "{msg1}"  →  Modificado: "{msg2}"',
                          fill='#ffffff', font=('Segoe UI', 10))
        
        y = 110
        bar_height = 50
        
        canvas.create_text(20, y, text="Original:", fill='#ffffff',
                          font=('Segoe UI', 10), anchor='w')
        self.draw_hash_bar(canvas, hash1, 20, y + 20, width - 40, bar_height, '#007acc')
        
        y += 90
        canvas.create_text(20, y, text="Modificado:", fill='#ffffff',
                          font=('Segoe UI', 10), anchor='w')
        self.draw_hash_bar(canvas, hash2, 20, y + 20, width - 40, bar_height, '#ff4444')
        
        y += 90
        canvas.create_text(20, y, text="Diferencias:", fill='#00ff00',
                          font=('Segoe UI', 10, 'bold'), anchor='w')
        self.draw_diff_bar(canvas, hash1, hash2, 20, y + 20, width - 40, bar_height)
    
    def draw_hash_bar(self, canvas, hash_str, x, y, width, height, color):
        """Dibujar barra de hash"""
        seg_width = width / len(hash_str)
        
        for i, char in enumerate(hash_str):
            intensity = int(char, 16) / 15.0
            r = int(int(color[1:3], 16) * intensity)
            g = int(int(color[3:5], 16) * intensity)
            b = int(int(color[5:7], 16) * intensity)
            
            canvas.create_rectangle(x + i * seg_width, y,
                                   x + (i + 1) * seg_width, y + height,
                                   fill=f'#{r:02x}{g:02x}{b:02x}', outline='')
    
    def draw_diff_bar(self, canvas, hash1, hash2, x, y, width, height):
        """Dibujar diferencias"""
        seg_width = width / len(hash1)
        
        for i in range(len(hash1)):
            color = '#00ff00' if hash1[i] != hash2[i] else '#2d2d2d'
            canvas.create_rectangle(x + i * seg_width, y,
                                   x + (i + 1) * seg_width, y + height,
                                   fill=color, outline='')
    
    # ==================== MÉTODOS AUXILIARES ====================
    
    def toggle_key_visibility(self):
        """Toggle visibilidad de clave"""
        self.hmac_key.config(show='' if self.show_key.get() else '•')
    
    def go_back(self):
        """Regresar al home"""
        self.root.destroy()


def main():
    """Función principal standalone"""
    root = tk.Tk()
    app = MessageDigestUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
