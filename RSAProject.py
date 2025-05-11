import random
import math
from math import gcd
import tkinter as tk
from tkinter import ttk, messagebox

class RSAApp:
    def __init__(self, root):
        self.root = root
        self.root.title("RSA Encryption Tool")
        self.root.geometry("800x700")
        
        
        self.public_key = (None, None)
        self.private_key = (None, None)
        self.p = None
        self.q = None
        self.bit_length = tk.IntVar(value=256)
        self.message_type = tk.StringVar(value="integer")
        
        
        self.create_widgets()
        
    def create_widgets(self):
        
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill='both', expand=True)
        
        
        key_frame = ttk.Frame(notebook)
        notebook.add(key_frame, text="Key Generation")
        
        
        crypto_frame = ttk.Frame(notebook)
        notebook.add(crypto_frame, text="Encryption/Decryption")
        
        
        self.build_key_generation_tab(key_frame)
        
        
        self.build_crypto_tab(crypto_frame)
    
    def build_key_generation_tab(self, frame):
        
        ttk.Label(frame, text="Key Strength (bits):").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        bit_combo = ttk.Combobox(frame, textvariable=self.bit_length, 
                                values=[128, 256, 512, 1024, 2048], state='readonly')
        bit_combo.grid(row=0, column=1, padx=5, pady=5, sticky='ew')
        
       
        gen_btn = ttk.Button(frame, text="Generate Keys", command=self.generate_keys)
        gen_btn.grid(row=1, column=0, columnspan=2, pady=10)
        
        
        ttk.Label(frame, text="Public Key (n, e):").grid(row=2, column=0, padx=5, pady=5, sticky='nw')
        
        self.pub_key_n_display = tk.Text(frame, height=4, width=70, wrap=tk.WORD)
        self.pub_key_n_display.grid(row=2, column=1, padx=5, pady=5, sticky='w')
        
        ttk.Label(frame, text="Private Key (n, d):").grid(row=3, column=0, padx=5, pady=5, sticky='nw')
        self.priv_key_display = tk.Text(frame, height=4, width=70, wrap=tk.WORD)
        self.priv_key_display.grid(row=3, column=1, padx=5, pady=5, sticky='w')
        
        ttk.Label(frame, text="Prime p:").grid(row=4, column=0, padx=5, pady=5, sticky='w')
        self.p_display = ttk.Label(frame, text="Not generated", wraplength=600)
        self.p_display.grid(row=4, column=1, padx=5, pady=5, sticky='w')
        
        ttk.Label(frame, text="Prime q:").grid(row=5, column=0, padx=5, pady=5, sticky='w')
        self.q_display = ttk.Label(frame, text="Not generated", wraplength=600)
        self.q_display.grid(row=5, column=1, padx=5, pady=5, sticky='w')
    
    def build_crypto_tab(self, frame):
        
        ttk.Label(frame, text="Message Type:").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        type_combo = ttk.Combobox(frame, textvariable=self.message_type, 
                                 values=["integer", "string"], state='readonly')
        type_combo.grid(row=0, column=1, padx=5, pady=5, sticky='ew')
        
        
        ttk.Label(frame, text="Message:").grid(row=1, column=0, padx=5, pady=5, sticky='w')
        self.message_entry = ttk.Entry(frame)
        self.message_entry.grid(row=1, column=1, padx=5, pady=5, sticky='ew')
        
       
        encrypt_btn = ttk.Button(frame, text="Encrypt", command=self.encrypt_message)
        encrypt_btn.grid(row=2, column=0, columnspan=2, pady=5)
        
        
        ttk.Label(frame, text="Encrypted Message:").grid(row=3, column=0, padx=5, pady=5, sticky='w')
        self.encrypted_display = tk.Text(frame, height=4, width=70, wrap=tk.WORD)
        self.encrypted_display.grid(row=3, column=1, padx=5, pady=5, sticky='w')
        
        
        decrypt_btn = ttk.Button(frame, text="Decrypt", command=self.decrypt_message)
        decrypt_btn.grid(row=4, column=0, columnspan=2, pady=5)
        
        
        ttk.Label(frame, text="Decrypted Message:").grid(row=5, column=0, padx=5, pady=5, sticky='w')
        self.decrypted_display = tk.Text(frame, height=4, width=70, wrap=tk.WORD)
        self.decrypted_display.grid(row=5, column=1, padx=5, pady=5, sticky='w')
    
    def string_to_int(self, text):
        """Convert string to integer representation"""
        return int.from_bytes(text.encode('utf-8'), 'big')
    
    def int_to_string(self, num):
        """Convert integer back to string"""
        return num.to_bytes((num.bit_length() + 7) // 8, 'big').decode('utf-8')
    
    def is_prime(self, n: int, k: int = 5) -> bool:
        """Miller-Rabin primality test."""
        if n <= 1:
            return False
        elif n <= 3:
            return True
        elif n % 2 == 0:
            return False
        
        d = n - 1
        s = 0
        while d % 2 == 0:
            d //= 2
            s += 1
        
        for _ in range(k):
            a = random.randint(2, n - 2)
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for __ in range(s - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True
    
    def generate_prime(self, bits: int) -> int:
        """Generate a random prime number with approximately 'bits' bits."""
        while True:
            candidate = random.getrandbits(bits)
            candidate |= (1 << bits - 1) | 1  
            
            if self.is_prime(candidate):
                return candidate
    
    def modinv(self, a: int, m: int) -> int:
        """Modular inverse using extended Euclidean algorithm."""
        g, x, y = self.extended_gcd(a, m)
        if g != 1:
            raise ValueError('Modular inverse does not exist')
        return x % m
    
    def extended_gcd(self, a: int, b: int) -> tuple:
        """Extended Euclidean algorithm."""
        if a == 0:
            return (b, 0, 1)
        else:
            g, y, x = self.extended_gcd(b % a, a)
            return (g, x - (b // a) * y, y)
    
    def generate_keys(self):
        """Generate RSA public and private keys."""
        bits = self.bit_length.get()
        
        try:
            p = self.generate_prime(bits)
            q = self.generate_prime(bits)
            while q == p:
                q = self.generate_prime(bits)

            n = p * q
            phi = (p - 1) * (q - 1)

            e = 65537 if 65537 < phi and gcd(65537, phi) == 1 else None
            if e is None:
                e = random.randrange(2, phi)
                while gcd(e, phi) != 1:
                    e = random.randrange(2, phi)

            d = self.modinv(e, phi)
            
            self.public_key = (n, e)
            self.private_key = (n, d)
            self.p = p
            self.q = q
            
            
            self.pub_key_n_display.delete(1.0, tk.END)
            self.pub_key_n_display.insert(tk.END, f"n:\n{n}\n\ne:\n{e}")
            
            self.priv_key_display.delete(1.0, tk.END)
            self.priv_key_display.insert(tk.END, f"n:\n{n}\n\nd:\n{d}")
            
            self.p_display.config(text=str(p))
            self.q_display.config(text=str(q))
            
            messagebox.showinfo("Success", "Keys generated successfully!")
            
        except Exception as e:
            messagebox.showerror("Error", f"Key generation failed: {str(e)}")
    
    def encrypt_message(self):
        """Encrypt the message using public key."""
        if self.public_key[0] is None:
            messagebox.showerror("Error", "Please generate keys first!")
            return
        
        try:
            message = self.message_entry.get()
            
            if self.message_type.get() == "integer":
                message_num = int(message)
            else:  
                message_num = self.string_to_int(message)
            
            if message_num >= self.public_key[0]:
                messagebox.showerror("Error", "Message is too large for the current key size")
                return
                
            encrypted = pow(message_num, self.public_key[1], self.public_key[0])
            self.encrypted_display.delete(1.0, tk.END)
            self.encrypted_display.insert(tk.END, str(encrypted))
        except ValueError as ve:
            if self.message_type.get() == "integer":
                messagebox.showerror("Error", "Please enter a valid integer message")
            else:
                messagebox.showerror("Error", f"Invalid message: {str(ve)}")
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")
    
    def decrypt_message(self):
        """Decrypt the message using private key."""
        if self.private_key[0] is None:
            messagebox.showerror("Error", "Please generate keys first!")
            return
        
        try:
            
            encrypted_text = self.encrypted_display.get(1.0, tk.END).strip()
            
            if not encrypted_text:
                messagebox.showerror("Error", "No encrypted message to decrypt")
                return
                
            encrypted = int(encrypted_text)
            decrypted_num = pow(encrypted, self.private_key[1], self.private_key[0])
            
            self.decrypted_display.delete(1.0, tk.END)
            if self.message_type.get() == "integer":
                self.decrypted_display.insert(tk.END, str(decrypted_num))
            else:
                try:
                    decrypted_str = self.int_to_string(decrypted_num)
                    self.decrypted_display.insert(tk.END, decrypted_str)
                except UnicodeDecodeError:
                    self.decrypted_display.insert(tk.END, f"Numerical result: {decrypted_num}\n(Could not convert to string)")
        except ValueError:
            messagebox.showerror("Error", "Invalid encrypted message format")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = RSAApp(root)
    root.mainloop()