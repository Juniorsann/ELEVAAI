import sqlite3
import hashlib

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()  # Criptografar senha

def add_admin():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    username = "admin"
    password = hash_password("admin123")  # Senha segura
    role = "admin"

    cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (username, password, role))

    conn.commit()
    conn.close()
    print("Administrador criado com sucesso!")

if __name__ == "__main__":
    add_admin()
