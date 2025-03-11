import sqlite3
import matplotlib.pyplot as plt

DATABASE = 'database.db'

def create_user(username, password, role):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (username, password, role))
    conn.commit()
    conn.close()

def generate_graph(grades):
    plt.plot(grades)
    plt.title('Gráfico de Habilidades')
    plt.xlabel('Notas')
    plt.ylabel('Desempenho')
    plt.savefig('static/graph.png')
    plt.close()
