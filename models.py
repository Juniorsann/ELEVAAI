import sqlite3

DATABASE = 'database.db'

class User:
    @staticmethod
    def get_user_by_id(user_id):
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        conn.close()
        return user

    @staticmethod
    def authenticate(username, password):
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
        user = cursor.fetchone()
        conn.close()
        return user

class Discipline:
    @staticmethod
    def get_user_disciplines(user_id):
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM disciplines WHERE user_id = ?", (user_id,))
        disciplines = cursor.fetchall()
        conn.close()
        return disciplines
