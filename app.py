from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
from contextlib import contextmanager
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'default_secret_key')  # Usar variáveis de ambiente para segurança

# Configuração do Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Rota para redirecionar usuários não autenticados

# Classe de usuário para o Flask-Login
class User(UserMixin):
    def __init__(self, user_id, username, role):
        self.id = user_id
        self.username = username
        self.role = role

# Função para carregar o usuário
@login_manager.user_loader
def load_user(user_id):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        user_data = cursor.fetchone()
        if user_data:
            return User(user_data['id'], user_data['username'], user_data['role'])
        return None

# Gerenciador de contexto para conexões com o banco de dados
@contextmanager
def get_db_connection():
    conn = sqlite3.connect('database.db', timeout=10)  # Timeout de 10 segundos
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    except sqlite3.Error as e:
        flash(f'Erro ao conectar ao banco de dados: {e}', 'error')
        raise  # Propaga o erro para facilitar a depuração
    finally:
        conn.close()

# Rota de login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:  # Verifica se o usuário já está autenticado
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()

            if user and check_password_hash(user['password'], password):
                user_obj = User(user['id'], user['username'], user['role'])
                login_user(user_obj)  # Faz login com o Flask-Login
                return redirect(url_for('home'))
            else:
                flash('Credenciais inválidas!', 'error')

    return render_template('login.html')

# Rota de logout
@app.route('/logout')
@login_required
def logout():
    logout_user()  # Faz logout com o Flask-Login
    return redirect(url_for('home'))

# Rota principal
@app.route('/')
def home():
    if not current_user.is_authenticated:  # Verifica se o usuário está logado
        return render_template('home.html')

    if current_user.role == 'student':
        return redirect(url_for('student_dashboard'))
    elif current_user.role == 'teacher':
        return redirect(url_for('professor_dashboard'))
    elif current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    return redirect(url_for('login'))  # Redireciona para login se não houver role

# Rota para o painel do aluno
@app.route('/student_dashboard')
@login_required
def student_dashboard():
    if current_user.role != 'student':  # Verifica o papel do usuário
        return redirect(url_for('home'))

    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Buscar as disciplinas atribuídas ao aluno e suas notas/frequência
        cursor.execute("""
            SELECT disciplines.name, grades.grade, grades.frequency
            FROM grades
            JOIN disciplines ON grades.discipline_id = disciplines.id
            WHERE grades.student_id = ?
        """, (current_user.id,))
        grades = cursor.fetchall()

        # Buscar as mensagens para o aluno
        cursor.execute("""
            SELECT assunto, mensagem
            FROM messages
            WHERE student_id = ?
        """, (current_user.id,))
        messages = cursor.fetchall()

        # Buscar o conteúdo das disciplinas do aluno
        cursor.execute("""
            SELECT content.content, disciplines.name AS discipline_name
            FROM content
            JOIN disciplines ON content.discipline_id = disciplines.id
            JOIN grades ON grades.discipline_id = disciplines.id
            WHERE grades.student_id = ?
        """, (current_user.id,))
        contents = cursor.fetchall()

    return render_template('student_dashboard.html', grades=grades, messages=messages, contents=contents)

# Rota para o painel do professor
@app.route('/professor_dashboard', methods=['GET', 'POST'])
@login_required
def professor_dashboard():
    if current_user.role != 'teacher':  # Verifica o papel do usuário
        return redirect(url_for('home'))

    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Buscar as disciplinas atribuídas ao professor
        cursor.execute("""
            SELECT disciplines.id, disciplines.name
            FROM disciplines
            JOIN professor_discipline ON disciplines.id = professor_discipline.discipline_id
            WHERE professor_discipline.user_id = ?
        """, (current_user.id,))
        disciplines = cursor.fetchall()

        # Buscar o conteúdo adicionado pelo professor
        cursor.execute("""
            SELECT content.content, disciplines.name AS discipline_name
            FROM content
            JOIN disciplines ON content.discipline_id = disciplines.id
            WHERE content.professor_id = ?
        """, (current_user.id,))
        contents = cursor.fetchall()

    return render_template('professor_dashboard.html', disciplines=disciplines, contents=contents)

# Rota para adicionar conteúdo a uma disciplina
@app.route('/add_content/<int:discipline_id>', methods=['GET', 'POST'])
@login_required
def add_content(discipline_id):
    if current_user.role != 'teacher':  # Verifica o papel do usuário
        return redirect(url_for('home'))

    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Buscar a disciplina pelo ID
        cursor.execute("SELECT * FROM disciplines WHERE id = ?", (discipline_id,))
        discipline = cursor.fetchone()

        if not discipline:
            flash('Disciplina não encontrada.', 'error')
            return redirect(url_for('professor_dashboard'))

        # Processar o envio do formulário de conteúdo
        if request.method == 'POST':
            content = request.form.get('content')

            if not content:
                flash('Por favor, preencha o campo de conteúdo.', 'error')
            else:
                # Inserir o conteúdo na tabela
                cursor.execute("""
                    INSERT INTO content (professor_id, discipline_id, content)
                    VALUES (?, ?, ?)
                """, (current_user.id, discipline_id, content))
                conn.commit()
                flash('Conteúdo adicionado com sucesso!', 'success')
                return redirect(url_for('professor_dashboard'))

    return render_template('add_content.html', discipline=discipline)

# Rota para o painel do admin
@app.route('/admin_dashboard', methods=['GET', 'POST'])
@login_required
def admin_dashboard():
    if current_user.role != 'admin':  # Verifica o papel do usuário
        return redirect(url_for('home'))

    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Buscar todos os usuários cadastrados
        cursor.execute("SELECT * FROM users")
        users = cursor.fetchall()

        # Buscar todas as disciplinas cadastradas
        cursor.execute("SELECT * FROM disciplines")
        disciplines = cursor.fetchall()

        # Buscar professores e alunos para os formulários
        cursor.execute("SELECT id, username AS name FROM users WHERE role = 'teacher'")
        teachers = cursor.fetchall()

        cursor.execute("SELECT id, username AS name FROM users WHERE role = 'student'")
        students = cursor.fetchall()

        # Buscar notas e frequência de todos os alunos
        cursor.execute("""
            SELECT grades.student_id, grades.discipline_id, grades.grade, grades.frequency
            FROM grades
            JOIN users ON grades.student_id = users.id
            JOIN disciplines ON grades.discipline_id = disciplines.id
        """)
        grades_data = cursor.fetchall()

        # Organizar os dados em um dicionário para facilitar o acesso
        grades_dict = {}
        for grade in grades_data:
            student_id = grade['student_id']
            discipline_id = grade['discipline_id']
            grades_dict[(student_id, discipline_id)] = {
                'grade': grade['grade'],
                'frequency': grade['frequency']
            }

        # Cadastrar novo usuário
        if request.method == 'POST' and 'username' in request.form:
            username = request.form['username']
            password = request.form['password']
            role = request.form['role']

            if not username or not password or not role:
                flash('Por favor, preencha todos os campos.', 'error')
            else:
                # Verifica se o nome de usuário já existe
                cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
                existing_user = cursor.fetchone()

                if existing_user:
                    flash('Nome de usuário já em uso. Escolha outro.', 'error')
                else:
                    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
                    cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
                                   (username, hashed_password, role))
                    conn.commit()

                    # Atribuir disciplina ao professor, se for o caso
                    if role == 'teacher' and 'discipline_id' in request.form:
                        discipline_id = request.form['discipline_id']
                        cursor.execute("INSERT INTO professor_discipline (user_id, discipline_id) VALUES (?, ?)", 
                                       (cursor.lastrowid, discipline_id))
                        conn.commit()

                    flash('Usuário cadastrado com sucesso!', 'success')

        # Cadastrar nova disciplina
        if request.method == 'POST' and 'disciplina' in request.form:
            disciplina = request.form['disciplina']
            professor_id = request.form.get('professor')  # Use .get() para evitar KeyError

            if not disciplina or not professor_id:
                flash('Por favor, preencha todos os campos.', 'error')
            else:
                # Verifica se a disciplina já existe
                cursor.execute("SELECT * FROM disciplines WHERE name = ?", (disciplina,))
                existing_discipline = cursor.fetchone()

                if existing_discipline:
                    flash('Disciplina já cadastrada. Escolha outro nome.', 'error')
                else:
                    # Inserir a nova disciplina
                    cursor.execute("INSERT INTO disciplines (name) VALUES (?)", (disciplina,))
                    discipline_id = cursor.lastrowid

                    # Atribuir a disciplina ao professor
                    cursor.execute("INSERT INTO professor_discipline (user_id, discipline_id) VALUES (?, ?)", 
                                   (professor_id, discipline_id))
                    conn.commit()

                    flash('Disciplina cadastrada com sucesso!', 'success')

        # Atribuir disciplina ao aluno
        if request.method == 'POST' and 'aluno' in request.form:
            print(request.form)  # Depuração: exibe os dados do formulário
            try:
                aluno_id = int(request.form['aluno'])
                disciplina_id = int(request.form['disciplina'])
            except (ValueError, KeyError):
                flash('Dados inválidos. Verifique os campos.', 'error')
                return redirect(url_for('admin_dashboard'))

            cursor.execute("SELECT * FROM grades WHERE student_id = ? AND discipline_id = ?", 
                           (aluno_id, disciplina_id))
            if cursor.fetchone():
                flash('O aluno já está matriculado nesta disciplina.', 'warning')
            else:
                cursor.execute("INSERT INTO grades (student_id, discipline_id, grade) VALUES (?, ?, ?)", 
                               (aluno_id, disciplina_id, 'N/A'))
                conn.commit()
                flash('Disciplina atribuída com sucesso!', 'success')

        # Atribuir nota e frequência ao aluno
        if request.method == 'POST' and 'nota' in request.form:
            aluno_id = request.form['aluno']
            disciplina_id = request.form['disciplina']
            nota = request.form['nota']
            frequencia = request.form.get('frequencia', 0)  # Frequência padrão é 0

            if not aluno_id or not disciplina_id or not nota:
                flash('Por favor, preencha todos os campos.', 'error')
            else:
                # Verificar se o aluno já tem uma nota na disciplina
                cursor.execute("SELECT * FROM grades WHERE student_id = ? AND discipline_id = ?", 
                               (aluno_id, disciplina_id))
                if cursor.fetchone():
                    # Atualizar a nota e frequência existente
                    cursor.execute("""
                        UPDATE grades
                        SET grade = ?, frequency = ?
                        WHERE student_id = ? AND discipline_id = ?
                    """, (nota, frequencia, aluno_id, disciplina_id))
                else:
                    # Inserir uma nova nota e frequência
                    cursor.execute("""
                        INSERT INTO grades (student_id, discipline_id, grade, frequency)
                        VALUES (?, ?, ?, ?)
                    """, (aluno_id, disciplina_id, nota, frequencia))
                
                conn.commit()
                flash('Nota e frequência atribuídas com sucesso!', 'success')

        # Enviar mensagem para alunos
        if request.method == 'POST' and 'assunto' in request.form:
            assunto = request.form['assunto']
            mensagem = request.form['mensagem']
            aluno_id = request.form.get('aluno')  # ID do aluno (opcional, pode ser para todos)

            if not assunto or not mensagem:
                flash('Por favor, preencha todos os campos.', 'error')
            else:
                if aluno_id:  # Se um aluno específico foi selecionado
                    print(f"Enviando mensagem para aluno {aluno_id}: assunto={assunto}, mensagem={mensagem}")
                    cursor.execute("INSERT INTO messages (student_id, assunto, mensagem) VALUES (?, ?, ?)", 
                                   (aluno_id, assunto, mensagem))
                else:  # Se a mensagem é para todos os alunos
                    cursor.execute("SELECT id FROM users WHERE role = 'student'")
                    alunos = cursor.fetchall()
                    for aluno in alunos:
                        print(f"Enviando mensagem para aluno {aluno['id']}: assunto={assunto}, mensagem={mensagem}")
                        cursor.execute("INSERT INTO messages (student_id, assunto, mensagem) VALUES (?, ?, ?)", 
                                       (aluno['id'], assunto, mensagem))
                conn.commit()
                flash('Mensagem enviada com sucesso!', 'success')

    return render_template('admin_dashboard.html', users=users, disciplines=disciplines, teachers=teachers, students=students, grades_dict=grades_dict)

# Rota para editar usuário
@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if current_user.role != 'admin':  # Apenas administradores podem editar usuários
        return redirect(url_for('home'))

    with get_db_connection() as conn:
        cursor = conn.cursor()

        if request.method == 'GET':
            # Buscar o usuário pelo ID
            cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
            user = cursor.fetchone()

            if user:
                return render_template('edit_user.html', user=user)
            else:
                flash('Usuário não encontrado.', 'error')
                return redirect(url_for('admin_dashboard'))

        if request.method == 'POST':
            # Atualizar o usuário
            username = request.form['username']
            password = request.form['password']
            role = request.form['role']

            if username and password and role:
                hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

                cursor.execute("""
                    UPDATE users
                    SET username = ?, password = ?, role = ?
                    WHERE id = ?
                """, (username, hashed_password, role, user_id))
                conn.commit()

                flash('Usuário atualizado com sucesso!', 'success')
                return redirect(url_for('admin_dashboard'))
            else:
                flash('Por favor, preencha todos os campos.', 'error')

    return redirect(url_for('admin_dashboard'))

# Rota para excluir usuário
@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.role != 'admin':  # Apenas administradores podem excluir usuários
        return redirect(url_for('home'))

    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Verificar se o usuário existe
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()

        if not user:
            flash('Usuário não encontrado.', 'error')
            return redirect(url_for('admin_dashboard'))

        # Excluir o usuário
        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()

    flash('Usuário excluído com sucesso!', 'success')
    return redirect(url_for('admin_dashboard'))

# Rota para excluir disciplina
@app.route('/delete_discipline/<int:discipline_id>', methods=['POST'])
@login_required
def delete_discipline(discipline_id):
    if current_user.role != 'admin':  # Apenas administradores podem excluir disciplinas
        return redirect(url_for('home'))

    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Verificar se a disciplina existe
        cursor.execute("SELECT * FROM disciplines WHERE id = ?", (discipline_id,))
        discipline = cursor.fetchone()

        if not discipline:
            flash('Disciplina não encontrada.', 'error')
            return redirect(url_for('admin_dashboard'))

        # Excluir a disciplina
        cursor.execute("DELETE FROM disciplines WHERE id = ?", (discipline_id,))
        conn.commit()

    flash('Disciplina excluída com sucesso!', 'success')
    return redirect(url_for('admin_dashboard'))

# Função para configurar o banco de dados
def setup():
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Cria a tabela users
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                            id INTEGER PRIMARY KEY, 
                            username TEXT UNIQUE, 
                            password TEXT, 
                            role TEXT)''')
        
        # Cria a tabela disciplines
        cursor.execute('''CREATE TABLE IF NOT EXISTS disciplines (
                            id INTEGER PRIMARY KEY, 
                            name TEXT UNIQUE)''')
        
        # Cria a tabela professor_discipline
        cursor.execute('''CREATE TABLE IF NOT EXISTS professor_discipline (
                            user_id INTEGER, 
                            discipline_id INTEGER, 
                            FOREIGN KEY (user_id) REFERENCES users(id), 
                            FOREIGN KEY (discipline_id) REFERENCES disciplines(id))''')
        
        # Cria a tabela grades
        cursor.execute('''CREATE TABLE IF NOT EXISTS grades (
                            id INTEGER PRIMARY KEY, 
                            student_id INTEGER, 
                            discipline_id INTEGER, 
                            grade TEXT,
                            frequency REAL,  -- Coluna adicionada
                            FOREIGN KEY (student_id) REFERENCES users(id),
                            FOREIGN KEY (discipline_id) REFERENCES disciplines(id))''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS content (
                            id INTEGER PRIMARY KEY, 
                            professor_id INTEGER, 
                            discipline_id INTEGER, 
                            content TEXT,
                            FOREIGN KEY (professor_id) REFERENCES users(id),
                            FOREIGN KEY (discipline_id) REFERENCES disciplines(id))''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS messages (
                            id INTEGER PRIMARY KEY, 
                            student_id INTEGER, 
                            assunto TEXT, 
                            mensagem TEXT,
                            FOREIGN KEY (student_id) REFERENCES users(id))''')

        admin_username = 'admin'
        admin_password = generate_password_hash('admin_password') 
        cursor.execute("SELECT * FROM users WHERE username = ?", (admin_username,))
        admin_user = cursor.fetchone()

        if not admin_user:
            cursor.execute("""
                INSERT INTO users (username, password, role)
                VALUES (?, ?, ?)
            """, (admin_username, admin_password, 'admin'))
            conn.commit()
            print("Usuário administrador padrão criado: admin / admin123")

if __name__ == '__main__':
    setup()
    app.run(debug=True)








