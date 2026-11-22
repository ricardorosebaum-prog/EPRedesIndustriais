from flask import Flask, render_template, request, redirect, url_for, make_response, session
import sqlite3
import os

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "chave-de-desenvolvimento-troque-isto")


def conectar_banco():
    conn = sqlite3.connect('usuarios.db')
    conn.row_factory = sqlite3.Row
    conn.execute('''
        CREATE TABLE IF NOT EXISTS clientes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome_usuario TEXT NOT NULL,
            email_usuario TEXT NOT NULL,
            senha_usuario TEXT NOT NULL
        )
    ''')
    return conn

@app.route("/", methods=["GET"])
def home():

    return render_template("index.html")


@app.route("/register")
def register():
    return render_template("Register.html")

@app.route("/enviar", methods=["POST"])
def enviar_dados():
    
    nome_usuario = request.form.get("name")
    email_usuario = request.form.get("email")
    senha_usuario = request.form.get("password")

    conn = conectar_banco()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO clientes (nome_usuario, email_usuario, senha_usuario) VALUES (?, ?, ?)", (nome_usuario, email_usuario, senha_usuario))
    usuario_id = cursor.lastrowid
    conn.commit()
    conn.close()
    session['usuario_id'] = usuario_id
    return redirect(url_for('pagina_usuario'))

@app.route('/fake-login', methods=['GET', 'POST'])
def fake_login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        senha = request.form.get('password', '')
        conn = conectar_banco()
        usuario = conn.execute(
            'SELECT id FROM clientes WHERE email_usuario = ? AND senha_usuario = ?',
            (email, senha)
        ).fetchone()
        conn.close()
        if usuario is None:
            return 'E-mail ou senha incorretos.', 401
        session['usuario_id'] = usuario['id']
        return redirect(url_for('pagina_usuario'))
    else:
        return redirect(url_for('home'))


@app.route('/usuario')
def pagina_usuario():
    usuario_id = session.get('usuario_id')
    if usuario_id is None:
        return redirect(url_for('home'))
    conn = conectar_banco()
    usuario = conn.execute(
        'SELECT nome_usuario FROM clientes WHERE id = ?', (usuario_id,)
    ).fetchone()
    conn.close()
    if usuario is None:
        session.clear()
        return redirect(url_for('home'))
    return render_template('usuario.html', nome=usuario['nome_usuario'])

@app.route('/delete-cookie')
def delete_cookie():
    session.clear()
    return redirect(url_for('home'))

if __name__ == "__main__":
    app.run(debug=True)

