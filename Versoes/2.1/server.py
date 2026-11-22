from flask import Flask, jsonify, render_template, request, redirect, url_for, make_response
import sqlite3
import os
import base64
import json
import secrets
from cryptography.exceptions import InvalidKey, InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

app = Flask(__name__)


def gerar_hash_senha(senha):
    salt = os.urandom(16)
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    digest = kdf.derive(senha.encode('utf-8'))
    # Base64 do salt (16 bytes) seguido do digest (32 bytes).
    return base64.b64encode(salt + digest).decode('ascii')


def verificar_senha(senha, senha_salva):
    try:
        dados = base64.b64decode(senha_salva, validate=True)
    except (ValueError, TypeError):
        return False

    if len(dados) != 48:
        return False

    salt, digest = dados[:16], dados[16:]
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    try:
        kdf.verify(senha.encode('utf-8'), digest)
        return True
    except InvalidKey:
        return False


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
    conn.execute('''
        CREATE TABLE IF NOT EXISTS sessoes (
            id_sessao TEXT PRIMARY KEY,
            usuario_id INTEGER NOT NULL,
            FOREIGN KEY (usuario_id) REFERENCES clientes (id)
        )
    ''')
    return conn


def criar_sessao(usuario_id, resposta=None):
    id_sessao = secrets.token_urlsafe(32)
    conn = conectar_banco()
    # Revoga a sessão atual deste navegador ao autenticar novamente.
    sessao_anterior = request.cookies.get('session_id')
    if sessao_anterior:
        conn.execute('DELETE FROM sessoes WHERE id_sessao = ?', (sessao_anterior,))
    conn.execute(
        'INSERT INTO sessoes (id_sessao, usuario_id) VALUES (?, ?)',
        (id_sessao, usuario_id)
    )
    conn.commit()
    conn.close()

    if resposta is None:
        resposta = make_response(redirect(url_for('pagina_usuario')))
    resposta.set_cookie(
        'session_id', id_sessao, httponly=True,
        secure=request.is_secure, samesite='Lax'
    )
    return resposta


def autenticar_usuario(email, senha):
    conn = conectar_banco()
    usuario = conn.execute(
        'SELECT id, senha_usuario FROM clientes WHERE email_usuario = ?',
        (email.strip(),)
    ).fetchone()
    conn.close()
    if usuario is None or not verificar_senha(senha, usuario['senha_usuario']):
        return None
    return usuario['id']

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
    if not nome_usuario or not email_usuario or not senha_usuario:
        return 'Preencha nome, e-mail e senha.', 400

    conn = conectar_banco()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO clientes (nome_usuario, email_usuario, senha_usuario) VALUES (?, ?, ?)",
        (nome_usuario, email_usuario, gerar_hash_senha(senha_usuario))
    )
    usuario_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return criar_sessao(usuario_id)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        senha = request.form.get('password', '')
        usuario_id = autenticar_usuario(email, senha)
        if usuario_id is None:
            return 'E-mail ou senha incorretos.', 401
        return criar_sessao(usuario_id)
    else:
        return redirect(url_for('home'))


@app.route('/api/login', methods=['POST'])
def api_login():
    try:
        chaves = base64.b64decode(request.form['session_keys'], validate=True)
        ciphertext = base64.b64decode(request.form['ciphertext'], validate=True)
        tag = base64.b64decode(request.form['hmac'], validate=True)
    except (KeyError, ValueError, TypeError):
        return jsonify(erro='Requisição inválida.'), 400

    if len(chaves) != 80 or len(tag) != 32:
        return jsonify(erro='Requisição inválida.'), 400

    aes_key = chaves[:32]
    mac_key = chaves[32:64]
    iv = chaves[64:80]

    # A integridade do texto cifrado é verificada antes da descriptografia.
    verificador = crypto_hmac.HMAC(mac_key, hashes.SHA256())
    verificador.update(ciphertext)
    try:
        verificador.verify(tag)
    except InvalidSignature:
        return jsonify(erro='HMAC inválido.'), 400

    try:
        decryptor = Cipher(algorithms.AES(aes_key), modes.CTR(iv)).decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        credenciais = json.loads(plaintext.decode('utf-8'))
        email = credenciais['email']
        senha = credenciais['password']
        if not isinstance(email, str) or not isinstance(senha, str):
            raise ValueError('Credenciais inválidas')
    except (KeyError, TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return jsonify(erro='Dados de login inválidos.'), 400

    usuario_id = autenticar_usuario(email, senha)
    if usuario_id is None:
        return jsonify(erro='E-mail ou senha incorretos.'), 401

    resposta = make_response(jsonify(mensagem='Login realizado com sucesso.'), 200)
    return criar_sessao(usuario_id, resposta=resposta)


@app.route('/usuario')
def pagina_usuario():
    id_sessao = request.cookies.get('session_id')
    if not id_sessao:
        return redirect(url_for('home'))
    conn = conectar_banco()
    usuario = conn.execute(
        '''SELECT clientes.nome_usuario
           FROM sessoes
           JOIN clientes ON clientes.id = sessoes.usuario_id
           WHERE sessoes.id_sessao = ?''',
        (id_sessao,)
    ).fetchone()
    conn.close()
    if usuario is None:
        return redirect(url_for('home'))
    return render_template('usuario.html', nome=usuario['nome_usuario'])

@app.route('/delete-cookie')
def delete_cookie():
    id_sessao = request.cookies.get('session_id')
    conn = conectar_banco()
    if id_sessao:
        conn.execute('DELETE FROM sessoes WHERE id_sessao = ?', (id_sessao,))
        conn.commit()
    conn.close()
    resposta = make_response(redirect(url_for('home')))
    resposta.delete_cookie('session_id')
    return resposta

if __name__ == "__main__":
    app.run(debug=True)

