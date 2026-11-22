from flask import Flask, render_template, request, redirect, url_for
import sqlite3

app = Flask(__name__)

@app.route("/", methods=["GET"])
def home():

    return render_template("index.html")

@app.route("/enviar", methods=["POST"])
def enviar_dados():
    
    nome_usuario = request.form.get("name")
    email_usuario = request.form.get("email")
    senha_usuario = request.form.get("password")

    conn = sqlite3.connect('usuarios.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS clientes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome_usuario TEXT NOT NULL,
            email_usuario TEXT NOT NULL,
            senha_usuario TEXT NOT NULL
        )
    ''')
    

    cursor.execute("INSERT INTO clientes (nome_usuario, email_usuario, senha_usuario) VALUES (?, ?, ?)", (nome_usuario, email_usuario, senha_usuario))
    
    conn.commit()
    conn.close()
    return "Dados salvos com sucesso no banco de dados!"

if __name__ == "__main__":
    app.run(debug=True)

