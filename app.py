from flask import Flask, request, render_template_string, send_file, jsonify
import sqlite3
import os

app = Flask(__name__)

# Page d'accueil HTML
HOME_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>Bibliothèque en ligne</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
        .container { background: #f4f4f4; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        input, button { padding: 10px; margin: 5px; }
        button { background: #007bff; color: white; border: none; cursor: pointer; }
        button:hover { background: #0056b3; }
        .book { background: white; padding: 15px; margin: 10px 0; border-left: 4px solid #007bff; }
        .error { color: red; }
        .success { color: green; }
    </style>
</head>
<body>
    <h1>📚 Bibliothèque Numérique</h1>

    <div class="container">
        <h2>Connexion</h2>
        <form action="/login" method="POST">
            <input type="text" name="username" placeholder="Nom d'utilisateur" required>
            <input type="password" name="password" placeholder="Mot de passe" required>
            <button type="submit">Se connecter</button>
        </form>
    </div>

    <div class="container">
        <h2>Rechercher un livre</h2>
        <form action="/search" method="GET">
            <input type="text" name="query" placeholder="Titre du livre">
            <button type="submit">Rechercher</button>
        </form>
    </div>

    <div class="container">
        <h2>Télécharger un fichier</h2>
        <form action="/download" method="GET">
            <input type="text" name="file" placeholder="Nom du fichier (ex: book1.pdf)">
            <button type="submit">Télécharger</button>
        </form>
    </div>
</body>
</html>
"""

# Initialisation de la base de données
def init_db():
    conn = sqlite3.connect('library.db')
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS books (
            id INTEGER PRIMARY KEY,
            title TEXT NOT NULL,
            author TEXT NOT NULL,
            year INTEGER
        )
    ''')

    # Ajout d'utilisateurs de test
    cursor.execute("DELETE FROM users")
    cursor.execute("INSERT INTO users (username, password, role) VALUES ('admin', 'admin123', 'admin')")
    cursor.execute("INSERT INTO users (username, password, role) VALUES ('user', 'user123', 'user')")

    # Ajout de livres de test
    cursor.execute("DELETE FROM books")
    cursor.execute("INSERT INTO books (title, author, year) VALUES ('Python pour les nuls', 'Jean Dupont', 2020)")
    cursor.execute("INSERT INTO books (title, author, year) VALUES ('Sécurité informatique', 'Marie Martin', 2021)")
    cursor.execute("INSERT INTO books (title, author, year) VALUES ('Développement web', 'Paul Bernard', 2022)")

    conn.commit()
    conn.close()

@app.route('/')
def home():
    return HOME_PAGE

# VULNÉRABILITÉ 1: SQL Injection
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    conn = sqlite3.connect('library.db')
    cursor = conn.cursor()

    # VULNERABLE: Concaténation directe dans la requête SQL
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    print(f"[DEBUG] Executing query: {query}")

    try:
        cursor.execute(query)
        user = cursor.fetchone()
        conn.close()

        if user:
            return f"""
            <html><body>
                <h1>Connexion réussie!</h1>
                <p>Bienvenue {user[1]} (Rôle: {user[3]})</p>
                <a href="/">Retour</a>
            </body></html>
            """
        else:
            return """
            <html><body>
                <h1>Échec de connexion</h1>
                <p>Identifiants incorrects</p>
                <a href="/">Retour</a>
            </body></html>
            """
    except Exception as e:
        return f"<html><body><h1>Erreur SQL</h1><p>{str(e)}</p><a href='/'>Retour</a></body></html>"

# VULNÉRABILITÉ 2: Path Traversal
@app.route('/download')
def download():
    filename = request.args.get('file', '')

    # VULNERABLE: Pas de validation du chemin
    file_path = os.path.join('files', filename)
    print(f"[DEBUG] Attempting to access: {file_path}")

    try:
        if os.path.exists(file_path):
            return send_file(file_path)
        else:
            return f"""
            <html><body>
                <h1>Fichier non trouvé</h1>
                <p>Le fichier '{filename}' n'existe pas</p>
                <a href="/">Retour</a>
            </body></html>
            """
    except Exception as e:
        return f"<html><body><h1>Erreur</h1><p>{str(e)}</p><a href='/'>Retour</a></body></html>"

# VULNÉRABILITÉ 3: SQL Injection dans la recherche
@app.route('/search')
def search():
    query = request.args.get('query', '')

    conn = sqlite3.connect('library.db')
    cursor = conn.cursor()

    # VULNERABLE: Concaténation directe
    sql = f"SELECT * FROM books WHERE title LIKE '%{query}%' OR author LIKE '%{query}%'"
    print(f"[DEBUG] Search query: {sql}")

    try:
        cursor.execute(sql)
        books = cursor.fetchall()
        conn.close()

        result_html = "<html><body><h1>Résultats de recherche</h1>"
        if books:
            for book in books:
                result_html += f"<div class='book'><h3>{book[1]}</h3><p>Auteur: {book[2]} | Année: {book[3]}</p></div>"
        else:
            result_html += "<p>Aucun livre trouvé</p>"
        result_html += "<br><a href='/'>Retour</a></body></html>"

        return result_html
    except Exception as e:
        return f"<html><body><h1>Erreur</h1><p>{str(e)}</p><a href='/'>Retour</a></body></html>"

# Endpoint de santé pour les tests
@app.route('/health')
def health():
    return jsonify({"status": "healthy", "app": "library"}), 200

if __name__ == '__main__':
    # Créer le dossier files s'il n'existe pas
    os.makedirs('files', exist_ok=True)

    # Créer quelques fichiers de test
    with open('files/book1.pdf', 'w') as f:
        f.write('Contenu du livre 1')
    with open('files/book2.pdf', 'w') as f:
        f.write('Contenu du livre 2')

    # Initialiser la base de données
    init_db()

    app.run(debug=True, host='0.0.0.0', port=5000)
