"""
Version SÉCURISÉE de l'application Bibliothèque
Corrections de toutes les vulnérabilités identifiées
"""

from flask import Flask, request, render_template_string, send_file, jsonify, abort
import sqlite3
import os
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import logging
from functools import wraps
import time

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'change-me-in-production')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max

# Configuration des logs
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Rate limiting simple (en production, utiliser Flask-Limiter)
login_attempts = {}

def rate_limit(max_attempts=5, window=60):
    """Décorateur pour limiter les tentatives de connexion"""
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            ip = request.remote_addr
            now = time.time()

            if ip not in login_attempts:
                login_attempts[ip] = []

            # Nettoyer les anciennes tentatives
            login_attempts[ip] = [t for t in login_attempts[ip] if now - t < window]

            if len(login_attempts[ip]) >= max_attempts:
                logger.warning(f"Rate limit exceeded for IP: {ip}")
                return jsonify({"error": "Trop de tentatives. Réessayez plus tard."}), 429

            login_attempts[ip].append(now)
            return f(*args, **kwargs)
        return wrapped
    return decorator

# Page d'accueil HTML (identique)
HOME_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>Bibliothèque en ligne - Sécurisée</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
        .container { background: #f4f4f4; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        input, button { padding: 10px; margin: 5px; }
        button { background: #28a745; color: white; border: none; cursor: pointer; }
        button:hover { background: #218838; }
        .book { background: white; padding: 15px; margin: 10px 0; border-left: 4px solid #28a745; }
        .badge { background: #28a745; color: white; padding: 5px 10px; border-radius: 3px; }
    </style>
</head>
<body>
    <h1>📚 Bibliothèque Numérique <span class="badge">Version Sécurisée</span></h1>

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
            <input type="text" name="query" placeholder="Titre du livre" maxlength="100">
            <button type="submit">Rechercher</button>
        </form>
    </div>

    <div class="container">
        <h2>Télécharger un fichier</h2>
        <form action="/download" method="GET">
            <input type="text" name="file" placeholder="Nom du fichier (ex: book1.pdf)" maxlength="100">
            <button type="submit">Télécharger</button>
        </form>
    </div>
</body>
</html>
"""

def get_db():
    """Obtenir une connexion à la base de données"""
    conn = sqlite3.connect('library_secure.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialisation sécurisée de la base de données"""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
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

    # Vérifier si les utilisateurs existent déjà
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        # Utiliser des mots de passe hashés
        admin_pass = generate_password_hash('admin123')
        user_pass = generate_password_hash('user123')

        cursor.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            ('admin', admin_pass, 'admin')
        )
        cursor.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            ('user', user_pass, 'user')
        )

    # Vérifier si les livres existent déjà
    cursor.execute("SELECT COUNT(*) FROM books")
    if cursor.fetchone()[0] == 0:
        books = [
            ('Python pour les nuls', 'Jean Dupont', 2020),
            ('Sécurité informatique', 'Marie Martin', 2021),
            ('Développement web', 'Paul Bernard', 2022)
        ]
        cursor.executemany(
            "INSERT INTO books (title, author, year) VALUES (?, ?, ?)",
            books
        )

    conn.commit()
    conn.close()

@app.route('/')
def home():
    return HOME_PAGE

@app.route('/login', methods=['POST'])
@rate_limit(max_attempts=5, window=300)  # 5 tentatives par 5 minutes
def login():
    """Authentification sécurisée avec requêtes paramétrées"""
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')

    # Validation basique
    if not username or not password:
        return jsonify({"error": "Nom d'utilisateur et mot de passe requis"}), 400

    if len(username) > 50:
        return jsonify({"error": "Nom d'utilisateur trop long"}), 400

    try:
        conn = get_db()
        cursor = conn.cursor()

        # SÉCURISÉ : Utilisation de requêtes paramétrées
        cursor.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        )
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password):
            logger.info(f"Successful login for user: {username}")
            return f"""
            <html><body>
                <h1>Connexion réussie!</h1>
                <p>Bienvenue {user['username']} (Rôle: {user['role']})</p>
                <a href="/">Retour</a>
            </body></html>
            """
        else:
            logger.warning(f"Failed login attempt for user: {username}")
            return """
            <html><body>
                <h1>Échec de connexion</h1>
                <p>Identifiants incorrects</p>
                <a href="/">Retour</a>
            </body></html>
            """, 401

    except Exception as e:
        logger.error(f"Database error in login: {str(e)}")
        return jsonify({"error": "Une erreur est survenue"}), 500

@app.route('/download')
def download():
    """Téléchargement sécurisé avec validation du chemin"""
    filename = request.args.get('file', '')

    if not filename:
        return jsonify({"error": "Nom de fichier requis"}), 400

    # SÉCURISÉ : Utilisation de secure_filename
    safe_filename = secure_filename(filename)

    if not safe_filename:
        return jsonify({"error": "Nom de fichier invalide"}), 400

    # Définir le répertoire de base sécurisé
    base_dir = os.path.abspath('files')
    file_path = os.path.abspath(os.path.join(base_dir, safe_filename))

    # SÉCURISÉ : Vérifier que le chemin résolu est bien dans le dossier autorisé
    if not file_path.startswith(base_dir + os.sep):
        logger.warning(f"Path traversal attempt detected: {filename}")
        abort(403)

    try:
        if os.path.exists(file_path) and os.path.isfile(file_path):
            logger.info(f"File downloaded: {safe_filename}")
            return send_file(file_path)
        else:
            return f"""
            <html><body>
                <h1>Fichier non trouvé</h1>
                <p>Le fichier '{safe_filename}' n'existe pas</p>
                <a href="/">Retour</a>
            </body></html>
            """, 404

    except Exception as e:
        logger.error(f"Error serving file {safe_filename}: {str(e)}")
        return jsonify({"error": "Erreur lors du téléchargement"}), 500

@app.route('/search')
def search():
    """Recherche sécurisée avec requêtes paramétrées"""
    query = request.args.get('query', '').strip()

    if len(query) > 100:
        return jsonify({"error": "Requête trop longue"}), 400

    try:
        conn = get_db()
        cursor = conn.cursor()

        # SÉCURISÉ : Utilisation de requêtes paramétrées avec LIKE
        search_pattern = f"%{query}%"
        cursor.execute(
            "SELECT * FROM books WHERE title LIKE ? OR author LIKE ?",
            (search_pattern, search_pattern)
        )
        books = cursor.fetchall()
        conn.close()

        result_html = "<html><body><h1>Résultats de recherche</h1>"
        if books:
            for book in books:
                # Échapper les données pour éviter XSS
                title = book['title'].replace('<', '&lt;').replace('>', '&gt;')
                author = book['author'].replace('<', '&lt;').replace('>', '&gt;')
                result_html += f"<div class='book'><h3>{title}</h3><p>Auteur: {author} | Année: {book['year']}</p></div>"
        else:
            result_html += "<p>Aucun livre trouvé</p>"
        result_html += "<br><a href='/'>Retour</a></body></html>"

        logger.info(f"Search performed: {query}, results: {len(books)}")
        return result_html

    except Exception as e:
        logger.error(f"Search error: {str(e)}")
        return jsonify({"error": "Erreur lors de la recherche"}), 500

@app.route('/health')
def health():
    """Endpoint de santé pour les tests"""
    return jsonify({
        "status": "healthy",
        "app": "library-secure",
        "version": "2.0"
    }), 200

@app.errorhandler(403)
def forbidden(e):
    return jsonify({"error": "Accès interdit"}), 403

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Ressource non trouvée"}), 404

@app.errorhandler(500)
def internal_error(e):
    return jsonify({"error": "Erreur interne du serveur"}), 500

if __name__ == '__main__':
    # Créer le dossier files s'il n'existe pas
    os.makedirs('files', exist_ok=True)

    # Créer quelques fichiers de test
    test_files = ['book1.pdf', 'book2.pdf', 'book3.pdf']
    for filename in test_files:
        filepath = os.path.join('files', filename)
        if not os.path.exists(filepath):
            with open(filepath, 'w') as f:
                f.write(f'Contenu de {filename}')

    # Initialiser la base de données
    init_db()

    # SÉCURISÉ : Debug désactivé, utiliser des variables d'environnement en production
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'

    app.run(
        debug=debug_mode,
        host='0.0.0.0',
        port=5000
    )
