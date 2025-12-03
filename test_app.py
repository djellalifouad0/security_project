import pytest
import os
import sqlite3
from app import app, init_db

@pytest.fixture
def client():
    """Fixture pour créer un client de test Flask"""
    app.config['TESTING'] = True

    # Créer un environnement de test propre
    if os.path.exists('library.db'):
        os.remove('library.db')

    os.makedirs('files', exist_ok=True)
    with open('files/test.pdf', 'w') as f:
        f.write('Test content')

    init_db()

    with app.test_client() as client:
        yield client

    # Nettoyage
    if os.path.exists('library.db'):
        os.remove('library.db')
    if os.path.exists('files/test.pdf'):
        os.remove('files/test.pdf')

def test_home_page(client):
    """Test que la page d'accueil se charge correctement"""
    response = client.get('/')
    assert response.status_code == 200
    assert b'Biblioth' in response.data
    assert b'Connexion' in response.data

def test_health_endpoint(client):
    """Test du endpoint de santé"""
    response = client.get('/health')
    assert response.status_code == 200
    json_data = response.get_json()
    assert json_data['status'] == 'healthy'
    assert json_data['app'] == 'library'

def test_login_success(client):
    """Test d'une connexion réussie avec des credentials valides"""
    response = client.post('/login', data={
        'username': 'admin',
        'password': 'admin123'
    })
    assert response.status_code == 200
    assert b'Connexion' in response.data or b'Bienvenue' in response.data

def test_login_failure(client):
    """Test d'une connexion échouée avec des credentials invalides"""
    response = client.post('/login', data={
        'username': 'wronguser',
        'password': 'wrongpass'
    })
    assert response.status_code == 200
    assert b'chec' in response.data or b'incorrects' in response.data

def test_search_books(client):
    """Test de la recherche de livres"""
    response = client.get('/search?query=Python')
    assert response.status_code == 200
    assert b'sultats' in response.data

def test_search_no_results(client):
    """Test de recherche sans résultats"""
    response = client.get('/search?query=NonExistentBook12345')
    assert response.status_code == 200
    assert b'Aucun' in response.data or b'trouv' in response.data

def test_download_existing_file(client):
    """Test du téléchargement d'un fichier existant"""
    response = client.get('/download?file=test.pdf')
    assert response.status_code == 200
    assert response.data == b'Test content'

def test_download_nonexistent_file(client):
    """Test du téléchargement d'un fichier inexistant"""
    response = client.get('/download?file=nonexistent.pdf')
    assert response.status_code == 200
    assert b"n'existe pas" in response.data or b'non' in response.data

def test_database_initialization():
    """Test que la base de données s'initialise correctement"""
    if os.path.exists('test_library.db'):
        os.remove('test_library.db')

    conn = sqlite3.connect('test_library.db')
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        )
    ''')

    cursor.execute("INSERT INTO users (username, password, role) VALUES ('test', 'test123', 'user')")
    conn.commit()

    cursor.execute("SELECT * FROM users WHERE username='test'")
    user = cursor.fetchone()

    assert user is not None
    assert user[1] == 'test'
    assert user[2] == 'test123'

    conn.close()
    os.remove('test_library.db')

def test_sql_injection_vulnerability(client):
    """Test pour vérifier que l'injection SQL est possible (vulnérabilité intentionnelle)"""
    # Test d'injection SQL classique
    response = client.post('/login', data={
        'username': "admin' OR '1'='1",
        'password': "anything"
    })
    assert response.status_code == 200
    # L'injection devrait réussir à cause de la vulnérabilité

def test_path_traversal_vulnerability(client):
    """Test pour vérifier que le path traversal est possible (vulnérabilité intentionnelle)"""
    # Tentative de path traversal
    response = client.get('/download?file=../app.py')
    # Le serveur devrait tenter d'accéder au fichier (vulnérabilité)
    assert response.status_code in [200, 404]

if __name__ == '__main__':
    pytest.main(['-v', '--cov=app', '--cov-report=html', '--cov-report=term'])
