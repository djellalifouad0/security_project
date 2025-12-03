.PHONY: help install test run run-secure docker-build docker-run docker-scan exploit clean

help:
	@echo "Commandes disponibles:"
	@echo "  make install       - Installer les dépendances"
	@echo "  make test          - Exécuter les tests"
	@echo "  make run           - Lancer l'application vulnérable"
	@echo "  make run-secure    - Lancer l'application sécurisée"
	@echo "  make docker-build  - Construire l'image Docker"
	@echo "  make docker-run    - Lancer les conteneurs Docker"
	@echo "  make docker-scan   - Scanner l'image avec Trivy"
	@echo "  make exploit       - Lancer le script d'exploitation"
	@echo "  make clean         - Nettoyer les fichiers générés"

install:
	pip install -r requirements.txt
	pip install colorama  # Pour le script exploit_demo.py

test:
	pytest test_app.py -v --cov=app --cov-report=html --cov-report=term

run:
	@echo "Démarrage de l'application VULNÉRABLE sur http://localhost:5000"
	python app.py

run-secure:
	@echo "Démarrage de l'application SÉCURISÉE sur http://localhost:5000"
	python app_secure.py

docker-build:
	docker build -t bibliotheque-app:latest .

docker-run:
	docker-compose up -d
	@echo "Application vulnérable: http://localhost:5000"
	@echo "Application sécurisée: http://localhost:5001"

docker-stop:
	docker-compose down

docker-scan:
	@echo "Scan Trivy de l'image Docker..."
	trivy image bibliotheque-app:latest

docker-scan-fs:
	@echo "Scan Trivy du filesystem..."
	trivy fs .

exploit:
	@echo "Lancement du script de démonstration d'exploitation..."
	@echo "Assurez-vous que l'application vulnérable tourne (make run)"
	python exploit_demo.py

clean:
	rm -rf __pycache__
	rm -rf .pytest_cache
	rm -rf htmlcov
	rm -f .coverage
	rm -f *.db
	rm -f files/*.pdf
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete

lint:
	flake8 app.py app_secure.py test_app.py --max-line-length=127

format:
	black app.py app_secure.py test_app.py

security-check:
	@echo "Vérification de sécurité avec bandit..."
	bandit -r . -ll

all: clean install test docker-build
