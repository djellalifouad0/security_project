# Stage 1: Builder
FROM python:3.11-slim as builder

WORKDIR /app

# Installer les dépendances de build
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copier uniquement requirements.txt pour profiter du cache Docker
COPY requirements.txt .

# Installer les dépendances Python
RUN pip install --no-cache-dir --user -r requirements.txt

# Stage 2: Runtime
FROM python:3.11-slim

WORKDIR /app

# Créer un utilisateur non-root pour la sécurité
RUN useradd -m -u 1000 appuser && \
    chown -R appuser:appuser /app

# Copier les dépendances Python depuis le builder
COPY --from=builder /root/.local /home/appuser/.local

# Copier le code de l'application
COPY --chown=appuser:appuser app.py .

# Créer les dossiers nécessaires
RUN mkdir -p files && chown -R appuser:appuser files

# Passer à l'utilisateur non-root
USER appuser

# Ajouter les binaires Python au PATH
ENV PATH=/home/appuser/.local/bin:$PATH

# Exposer le port de l'application
EXPOSE 5000

# Variable d'environnement pour Flask
ENV FLASK_APP=app.py
ENV PYTHONUNBUFFERED=1

# Healthcheck pour Docker
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:5000/health')" || exit 1

# Commande de démarrage
CMD ["python", "app.py"]
