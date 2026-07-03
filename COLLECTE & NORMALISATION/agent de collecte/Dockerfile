FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY agentU.py .

# En déploiement réel, cet agent tourne directement sur les machines à
# surveiller (voir agentU.py / agentW.py). Ce conteneur sert de démonstration :
# il ne verra que les logs montés en volume (/var/log de l'hôte, en lecture
# seule) — voir docker-compose.yml.
CMD ["python", "agentU.py"]
