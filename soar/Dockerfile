# Build context attendu : racine du projet (docker compose up depuis la racine)
# Cela permet aux imports "from soar import config" de fonctionner correctement.
FROM python:3.11-slim
WORKDIR /app
COPY soar/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY soar/ ./soar/
CMD ["python", "-m", "soar.worker"]
