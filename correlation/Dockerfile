FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir elasticsearch
COPY . .
CMD ["python", "engine.py"]
