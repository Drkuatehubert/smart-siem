FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir redis elasticsearch
COPY . .
CMD ["python", "main.py"]
