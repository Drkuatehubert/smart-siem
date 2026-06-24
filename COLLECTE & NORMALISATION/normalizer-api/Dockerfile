FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
COPY http_ca.crt .
EXPOSE 443
CMD ["python", "app.py"]