FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir elasticsearch weasyprint openpyxl apscheduler
COPY . .
CMD ["python", "scheduler.py"]
