FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Run seed on startup, then start uvicorn
CMD python -m jwt_rbac.seed && uvicorn jwt_rbac.main:app --host 0.0.0.0 --port 8000
