FROM python:3.12-slim

WORKDIR /app

RUN pip install fastapi uvicorn motor pymongo PyJWT

COPY server.py .
COPY index.html .

EXPOSE 8080

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8080"]
