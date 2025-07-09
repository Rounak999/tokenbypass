FROM python:3.11-slim

WORKDIR /app

# Install openssl for certs
RUN apt-get update && apt-get install -y openssl && apt-get clean

COPY . /app

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8000

CMD ["python", "app.py"]
