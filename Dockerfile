FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

COPY init_and_run.sh .
RUN chmod +x init_and_run.sh

EXPOSE 5000

CMD ["sh", "./init_and_run.sh"]
