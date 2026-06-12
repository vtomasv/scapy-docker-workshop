FROM python:3.12-slim

RUN pip install --no-cache-dir 'flask>=3,<4'

COPY app.py /app/app.py
WORKDIR /app

EXPOSE 8080

CMD ["python", "app.py"]
