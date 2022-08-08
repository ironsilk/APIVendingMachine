FROM python:3.10

LABEL Author="Mike"

RUN mkdir /app
WORKDIR /app

COPY / ./

RUN pip install -r requirements.txt

EXPOSE 4231

ENTRYPOINT ["python", "main.py"]