FROM python:3.11
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
COPY . /tests
WORKDIR /tests
ENV ENV=dev
RUN apt-get update -y && \
    apt-get upgrade -y && \
    pip install -r requirements.txt