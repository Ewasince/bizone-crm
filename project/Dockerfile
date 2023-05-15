FROM python:3.11
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
WORKDIR /project/app
COPY . .
RUN apt-get update -y && \
    apt-get upgrade -y && \
    pip install -r requirements.txt
