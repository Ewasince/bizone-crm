FROM python:3.10-slim-buster

#
#RUN apt-get update \
#  && apt-get install -y curl \
#  && curl --version \
#  && apt-get clean autoclean \
#  && apt-get autoremove -y \
#  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# deps
COPY ./requirements.txt /app

RUN cd /app \
    && pip install -r requirements.txt
#
COPY . /app

#
RUN mkdir -p /app/logs
RUN mkdir -p /app/data




# rest port
#EXPOSE 7790

#
CMD chmod a+x ./run_in_docker.sh && /bin/sh ./run_in_docker.sh
