#!/bin/bash

mkdir -p logs

docker-compose up --force-recreate --build debug

