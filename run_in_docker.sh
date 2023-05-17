#!/usr/bin/env sh
set -e
set -x

DIRECTORY=$(dirname $(readlink -e "$0"))
cd ${DIRECTORY}

#
#sleep 30

## external tool migrate DB
#cd ${DIRECTORY}/migrations
###alembic upgrade head
#python ./db_migrate.py upgrade head
## xxx

# run project
cd /app
export PYTHONPATH="$PWD"
python ./project/main.py
