#!/bin/sh
python -c "from modules.db import init_db; init_db()"
exec gunicorn -w 4 -b 0.0.0.0:5000 app:app