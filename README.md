# Ticketing Backend

Simple Django + DRF backend for ticketing used by the React Native app.

Quick start

- create a virtualenv and install requirements:

  python -m venv .venv; .\.venv\Scripts\Activate.ps1; pip install -r requirements.txt

- run migrations and create superuser:

  python manage.py migrate; python manage.py createsuperuser

- run server:

  python manage.py runserver

API endpoints

- POST /api/tickets/create/  -> create ticket. Required body: first_name, last_name, title, description. Returns ticket object with uid.
  - This endpoint now requires at least one file under the multipart field name `attachments`. Use multipart/form-data.
- GET /api/tickets/ -> list tickets
- GET /api/tickets/<uid>/ -> ticket detail with messages
- POST /api/messages/create/ -> create message. Provide ticket (id) or ticket_uid, sender, content.

Example curl to create ticket with two attachments:

  curl -X POST http://127.0.0.1:8000/api/tickets/create/ \
    -F first_name=John -F last_name=Doe -F title="Problem" -F description="Desc" \
    -F "attachments=@/path/to/file1.pdf" -F "attachments=@/path/to/file2.png"

Examples (curl)

Create ticket:

  curl -X POST http://127.0.0.1:8000/api/tickets/create/ -H "Content-Type: application/json" -d "{\"first_name\":\"John\",\"last_name\":\"Doe\",\"title\":\"Login issue\",\"description\":\"Can't login\"}"

Get ticket:

  curl http://127.0.0.1:8000/api/tickets/<uid>/

Post message:

  curl -X POST http://127.0.0.1:8000/api/messages/create/ -H "Content-Type: application/json" -d "{\"ticket_uid\":\"<uid>\",\"sender\":\"admin\",\"content\":\"We received your ticket\"}"

