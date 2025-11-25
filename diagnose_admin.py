import os
import django
import json
import traceback

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'backend.settings')
django.setup()

from tickets.models import Ticket
from tickets.serializers import TicketAdminSerializer

qs = Ticket.objects.all()
print('TICKET_COUNT', qs.count())
if not qs.exists():
    print('NO TICKETS')
else:
    t = qs.first()
    try:
        s = TicketAdminSerializer(t)
        print(json.dumps(s.data, default=str))
    except Exception as e:
        print('ERROR:', str(e))
        traceback.print_exc()
