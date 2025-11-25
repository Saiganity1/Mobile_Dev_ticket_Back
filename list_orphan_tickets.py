import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'backend.settings')
django.setup()

from tickets.models import Ticket

orphan = Ticket.objects.filter(user__isnull=True)
print('ORPHAN COUNT', orphan.count())
for t in orphan[:20]:
    print(t.id, t.uid, t.title, t.created_at)
