import os
import django
import sys

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'backend.settings')
django.setup()

from tickets.models import Ticket
from django.contrib.auth import get_user_model

User = get_user_model()

def assign_orphans(target_user_id=None, dry_run=True):
    orphans = Ticket.objects.filter(user__isnull=True)
    print('Found orphan tickets:', orphans.count())
    if orphans.count() == 0:
        return

    if target_user_id is None:
        # pick first superuser/admin as default
        admin = User.objects.filter(is_superuser=True).first() or User.objects.filter(is_staff=True).first()
        if not admin:
            print('No admin user found. Provide a target_user_id.')
            return
        target_user = admin
    else:
        try:
            target_user = User.objects.get(id=target_user_id)
        except User.DoesNotExist:
            print('User not found for id', target_user_id)
            return

    print('Target user:', target_user.id, target_user.username)
    if dry_run:
        print('Dry run: the following tickets would be reassigned:')
        for t in orphans:
            print(f'  id={t.id} uid={t.uid} title="{t.title}" created_at={t.created_at}')
        print('\nRun with dry_run=False to perform the assignment.')
        return

    # perform assignment
    updated = orphans.update(user=target_user)
    print(f'Assigned {updated} tickets to user {target_user.username} ({target_user.id})')

if __name__ == '__main__':
    # usage: python assign_orphans.py [user_id] [--apply]
    uid = None
    apply_flag = False
    if len(sys.argv) >= 2:
        uid = sys.argv[1]
    if len(sys.argv) >= 3 and sys.argv[2] == '--apply':
        apply_flag = True
    assign_orphans(target_user_id=uid, dry_run=not apply_flag)
