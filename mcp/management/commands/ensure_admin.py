"""Run on every boot: make ADMIN_USERNAME the only login, an active superuser whose password is
ADMIN_PASSWORD. Any other account is deactivated, and when the password changes every connector
token is revoked, so rotating the variable and redeploying locks every agent out."""
import os

from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.management.base import BaseCommand, CommandError

from mcp.models import OAuthToken


class Command(BaseCommand):
    help = "Create or update the superuser from ADMIN_USERNAME / ADMIN_PASSWORD."

    def handle(self, *args, **options):
        User = get_user_model()
        username, password = os.getenv("ADMIN_USERNAME", "admin"), os.getenv("ADMIN_PASSWORD", "")
        user = User.objects.filter(username=username).first() or User(username=username)
        try:
            validate_password(password, user)
        except Exception as exc:
            raise CommandError(f"ADMIN_PASSWORD is not strong enough: {exc}") from exc
        if user.pk is None or not user.check_password(password) or not user.is_active:
            user.set_password(password)
            OAuthToken.objects.update(revoked=True)
            self.stdout.write("ADMIN_PASSWORD set: revoked all connector tokens.")
        user.is_active = user.is_staff = user.is_superuser = True
        user.save()
        others = User.objects.exclude(pk=user.pk)
        OAuthToken.objects.filter(user__in=others).update(revoked=True)
        others.update(is_active=False, is_staff=False, is_superuser=False)
        self.stdout.write(f"Superuser {username!r} is ready.")
