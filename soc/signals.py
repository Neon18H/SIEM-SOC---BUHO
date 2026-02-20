from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import UserProfile, Organization


@receiver(post_save, sender=User)
def create_profile(sender, instance, created, **kwargs):
    if created:
        org, _ = Organization.objects.get_or_create(name='Default Org')
        UserProfile.objects.create(user=instance, organization=org, role=UserProfile.ROLE_ADMIN)
