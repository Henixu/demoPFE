from django.db import models

from django.contrib.auth.models import User

class Employees(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='employee')
    score_employees = models.IntegerField(default=0)
    score_trainer = models.IntegerField(default=0)

    def __str__(self):
        return self.user.username

class History(models.Model):
    ip_address = models.GenericIPAddressField()
    timestamp = models.DateTimeField(auto_now_add=True)
    attempt_count = models.PositiveIntegerField(default=0)
    is_banned = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.ip_address} - {self.timestamp}"