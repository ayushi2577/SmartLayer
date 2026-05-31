
from django.db import models
from django.contrib.auth import get_user_model

User=get_user_model()

class RequestLog(models.Model):
    method = models.CharField(max_length=10)
    path = models.CharField(max_length=100)
    status_code = models.IntegerField()
    response_time_ms = models.FloatField()
    timestamp = models.DateTimeField(auto_now_add=True)
    was_blocked = models.BooleanField(default=False)
    
    def __str__(self):
        return self.method + " " + self.path
    
class UserRequestCount(models.Model):
    user = models.ForeignKey('auth.User', on_delete=models.CASCADE)
    path = models.CharField(max_length=200)
    lifetime_count = models.IntegerField(default=0)

    class Meta:
        unique_together = ['user', 'path']  # one row per user per path
