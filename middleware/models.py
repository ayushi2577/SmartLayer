
from django.db import models
from django.contrib.auth import get_user_model

User=get_user_model()

class RequestLog(models.Model):
    user_id = models.IntegerField(null=True, blank=True)
    ip_address=models.GenericIPAddressField(null=True, blank=True)
    method = models.CharField(max_length=10)            #GET/POST/PUT/DELETE
    path = models.CharField(max_length=100)             #/api/v1/users/1
    status_code = models.IntegerField()                 #200/400/500
    response_time_ms = models.FloatField()              #time in ms
    timestamp = models.DateTimeField(auto_now_add=True) #when request was made
    was_blocked = models.BooleanField(default=False)    #was blocked by middleware
    
    def __str__(self):
        return self.method + " " + self.path
    
class UserRequestCount(models.Model):
    user = models.ForeignKey('auth.User', on_delete=models.CASCADE)
    path = models.CharField(max_length=200)
    lifetime_count = models.IntegerField(default=0)

    class Meta:
        unique_together = ['user', 'path']  # one row per user per path
