
from django.db import models

class RequestLog(models.Model):
    method = models.CharField(max_length=10)
    path = models.CharField(max_length=100)
    status_code = models.IntegerField()
    response_time_ms = models.FloatField()
    timestamp = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return self.method + " " + self.path

