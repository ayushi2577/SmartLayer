
from django.db import models
from django.contrib.auth import get_user_model
from django.utils import timezone

User = get_user_model()


class RequestLog(models.Model):
    user_id    = models.IntegerField(null=True, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    method     = models.CharField(max_length=10)         # GET/POST/PUT/DELETE
    path       = models.CharField(max_length=500)        # /api/v1/users/1
    status_code      = models.IntegerField()             # 200/400/500
    response_time_ms = models.FloatField()               # time in ms
    timestamp   = models.DateTimeField(auto_now_add=True)
    was_blocked = models.BooleanField(default=False)     # blocked by any middleware

    class Meta:
        indexes = [
            # Every anomaly detector query filters by (user_id, timestamp).
            # Without this index those are full-table scans.
            models.Index(fields=['user_id', 'timestamp'], name='reqlog_user_time_idx'),
            # WatchLog and AILogAnalyser filter by date alone too.
            models.Index(fields=['timestamp'], name='reqlog_time_idx'),
        ]

    def __str__(self):
        return f"{self.method} {self.path}"


class BannedUser(models.Model):
    """
    Written by AIAnomalyDetector when AI verdict is BLOCK.
    Checked at the very start of every request — before any other logic runs.

    Two kinds of bans:
      - user_id ban  : for authenticated users  (checked by user id)
      - ip_address ban: for anonymous users      (checked by IP)

    expires_at = None means permanent ban (until manually lifted).
    """
    user_id    = models.IntegerField(null=True, blank=True, db_index=True)      #as may be user is unauthenticated, so we can't use ForeignKey to User model
    ip_address = models.GenericIPAddressField(null=True, blank=True, db_index=True)     #as may be user is authenticated, so we will not set ip`
    reason     = models.TextField(default='AI anomaly detection')
    banned_at  = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True)  # None = permanent

    class Meta:
        # Prevent duplicate ban rows for the same user/IP
        constraints = [
            models.UniqueConstraint(                #UniqueConstraint says Only enforce uniqueness when the value exists.
                fields=['user_id'],
                condition=models.Q(user_id__isnull=False),
                name='unique_banned_user_id'
            ),
            models.UniqueConstraint(
                fields=['ip_address'],
                condition=models.Q(ip_address__isnull=False),
                name='unique_banned_ip'
            ),
        ]

    @classmethod
    def is_banned(cls, user_id=None, ip_address=None):
        """
        Returns True if this user_id or IP is currently banned.
        Handles expiry automatically — expired bans are treated as not banned.

        Usage:
            BannedUser.is_banned(user_id=request.user.id)
            BannedUser.is_banned(ip_address='1.2.3.4')
        """
        now = timezone.now()

        if user_id:
            exists = cls.objects.filter(
                user_id=user_id
            ).filter(
                models.Q(expires_at__isnull=True) | models.Q(expires_at__gt=now)
            ).exists()
            if exists:
                return True

        if ip_address:
            exists = cls.objects.filter(
                ip_address=ip_address
            ).filter(
                models.Q(expires_at__isnull=True) | models.Q(expires_at__gt=now)
            ).exists()
            if exists:
                return True

        return False

    def __str__(self):
        target = f"user:{self.user_id}" if self.user_id else f"ip:{self.ip_address}"
        return f"BannedUser({target}, expires={self.expires_at or 'never'})"


class UserRequestCount(models.Model):
    user          = models.ForeignKey('auth.User', on_delete=models.CASCADE)
    path          = models.CharField(max_length=200)
    plan_field    = models.CharField(max_length=50)         #user.plan 
    lifetime_count = models.IntegerField(default=0)

    class Meta:
        unique_together = ['user', 'path', 'plan_field']  # one row per user per path per plan
