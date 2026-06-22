from django.contrib import admin
from django.utils import timezone
from datetime import timedelta
from .models import BannedUser, RequestLog, DailyReport


@admin.register(DailyReport)
class DailyReportAdmin(admin.ModelAdmin):
    list_display    = ['date', 'created_at']
    readonly_fields = ['date', 'report', 'created_at']
    ordering        = ['-date']


@admin.register(RequestLog)
class RequestLogAdmin(admin.ModelAdmin):
    list_display    = ['method', 'path', 'status_code', 'response_time_ms', 'user_id', 'was_blocked', 'timestamp']
    readonly_fields = ['method', 'path', 'status_code', 'response_time_ms', 'user_id', 'ip_address', 'was_blocked', 'timestamp']
    ordering        = ['-timestamp']


@admin.register(BannedUser)
class BannedUserAdmin(admin.ModelAdmin):
    list_display  = ['target', 'reason', 'banned_at', 'expires_at', 'is_active']
    list_filter   = ['banned_at']
    search_fields = ['user_id', 'ip_address', 'reason']
    actions       = ['lift_ban', 'extend_ban_24h', 'extend_ban_7days']

    def target(self, obj):
        return f"user:{obj.user_id}" if obj.user_id else f"ip:{obj.ip_address}"
    target.short_description = 'Banned Target'

    def is_active(self, obj):
        if obj.expires_at is None:
            return True
        return obj.expires_at > timezone.now()
    is_active.boolean = True
    is_active.short_description = 'Active'

    @admin.action(description='Lift ban immediately')
    def lift_ban(self, request, queryset):
        queryset.update(expires_at=timezone.now())
        self.message_user(request, f"{queryset.count()} ban(s) lifted.")

    @admin.action(description='Extend ban by 24 hours')
    def extend_ban_24h(self, request, queryset):
        queryset.update(expires_at=timezone.now() + timedelta(hours=24))
        self.message_user(request, f"{queryset.count()} ban(s) extended by 24 hours.")

    @admin.action(description='Extend ban by 7 days')
    def extend_ban_7days(self, request, queryset):
        queryset.update(expires_at=timezone.now() + timedelta(days=7))
        self.message_user(request, f"{queryset.count()} ban(s) extended by 7 days.")