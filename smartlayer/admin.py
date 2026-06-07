# smart_layer/admin.py
from django.contrib import admin
from smartlayer.models import DailyReport, RequestLog, BannedUser

@admin.register(DailyReport)
class DailyReportAdmin(admin.ModelAdmin):
    list_display   = ['date', 'created_at']
    readonly_fields= ['date', 'report', 'created_at']
    ordering       = ['-date']

@admin.register(RequestLog)
class RequestLogAdmin(admin.ModelAdmin):
    list_display   = ['method', 'path', 'status_code', 'response_time_ms', 'user_id', 'was_blocked', 'timestamp']
    readonly_fields= ['method', 'path', 'status_code', 'response_time_ms', 'user_id', 'ip_address', 'was_blocked', 'timestamp']
    ordering       = ['-timestamp']

@admin.register(BannedUser)
class BannedUserAdmin(admin.ModelAdmin):
    list_display   = ['ip_address', 'reason', 'banned_at', 'expires_at']
    ordering       = ['-banned_at']