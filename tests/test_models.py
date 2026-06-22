from django.test import TestCase
from django.utils import timezone
from datetime import timedelta
from smartlayer.models import BannedUser


class TestBannedUser(TestCase):

    def test_active_ban_by_ip_is_detected(self):
        BannedUser.objects.create(
            ip_address='1.2.3.4',
            reason='test',
            expires_at=timezone.now() + timedelta(hours=24)
        )
        self.assertTrue(BannedUser.is_banned(ip_address='1.2.3.4'))

    def test_active_ban_by_user_id_is_detected(self):
        BannedUser.objects.create(
            user_id=42,
            reason='test',
            expires_at=timezone.now() + timedelta(hours=24)
        )
        self.assertTrue(BannedUser.is_banned(user_id=42))

    def test_expired_ban_is_ignored(self):
        BannedUser.objects.create(
            ip_address='5.6.7.8',
            reason='test',
            expires_at=timezone.now() - timedelta(hours=1)  # already expired
        )
        self.assertFalse(BannedUser.is_banned(ip_address='5.6.7.8'))

    def test_unknown_ip_is_not_banned(self):
        self.assertFalse(BannedUser.is_banned(ip_address='9.9.9.9'))

    def test_unknown_user_is_not_banned(self):
        self.assertFalse(BannedUser.is_banned(user_id=999))

    def test_permanent_ban_is_detected(self):
        BannedUser.objects.create(
            ip_address='2.2.2.2',
            reason='test',
            expires_at=None  # permanent
        )
        self.assertTrue(BannedUser.is_banned(ip_address='2.2.2.2'))
