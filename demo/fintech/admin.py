"""Demo admin: block/unblock users straight from the Users list.

Consumes the package's ``BlockActionsMixin`` (we don't reimplement enforcement in
the demo). Blocking a user here returns the configured status (429) on their next
request, since the ``user`` scope keys on the pk that enforcement reads at ingress.
"""

from django.contrib import admin
from django.contrib.auth import get_user_model
from django.contrib.auth.admin import UserAdmin as DjangoUserAdmin

from sec_audit.django_enforcement.admin import BlockActionsMixin

User = get_user_model()

# auth.admin registers User first (auth precedes fintech in INSTALLED_APPS), so
# swap in a subclass that adds the block/unblock actions + a status column.
admin.site.unregister(User)


@admin.register(User)
class UserAdmin(BlockActionsMixin, DjangoUserAdmin):
    list_display = DjangoUserAdmin.list_display + ('block_status',)
