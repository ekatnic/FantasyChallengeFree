from django.contrib.auth import models as auth_models
from django.db.models.manager import EmptyManager
from django.utils.functional import cached_property


class TokenUser:
    """
    A dummy user class modeled after django.contrib.auth.models.AnonymousUser.
    Instances of this class act as stateless user objects which are backed by validated tokens.
    """

    # User is always active as a token is self-contained and can be validated.
    is_active = True

    _groups = EmptyManager(auth_models.Group)
    _user_permissions = EmptyManager(auth_models.Permission)

    def __init__(self, token):
        self.token = token

    def __str__(self):
        return f"TokenUser {self.id}"

    def __eq__(self, other):
        return self.id == other.id

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash(self.id)

    def save(self):
        raise NotImplementedError("Token users have no DB representation")

    def delete(self):
        raise NotImplementedError("Token users have no DB representation")

    def set_password(self, raw_password):
        raise NotImplementedError("Token users have no DB representation")

    def check_password(self, raw_password):
        raise NotImplementedError("Token users have no DB representation")

    @cached_property
    def id(self):
        user_id_claim = "sub"
        return self.token[user_id_claim]

    @cached_property
    def pk(self):
        return self.id

    @cached_property
    def username(self):
        return self.token.get("username", "")

    @cached_property
    def is_staff(self):
        return self.token.get("is_staff", False)

    @cached_property
    def is_superuser(self):
        return self.token.get("is_superuser", False)

    @property
    def groups(self):
        return self._groups

    @property
    def user_permissions(self):
        return self._user_permissions

    @property
    def is_anonymous(self):
        return False

    @property
    def is_authenticated(self):
        return True

    def get_username(self):
        return self.username

    def get_group_permissions(self, obj=None):
        return set()

    def get_all_permissions(self, obj=None):
        return set()

    def has_perm(self, perm, obj=None):
        return False

    def has_perms(self, perm_list, obj=None):
        return False

    def has_module_perms(self, module):
        return False