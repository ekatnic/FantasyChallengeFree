# from django.contrib.auth.models import AbstractUser
# from django.db import models

# class User(AbstractUser):
#     # cognito_sub = models.CharField(max_length=255, unique=True, null=True)
#     # email = models.EmailField(unique=True)

#     # Make both username and email case-insensitive unique
#     class Meta:
#         constraints = [
#             models.UniqueConstraint(
#                 fields=['username'],
#                 name='unique_case_insensitive_username'
#             ),
#             models.UniqueConstraint(
#                 fields=['email'],
#                 name='unique_case_insensitive_email'
#             )
#         ]

#     def save(self, *args, **kwargs):
#         # Ensure username and email are stored in lowercase
#         if self.username:
#             self.username = self.username.lower()
#         if self.email:
#             self.email = self.email.lower()
#         super().save(*args, **kwargs)