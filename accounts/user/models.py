import uuid
from django.db import models
from django.core.mail import send_mail
from django.core.validators import RegexValidator
from django.conf import settings
from django.utils import timezone
from django.core.mail import send_mail
from django.core.validators import RegexValidator
from dateutil.relativedelta import relativedelta
from django.utils.translation import gettext_lazy as _

# Create your models here.

#from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin

def two_days_from_now():
    # A helper function to deactivate email activation link after 2 days
    return timezone.now() + relativedelta(days=2)


from django.contrib.auth.models import ( 
    AbstractUser,
    BaseUserManager,
)

class UserManager(BaseUserManager):
    use_in_migrations = True
    
    def _create_user(self, email, password,**extra_fields): 
        if not email:
            raise ValueError("The given email must be set") 
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password) 
        user.save(using=self._db) 
        return user

    def create_user(self, email, password=None, **extra_fields): 
        extra_fields.setdefault("is_staff", False) 
        extra_fields.setdefault("is_superuser", False)
        return self._create_user(email, password, **extra_fields)

    def create_superuser(self, email, password, **extra_fields): 
        extra_fields.setdefault("is_staff", True) 
        extra_fields.setdefault("is_superuser", True)

        if extra_fields.get("is_staff") is not True: 
            raise ValueError(
                "Superuser must have is_staff=True." )
        if extra_fields.get("is_superuser") is not True: 
            raise ValueError(
                "Superuser must have is_superuser=True." )
        return self._create_user(email, password, **extra_fields)


class User(AbstractUser):
    username = models.CharField(db_index=True, max_length=255, unique=True)
    mobile = models.CharField(validators=[RegexValidator(regex=r'^\1?\d{9,10}$')],max_length=10,blank=True)
    email = models.EmailField(db_index=True, unique=True,  null=True, blank=True)
    user_bio = models.CharField(max_length=600, blank=True)

    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    objects = UserManager()

    def __str__(self):
        return f"{self.email}"

    def email_user(self, subject, message, from_email=None):
        """
        Sends an email to this User.
        """
        send_mail(subject, message, from_email, [self.email])


class Registration(models.Model):
    uuid = models.UUIDField(primary_key=False, default=uuid.uuid4, editable=False)
    user = models.OneToOneField(User, related_name='registration', on_delete=models.CASCADE)
    expires = models.DateTimeField(default=two_days_from_now)
    type = models.CharField(max_length=10, choices=(
      ('register', 'register'),
      ('lostpass', 'lostpass'),
    ), default = 'register')