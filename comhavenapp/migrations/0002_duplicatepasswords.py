# Generated by Django 2.1.4 on 2019-01-26 12:01

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('comhavenapp', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='DuplicatePasswords',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('login_account', models.CharField(default='', max_length=200)),
                ('login_password', models.CharField(default='', max_length=200)),
                ('login_score', models.CharField(default=0, max_length=20)),
                ('login_strength', models.CharField(default='', max_length=200)),
                ('user', models.ForeignKey(default='', on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL, to_field='username')),
            ],
        ),
    ]