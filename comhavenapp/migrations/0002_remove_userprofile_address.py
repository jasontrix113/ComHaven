# Generated by Django 2.1.4 on 2019-01-16 04:37

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('comhavenapp', '0001_initial'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='userprofile',
            name='address',
        ),
    ]
