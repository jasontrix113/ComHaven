# Generated by Django 2.0.9 on 2018-11-28 11:18

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('comhavenapp', '0005_auto_20181128_0214'),
    ]

    operations = [
        migrations.AddField(
            model_name='userprofile',
            name='address',
            field=models.CharField(default='', max_length=100),
        ),
        migrations.AddField(
            model_name='userprofile',
            name='notes',
            field=models.CharField(default='', max_length=200),
        ),
    ]
