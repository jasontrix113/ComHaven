# Generated by Django 2.0.9 on 2018-11-28 11:28

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('comhavenapp', '0006_auto_20181128_0318'),
    ]

    operations = [
        migrations.AlterField(
            model_name='userprofile',
            name='email',
            field=models.CharField(max_length=100),
        ),
    ]