# Generated by Django 2.1.4 on 2019-02-02 09:11

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('comhavenapp', '0003_auto_20190202_1700'),
    ]

    operations = [
        migrations.AddField(
            model_name='tempaccounts',
            name='ch_flag',
            field=models.BooleanField(default=False),
        ),
    ]
