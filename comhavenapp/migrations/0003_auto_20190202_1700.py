# Generated by Django 2.1.4 on 2019-02-02 09:00

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('comhavenapp', '0002_remove_rewards_user'),
    ]

    operations = [
        migrations.AlterField(
            model_name='securitychallenges',
            name='points',
            field=models.IntegerField(default=0),
        ),
        migrations.DeleteModel(
            name='Points',
        ),
    ]