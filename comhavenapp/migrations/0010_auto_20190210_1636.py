# Generated by Django 2.1.5 on 2019-02-10 08:36

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('comhavenapp', '0009_user_stats_count'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user_stats',
            name='count',
            field=models.IntegerField(default=10),
        ),
    ]