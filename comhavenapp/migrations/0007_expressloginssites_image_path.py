# Generated by Django 2.1.4 on 2019-02-03 08:43

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('comhavenapp', '0006_auto_20190202_1845'),
    ]

    operations = [
        migrations.AddField(
            model_name='expressloginssites',
            name='image_path',
            field=models.CharField(default='', max_length=200),
        ),
    ]
