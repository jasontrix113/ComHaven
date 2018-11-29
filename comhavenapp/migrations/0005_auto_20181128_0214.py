# Generated by Django 2.0.9 on 2018-11-28 10:14

from django.db import migrations, models
from django_add_default_value import AddDefaultValue

class Migration(migrations.Migration):

    dependencies = [
        ('comhavenapp', '0004_auto_20181128_0213'),
    ]

    operations = [
        migrations.AlterField(
            model_name='havenfolder',
            name='login_haven_folder',
            field=models.CharField(default='Folder', max_length=200, unique=True),
        ),
        AddDefaultValue(
            model_name='havenfolder',
            name='login_haven_folder',
            value='Folder'
        ),
    ]