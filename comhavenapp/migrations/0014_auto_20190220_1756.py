# Generated by Django 2.1.5 on 2019-02-20 09:56

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('comhavenapp', '0013_auto_20190212_2118'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='tempaccounts',
            name='user',
        ),
        migrations.AlterField(
            model_name='status',
            name='user',
            field=models.CharField(max_length=50),
        ),
        migrations.DeleteModel(
            name='TempAccounts',
        ),
    ]