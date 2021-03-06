# Generated by Django 2.1.4 on 2019-02-02 08:53

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='AccessListOfDevices',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('acl_user', models.CharField(max_length=30)),
                ('device_model', models.CharField(default='', max_length=30)),
                ('access_id_path', models.CharField(default='', max_length=30)),
                ('device_platform', models.CharField(default='', max_length=30)),
            ],
        ),
        migrations.CreateModel(
            name='CompromisedPasswords',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('login_account', models.CharField(default='', max_length=200)),
                ('login_password', models.CharField(default='', max_length=200)),
                ('user', models.ForeignKey(default='', on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL, to_field='username')),
            ],
        ),
        migrations.CreateModel(
            name='DuplicatePasswords',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('login_account', models.CharField(default='', max_length=200)),
                ('login_password', models.CharField(default='', max_length=200)),
                ('user', models.ForeignKey(default='', on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL, to_field='username')),
            ],
        ),
        migrations.CreateModel(
            name='ExpressLoginsSites',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('site_name', models.CharField(max_length=50)),
            ],
        ),
        migrations.CreateModel(
            name='NewAccountLogin',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('login_target_url', models.CharField(max_length=200)),
                ('login_name', models.CharField(max_length=200)),
                ('login_username', models.CharField(max_length=200)),
                ('login_password', models.CharField(max_length=200)),
                ('login_notes', models.CharField(max_length=200)),
                ('date_inserted', models.DateTimeField(auto_now=True)),
                ('changed_flag', models.BooleanField(default=False)),
                ('login_user', models.ForeignKey(default='user', on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL, to_field='username')),
            ],
        ),
        migrations.CreateModel(
            name='OldPasswords',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('login_account', models.CharField(default='', max_length=200)),
                ('login_password', models.CharField(default='', max_length=200)),
                ('date_last_inserted', models.DateTimeField(auto_now=True)),
                ('user', models.ForeignKey(default='', on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL, to_field='username')),
            ],
        ),
        migrations.CreateModel(
            name='PasswordGenerator',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('identifier', models.IntegerField()),
                ('pass_result', models.CharField(default='res', max_length=200)),
                ('user', models.ForeignKey(default='', on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL, to_field='username')),
            ],
        ),
        migrations.CreateModel(
            name='PerformedTasks',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('accounts', models.CharField(default='', max_length=200)),
                ('status', models.CharField(default='', max_length=20)),
                ('user', models.ForeignKey(default='', on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL, to_field='username')),
            ],
        ),
        migrations.CreateModel(
            name='Points',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('points', models.IntegerField(unique=True)),
            ],
        ),
        migrations.CreateModel(
            name='Rewards',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('reward', models.CharField(default='', max_length=200)),
                ('points_required', models.IntegerField()),
                ('user', models.ForeignKey(default='', on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL, to_field='username')),
            ],
        ),
        migrations.CreateModel(
            name='SecurityChallenges',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('date_completed', models.DateTimeField(auto_now_add=True)),
                ('date_initiated', models.DateTimeField(auto_now_add=True)),
                ('points', models.ForeignKey(default='', on_delete=django.db.models.deletion.CASCADE, to='comhavenapp.Points', to_field='points')),
            ],
        ),
        migrations.CreateModel(
            name='Status',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('status', models.CharField(max_length=50)),
                ('user', models.ForeignKey(default='', on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL, to_field='username')),
            ],
        ),
        migrations.CreateModel(
            name='Tasks',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('tasks', models.CharField(default='', max_length=200, unique=True)),
            ],
        ),
        migrations.CreateModel(
            name='TempAccounts',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('temp_uname', models.CharField(max_length=30)),
                ('temp_pword', models.CharField(max_length=200)),
                ('user', models.ForeignKey(default='', on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL, to_field='username')),
            ],
        ),
        migrations.CreateModel(
            name='User_Stats',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('user', models.CharField(max_length=30)),
                ('overall_points', models.CharField(default=0, max_length=200)),
            ],
        ),
        migrations.CreateModel(
            name='UserProfile',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('email', models.CharField(default='', max_length=100)),
                ('firstname', models.CharField(default='', max_length=100)),
                ('lastname', models.CharField(default='', max_length=100)),
                ('notes', models.CharField(default='', max_length=200)),
                ('user', models.OneToOneField(on_delete='CASCADE', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='WeakPasswords',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('login_account', models.CharField(default='', max_length=200)),
                ('login_password', models.CharField(default='', max_length=200)),
                ('login_score', models.CharField(default=0, max_length=20)),
                ('login_strength', models.CharField(default='', max_length=200)),
                ('user', models.ForeignKey(default='', on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL, to_field='username')),
            ],
        ),
        migrations.AddField(
            model_name='securitychallenges',
            name='status',
            field=models.ForeignKey(default='', on_delete=django.db.models.deletion.CASCADE, to='comhavenapp.Status'),
        ),
        migrations.AddField(
            model_name='securitychallenges',
            name='tasks',
            field=models.ForeignKey(default='', on_delete=django.db.models.deletion.CASCADE, to='comhavenapp.Tasks', to_field='tasks'),
        ),
        migrations.AddField(
            model_name='securitychallenges',
            name='user',
            field=models.ForeignKey(default='', on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL, to_field='username'),
        ),
    ]
