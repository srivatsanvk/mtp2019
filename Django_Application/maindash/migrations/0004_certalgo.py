# Generated by Django 2.2.7 on 2019-12-14 10:16

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('maindash', '0003_cred'),
    ]

    operations = [
        migrations.CreateModel(
            name='CertAlgo',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('algorithm', models.CharField(max_length=50)),
                ('level', models.CharField(max_length=50)),
            ],
        ),
    ]