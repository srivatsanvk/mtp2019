# Generated by Django 2.2.7 on 2019-11-14 02:58

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('maindash', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='id',
            name='ipaddress',
            field=models.CharField(max_length=50, unique=True),
        ),
    ]