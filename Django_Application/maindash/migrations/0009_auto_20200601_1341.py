# Generated by Django 2.2.7 on 2020-06-01 13:41

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('maindash', '0008_evalts'),
    ]

    operations = [
        migrations.AlterField(
            model_name='evalts',
            name='eval_ipaddress',
            field=models.CharField(max_length=50),
        ),
    ]
