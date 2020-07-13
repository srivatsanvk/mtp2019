from django.db import models



class ID(models.Model):
    hostname = models.CharField(max_length=50)
    ipaddress = models.CharField(unique=True,max_length=50)
    passkey = models.CharField(max_length = 20,default="A1B2C3D4E5")
    
class cred(models.Model):
	username = models.CharField(max_length=50)
	password = models.CharField(max_length=50) 
	ipaddress= models.CharField(unique=True,max_length=50)

	def save(self, *args, **kwargs):
		assert self.username, "The 'username' field must be populated."
		assert self.password, "The password field is required."
		super().save(*args, **kwargs) 

class Devts(models.Model):
    ipaddress    = models.CharField(unique=True,max_length=50)
    connections  = models.DecimalField(decimal_places=2,max_digits=4)
    processes    = models.DecimalField(decimal_places=2,max_digits=4)
    vulnerability= models.IntegerField()
    systemsec	 = models.IntegerField()

class Evalts(models.Model):
	host_ipaddress = models.CharField(unique=True,max_length=50)
	availability = models.IntegerField()
	certificate = models.IntegerField()
	retransmission = models.IntegerField()
	delay = models.DecimalField(decimal_places=2,max_digits=4)
	trustscore = models.IntegerField()
	eval_ipaddress = models.CharField(max_length=50)

class CertAlgo(models.Model):
    algorithm = models.CharField(max_length=50)
    level = models.CharField(max_length=50)

class Document(models.Model):
    docfile = models.FileField(upload_to='document')


