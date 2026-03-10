from django.db import models

# Create your models here.
from django.db.models import CASCADE


class ClientRegister_Model(models.Model):
    username = models.CharField(max_length=30)
    email = models.EmailField(max_length=30)
    password = models.CharField(max_length=10)
    phoneno = models.CharField(max_length=10)
    country = models.CharField(max_length=30)
    state = models.CharField(max_length=30)
    city = models.CharField(max_length=30)
    gender= models.CharField(max_length=30)
    address= models.CharField(max_length=30)


class Network_Anomaly(models.Model):

    Login_Frequency= models.CharField(max_length=3000)
    Failed_Login_Attempts= models.CharField(max_length=3000)
    Data_Transferred_MB= models.CharField(max_length=3000)
    Session_Duration_Minutes= models.CharField(max_length=3000)
    Accessed_Files= models.CharField(max_length=3000)
    Password_Changes= models.CharField(max_length=3000)
    IP_Location_Changes= models.CharField(max_length=3000)
    Malware_Detections= models.CharField(max_length=3000)
    Suspicious_URL_Clicks= models.CharField(max_length=3000)
    Time_Since_Last_Login_Hours= models.CharField(max_length=3000)   
    Prediction= models.CharField(max_length=3000)

class detection_accuracy(models.Model):

    names = models.CharField(max_length=300)
    ratio = models.CharField(max_length=300)

class detection_ratio(models.Model):

    names = models.CharField(max_length=300)
    ratio = models.CharField(max_length=300)



