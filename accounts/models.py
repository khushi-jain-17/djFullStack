from django.db import models


class Users(models.Model):
    user_id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=50)
    email = models.EmailField(unique=True,max_length=255)
    password = models.CharField(max_length=255, null=True)
    # role_id = models.IntegerField()  
    # role = models.ForeignKey(Roles, on_delete=models.CASCADE)
    is_deleted = models.BooleanField(default=False)
    created_by = models.CharField(max_length=50, null=True)
    created_on = models.DateTimeField(auto_now_add=True)
    updated_by = models.CharField(max_length=50, null=True)
    updated_on = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'Users' 

    def __str__(self):
        return f"{self.name}" 


   

class Record(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)
    rec_email = models.CharField(max_length=100, null=True)
    city = models.CharField(max_length=50, null=True)

    class Meta:
        db_table = 'Record' 

    def __str__(self):
        return f"{self.first_name} {self.last_name}"  

  

   