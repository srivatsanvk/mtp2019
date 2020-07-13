from django.urls import path
from django.views.decorators.csrf import csrf_exempt

from . import views

urlpatterns = [
    path('', csrf_exempt(views.index), name='index'),
    path('add/',csrf_exempt(views.credential),name='credential'),
    path('add/fetch',csrf_exempt(views.fetch), name='fetch') ,
    path('add/deletecreds',csrf_exempt(views.deletecreds), name='deletecreds') ,
    path('sendcs/',csrf_exempt(views.sendcs),name='sendcs'),
    path('certgen/',csrf_exempt(views.certgen),name='certgen'),
    path('sendca/',csrf_exempt(views.sendca),name='sendca'),
    path('checkip/',csrf_exempt(views.checkip),name='checkip'),
    path('sendkey/',csrf_exempt(views.sendkey),name='sendkey'),
    path('custcert/',csrf_exempt(views.custcert),name='custcert'),
    path('custcert/savecustcert',csrf_exempt(views.savecustcert),name='savecustcert'),
    path('testcustcert/',csrf_exempt(views.testcustcert),name='testcustcert'),
    path('custcert/fileupload',csrf_exempt(views.fileupload),name ='fileupload'),
    # path('custcert/renderupload',csrf_exempt(views.renderupload),name ='renderupload'),
    path('custcert/download',csrf_exempt(views.download),name ='download'),
    path('getparams/',csrf_exempt(views.getparams),name='getparams'),
    path('getvals/',csrf_exempt(views.getvals),name='getvals'),
    path('trustcalculate/',csrf_exempt(views.weights),name='weights'),
    path('trustcalculate/computets',csrf_exempt(views.computets),name='computets')
]
