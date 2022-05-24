from django.urls import path
from .views import Home,AddFile,DetailFile,FileDownload,FileDelete, FileUploadHASH, FileUploadRTA, CheckFileHash, CheckFileRTA
app_name = "file"
urlpatterns = [
    path("",Home.as_view(),name= "home"),
    path('hash-demo/',FileUploadHASH,name="hash-demo"),
    path('rta-demo/',FileUploadRTA,name="rta-demo"),
    path("detail/<str:slug>/",DetailFile.as_view(),name="detail-file"),
    path("download/<str:slug>/",FileDownload.as_view(),name="download-file"),
    path("delete/<str:slug>/",FileDelete,name="delete-file"),
    path("upload/",FileUploadRTA,name="upload-file"),
    path("check-hash/",CheckFileHash,name="check-file"),
    path("check-rta/",CheckFileRTA,name="check-rta")
]