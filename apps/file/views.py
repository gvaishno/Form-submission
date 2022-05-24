from xml.dom import NotFoundErr
from xmlrpc.client import Boolean
from django.shortcuts import render,redirect,get_object_or_404
from django.views.generic import View,ListView,DetailView,DeleteView,FormView
from django.contrib.auth.mixins import LoginRequiredMixin
from django.db import transaction
from django.urls import reverse_lazy
from django.http import FileResponse
import uuid, hashlib, requests
from file.models import UserFile
from account.models import User
from .forms import FileForm
from .mixins import UserLimit
from django.http import JsonResponse
from django.conf import settings
# Create your views here.
# Home page view
class Home(LoginRequiredMixin,ListView):
    template_name = "base/Home.html"
    def get_queryset(self):
        object = UserFile.objects.filter(owner=self.request.user)
        return object
# Add file page view
class AddFile(LoginRequiredMixin,UserLimit,FormView):
    template_name = "file/AddFile.html"
    form_class = FileForm
    success_url = "file:home"
    def form_valid(self, form):
        form = self.form_class(self.request.POST, self.request.FILES)
        form = form.save(commit=False)
        form.slug = uuid.uuid4().hex.upper()[0:6]
        form.owner = self.request.user
        form_file = form.file
        # Get file hash
        file_read = form_file.read()
        # Create a SHA256 hash
        file_hash = hashlib.sha256(file_read).hexdigest()
        print ("File hash: ",file_hash)
        form.save()
        User.objects.filter(username=self.request.user.username).update(
            limit=self.request.user.limit + 1
        )
        return redirect(self.success_url)


# File detail view
class DetailFile(DetailView):
    template_name = "file/DetailFile.html"
    def get_object(self):
        slug = self.kwargs.get('slug')
        object = get_object_or_404(UserFile, slug=slug)
        return object

# File download view
class FileDownload(View):
    def get(self, request,slug, *args, **kwargs):
        object = get_object_or_404(UserFile, slug=slug)
        return FileResponse(object.file, as_attachment=True)

# File delete view
def FileDelete(request, slug):
    model = UserFile.objects.get(slug=slug)
    model.delete()
    User.objects.filter(username=request.user.username).update(limit=request.user.limit + 1)
    return redirect('file:home')

# File upload view
def FileUploadHASH(request):
    # Get data from ajax request
    if request.method == 'POST':
        file = request.FILES.get('file')
        
        # Get file title
        title = request.POST.get('title')
        
        # Get file description
        description = request.POST.get('description')

        # Save file to database
        model = UserFile(
            title=title,
            description=description,
            file=file,
            slug=uuid.uuid4().hex.upper()[0:6],
            owner=request.user,
        )
        model.save()

        # Update user limit
        User.objects.filter(username=request.user.username).update(
            limit=request.user.limit + 1
        )
        
        # Send response to ajax request
        return JsonResponse({"status": "success"})
    else:
        return render(request, 'file/AddFileHASH.html')

def FileUploadRTA(request):
    # Get data from ajax request
    if request.method == 'POST':
        file = request.FILES.get('file')
        
        # Get file title
        title = request.POST.get('title')
        
        # Get file description
        description = request.POST.get('description')

        # Save file to database
        model = UserFile(
            title=title,
            description=description,
            file=file,
            slug=uuid.uuid4().hex.upper()[0:6],
            owner=request.user,
        )
        model.save()

        # Update user limit
        User.objects.filter(username=request.user.username).update(
            limit=request.user.limit + 1
        )
        
        # Send response to ajax request
        return JsonResponse({"status": "success"})
    else:
        return render(request, 'file/AddFileRTA.html')

# Check file hash for malware
def CheckFileHash(request):
    if request.method == 'POST':
        file = request.FILES.get('file')
        file_read = file.read()
        file_hash = hashlib.sha256(file_read).hexdigest()
        print ("File hash: ",file_hash)
        result = SendFile("HASH", None, file_hash)
        
        match result:
            case True:
                return JsonResponse({"status": "bad"})
            case False:
                return JsonResponse({"status": "good"})
            case default:
                return JsonResponse({"status": "unknown"})
    else:
        return render(request, 'file/AddFileHASH.html')

# Check file with Realtime analysis
def CheckFileRTA(request):
    if request.method == 'POST':
        file = request.FILES.get('file')
        result = SendFile("RTA", file)
        
        match result:
            case True:
                return JsonResponse({"status": "bad"})
            case False:
                return JsonResponse({"status": "good"})
            case default:
                return JsonResponse({"status": "unknown"})
    else:
        return render(request, 'file/AddFileRTA.html')

# Send file to Threatensics
def SendFile(scanmode, file=None, file_hash=None):
    match scanmode:
        case 'HASH':
            return ThreatensicsFileHashCheck(file_hash)
        case 'RTA':
            return ThreatensicsFileRTA(file)
        case default:
            return "notfound"

# Threatensics API Login Token
def ThreatensicsLogin() -> str:
    return settings.TIX_TOKEN

# Threatensics File hash check
def ThreatensicsFileHashCheck(file_hash) -> str:
    # Get Threatensics API token
    token = ThreatensicsLogin()
    # Create request url
    url = settings.TIX_API + "/tools/analyze-hash/" + file_hash
    # Create request headers
    headers = {
        'Authorization': "Bearer " + token,
        'Content-Type': "application/json"
    }
    # Create request
    request = requests.get(url, headers=headers)
    # Get response
    response = request.json()
    # Check if file is found
    match response['verdict']:
        case True:
            return True
        case False:
            return False
        case "notfound":
            return "notfound"
        case default:
            return "null"

# Threatensics File RTA check
def ThreatensicsFileRTA(file) -> str:
    # Get Threatensics API token
    token = ThreatensicsLogin()
    # Create request url
    url = settings.TIX_API + "/tools/scan-file/"
    # Create request headers
    headers = {
        'Authorization': "Bearer " + token,
    }
    # Create multipart form data
    files = {'file': file}
    # Create request
    request = requests.post(url, headers=headers, files=files)
    # Get response
    response = request.json()
    print (response)

    # Get file_hash
    file_hash = response["file_hash"]
    # Check ThreatensicsFileHashCheck(file_hash) until vertict is not null.
    pre_result = ThreatensicsFileHashCheck(file_hash)
    while pre_result == "null":
        pre_result = ThreatensicsFileHashCheck(file_hash)
    # Return result
    return pre_result