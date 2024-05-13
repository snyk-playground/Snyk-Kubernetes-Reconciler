import requests as reqs
from kubernetes import client, config
import os
import sys
from requests.adapters import HTTPAdapter
from urllib3.util import Retry
import urllib3
import subprocess
import re

APIKEY =  os.getenv("API_KEY")
ORGID = os.getenv("SNYK_CFG_ORG_ID")
SNYKAPIVERSION = "2023-11-06~beta"
SNYKDEBUG = bool(os.getenv("SNYKDEBUG"))
DOCKERPASSWORD = os.getenv("DOCKERPASSWORD")
DOCKERUSER = os.getenv("DOCKERUSER")
APIKEY = "Token " + APIKEY

ignoredMetadata = ["kubectl.kubernetes.io/last-applied-configuration", "app.kubernetes.io/instance", "kubernetes.io/config.seen", "component"]

class podMetadata:
    def __init__(self, imageName, labels, annotations) -> None:
        self.imageName = imageName
        self.labels = labels
        self.annotations = annotations

def scanMissingImages(images):

    snykPath =  re.findall('\/.*snyk',str(subprocess.run(["which",  "snyk"], shell=False, stdout=subprocess.PIPE).stdout))[0]

    subprocess.run([snykPath, "auth", APIKEY.split()[1]], shell=False)

    for missingImage in images:

        tags = []
        
        if missingImage.labels is not None:
            for podMetadata in missingImage.labels:
                if podMetadata in ignoredMetadata or len(podMetadata) > 30:
                    continue
                if len(tags) >= 10:
                    break
                tagVal = podMetadata + "=" + missingImage.labels[podMetadata]
                tags.append(tagVal)
                tagVal = ""


        if missingImage.annotations is not None and len(tags) < 10:
            for podMetadata in missingImage.annotations:
                if podMetadata in ignoredMetadata or len(podMetadata) > 30:
                    continue
                if len(tags) >= 10:
                    break
                tagVal = podMetadata + "=" + missingImage.annotations[podMetadata]
                tags.append(tagVal)
                tagVal = ""            

        tagVal = ','.join(map(str, tags))
        tagVal = tagVal.replace(".", "-").replace("/", "-")

        print("Scanning {}".format(missingImage.imageName))

        args = []
        args.append(missingImage.imageName)
        args.append('--project-name=' + missingImage.imageName)
        if tags:
            args.append('--tags=' + tagVal)
        if SNYKDEBUG:
            args.append('-d')
        if ORGID:
            args.append('--org=' + ORGID)
        if DOCKERUSER and DOCKERPASSWORD:
            args.append('--username=' + DOCKERUSER)
            args.append('--password=' + DOCKERPASSWORD)

        subprocess.run([snykPath, 'container', 'monitor'] + args, shell=False)



def deleteNonRunningTargets():

    urllib3.add_stderr_logger()

    fullListofContainers = []
    try:
        containerImageUrl = "https://api.snyk.io/rest/orgs/{}/container_images?version={}&limit=100".format(ORGID, SNYKAPIVERSION)
        while True:
            containerResponse = session.get(containerImageUrl, headers={'Authorization': APIKEY})
            containerResponse.raise_for_status()
            containerResponseJSON = containerResponse.json()
            fullListofContainers.extend(containerResponseJSON['data'])
            nextPageUrl = containerResponseJSON['links'].get('next')
            if not nextPageUrl:
                break
            containerImageUrl = "https://api.snyk.io/{}&version={}&limit=100".format(nextPageUrl, SNYKAPIVERSION)
    except reqs.RequestException as ex:
        print("Some issue deleting the designated target, exception: {}".format(ex))
        print("If this error looks abnormal please check https://status.snyk.io/ for any incidents")


    fullListOfProjects = []
    try:
        allProjectsURL = "https://api.snyk.io/rest/orgs/{}/projects?version={}&limit=100".format(ORGID, SNYKAPIVERSION)
        while True:
            projectResponse = session.get(allProjectsURL, headers={'Authorization': APIKEY})
            projectResponse.raise_for_status()
            projectResponseJSON = projectResponse.json()
            fullListOfProjects.extend(projectResponseJSON['data'])
            nextPageProjectURL = projectResponseJSON['links'].get('next')
            if not nextPageProjectURL:
                break
            allProjectsURL = "https://api.snyk.io{}".format(nextPageProjectURL)           
    except reqs.RequestException as ex:
        print("Some issue deleting the designated target, exception: {}".format(ex))
        print("If this error looks abnormal please check https://status.snyk.io/ for any incidents")

    for containerImage in fullListofContainers:

        if containerImage['relationships']['image_target_refs']['links'].get('self') is None or containerImage['attributes'].get('names') is None:
            continue

        for imageName in containerImage['attributes']['names']:
            if ':' in imageName:
                imageTagStripped = imageName.split(':')[0]
            else:
                imageTagStripped = imageName.split('@')[0]
            
            if imageName not in allRunningPods and not any(imageTagStripped in subString for subString in allRunningPods):
                deletedTargetIDs= []
                for project in fullListOfProjects:
                    if project['relationships']['target']['data']['id'] in deletedTargetIDs:
                        continue
                    if imageTagStripped in project['attributes']['target_reference']:
                        deleteTargetURL = "https://api.snyk.io/rest/orgs/{}/targets/{}?version={}".format(ORGID,project['relationships']['target']['data']['id'], SNYKAPIVERSION)
                        try:
                            print("Attempting to delete target {}".format(project['relationships']['target']['data']['id']))
                            deleteResp = session.delete(deleteTargetURL, headers={'Authorization': '{}'.format(APIKEY)})
                        except reqs.RequestException as ex:
                            print("Some issue deleting the designated target, exception: {}".format(ex))
                            continue
                            

                        deletedTargetIDs.append(project['relationships']['target']['data']['id'])

                        if deleteResp.status_code == 204:
                            print("succesfully deleted targetID {}, based off image {}".format(project['relationships']['target']['data']['id'], imageTagStripped))
                            continue



#Load Kubeconfig for interacting with the K8s API. Load in K8s api V1 to query pods. 
if os.getenv('KUBERNETES_SERVICE_HOST'):
    print("KUBERNETES_SERVICE_HOST detected, atempting to load in pod config... ")
    config.load_incluster_config() 
else:
    print("KUBERNETES_SERVICE_HOST is not set, loading kubeconfig from localhost...")
    config.load_kube_config()
v1 = client.CoreV1Api()


allRunningPods = []
needsToBeScanned = []

#Retry logic
retry_strategy = Retry(
    total=5,  # Maximum number of retries
    status_forcelist=[429, 500, 502, 503, 504],  # HTTP status codes to retry on
    backoff_factor=5
    )
adapter = HTTPAdapter(max_retries=retry_strategy)
session = reqs.Session()
session.mount('https://', adapter)
urllib3.add_stderr_logger()

for pod in v1.list_pod_for_all_namespaces().items:

    multiContainerPod = pod.status.container_statuses
    podAnnotations = pod.metadata.annotations
    podLabels = pod.metadata.labels

    for container in pod.spec.containers: 
        image = container.image
        
        if ':' not in image:
            for imagesInContainer in multiContainerPod:
                if image in imagesInContainer.image:
                    image = imagesInContainer.image

        if image in allRunningPods:
            continue
        allRunningPods.append(image)
        
        encodedImage = image.replace(":", "%3A").replace("/", "%2F").replace("@", "%40")

        URL = "https://api.snyk.io/rest/orgs/{}/projects?names={}&version=2023-11-06%7Ebeta".format(ORGID, encodedImage, SNYKAPIVERSION)
        try:
            print("Sending request to the container images endpoint for {}".format(image))
            response = session.get(URL, headers={'Authorization': APIKEY})
            responseJSON = response.json()
        except reqs.RequestException as ex:
            print("Some issue calling the container_images endpoint the, exception: {}".format(ex))
            print("If this error looks abnormal please check https://status.snyk.io/ for any incidents")
            continue
        
        podObject = podMetadata(image, podLabels, podAnnotations)

        if not responseJSON.get('data'):
            print("{} does not exist in Snyk, adding it to the queue to be scanned".format(image))
            needsToBeScanned.append(podObject)

#Do the work we have set out to do
if len(needsToBeScanned) != 0:
    scanMissingImages(needsToBeScanned)
else:
    print("All images on the cluster are accounted for, skipping scanning function")

deleteNonRunningTargets()
session.close()
sys.exit()