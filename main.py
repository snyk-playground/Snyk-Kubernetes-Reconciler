import json
import requests as reqs
from kubernetes import client, config
import os
import sys
from requests.adapters import HTTPAdapter
from urllib3.util import Retry
import urllib3
import subprocess
import re
import logging_config
import logging


APIKEY =  os.getenv("SNYK_TOKEN")
ORGID = os.getenv("SNYK_CFG_ORG_ID")
SNYKAPIVERSION = "2024-05-23"
SNYKDEBUG = bool(os.getenv("SNYKDEBUG"))
DOCKERPASSWORD = os.getenv("DOCKERPASSWORD")
DOCKERUSER = os.getenv("DOCKERUSER")
APIKEY = "Token " + APIKEY

logger = logging.getLogger(__name__)

SNYKPATH =  re.findall('\/.*snyk',str(subprocess.run(["which",  "snyk"], shell=False, stdout=subprocess.PIPE).stdout))[0]
subprocess.run([SNYKPATH, "auth", APIKEY.split()[1]], shell=False)

ignoredMetadata = ["pod-template-hash","kubectl.kubernetes.io/last-applied-configuration", "app.kubernetes.io/instance", "kubernetes.io/config.seen", "component"]

class podMetadata:
    def __init__(self, imageName, labels, annotations, securityMetadata, ownerRef) -> None:
        self.imageName = imageName
        self.labels = labels
        self.annotations = annotations
        self.securityMetadata = securityMetadata
        self.ownerRef = ownerRef

def scanMissingImages(image):

        tags = []
        tags.append(image.ownerRef)

        for podSecurityData in image.securityMetadata:
            tagVal = podSecurityData[0] + "=" + podSecurityData[1]
            tags.append(tagVal)
            tagVal = ""
           
        if image.labels is not None:
            for podMetadata in image.labels:
                if podMetadata in ignoredMetadata or len(podMetadata) > 30:
                    continue
                if len(tags) >= 10:
                    break
                tagVal = podMetadata + "=" + image.labels[podMetadata]
                tags.append(tagVal)
                tagVal = ""


        if image.annotations is not None and len(tags) < 10:
            for podMetadata in image.annotations:
                if podMetadata in ignoredMetadata or len(podMetadata) > 30:
                    continue
                if len(tags) >= 10:
                    break
                tagVal = podMetadata + "=" + image.annotations[podMetadata]
                tags.append(tagVal)
                tagVal = ""            

        tagVal = ','.join(map(str, tags))
        tagVal = tagVal.replace(".", "-").replace("/", "-")
        
        logger.info("Scanning {}".format(image.imageName))

        args = []
        args.append(image.imageName)
        args.append('--project-name=' + image.imageName)
        if tags:
            args.append('--tags=' + tagVal)
        if SNYKDEBUG:
            args.append('-d')
        if ORGID:
            args.append('--org=' + ORGID)
        if DOCKERUSER and DOCKERPASSWORD:
            args.append('--username=' + DOCKERUSER)
            args.append('--password=' + DOCKERPASSWORD)

        subprocess.run([SNYKPATH, 'container', 'monitor'] + args, shell=False)


def deleteNonRunningTargets():

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
        logger.warning("Some issue querying the designated target, exception: {}".format(ex))
        logger.warning("If this error looks abnormal please check https://status.snyk.io/ for any incidents")


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
        logger.warning("Some issue querying the designated target, exception: {}".format(ex))
        logger.warning("If this error looks abnormal please check https://status.snyk.io/ for any incidents")

    deletedTargetIDs= []

    for containerImage in fullListofContainers:

        for imageName in containerImage['attributes']['names']:
            if ':' in imageName and '@' not in imageName:
                imageTagStripped = imageName.split(':')[0]
            else:
                imageTagStripped = imageName.split('@')[0]

            if imageName not in allRunningPods and not imageName + ":latest" in allRunningPods:

                for project in fullListOfProjects:
                    multiLayerProjectTag = ""
                    if project['attributes']['name'].count(':') > 1:
                        multiLayerProjectTag = project['attributes']['name'].rsplit(':')[0] + ":" + project['attributes']['name'].rsplit(':')[1] 

                    if imageTagStripped in project['attributes']['target_reference'] and project['attributes']['name'] == imageName or multiLayerProjectTag == imageName:

                        getTargetURL = "https://api.snyk.io/rest/orgs/{}/projects?target_id={}&version={}".format(ORGID,project['relationships']['target']['data']['id'], SNYKAPIVERSION)
                        try:
                            logger.debug("Validating project count for target image {}..".format(imageTagStripped))
                            getTargetResp = session.get(getTargetURL, headers={'Authorization': '{}'.format(APIKEY)})
                            getTargetResp = getTargetResp.json()
                            logger.debug("Project count for image {} is {}".format(imageTagStripped, len(getTargetResp['data'])))
                        except reqs.RequestException as ex:
                            logger.warning("Some issue querying the designated target, exception: {}".format(ex))
                            continue
                        
                        if len(getTargetResp['data']) > 1:
                            deleteTargetURL = "https://api.snyk.io/v1/org/{}/project/{}".format(ORGID, project['id'])
                            try:
                                logger.info("Attempting to delete project {}".format(project['id']))
                                deleteResp = session.delete(deleteTargetURL, headers={'Authorization': '{}'.format(APIKEY)})
                            except reqs.RequestException as ex:
                                logger.warning("Some issue deleting the designated project, exception: {}".format(ex))
                                continue           
                            if deleteResp.status_code == 200:
                                logger.info("succesfully deleted ProjectID {}, based off image {}".format(project['id'], imageTagStripped))
                                continue
                        else:
                            deleteTargetURL = "https://api.snyk.io/rest/orgs/{}/targets/{}?version={}".format(ORGID,project['relationships']['target']['data']['id'], SNYKAPIVERSION)
                            try:
                                logger.info("Attempting to delete target {}".format(project['relationships']['target']['data']['id']))
                                deleteResp = session.delete(deleteTargetURL, headers={'Authorization': '{}'.format(APIKEY)})
                                deletedTargetIDs.append(project['relationships']['target']['data']['id'])

                            except reqs.RequestException as ex:
                                logger.warning("Some issue deleting the designated target, exception: {}".format(ex))
                                continue



#Load Kubeconfig for interacting with the K8s API. Load in K8s api V1 to query pods. 
if os.getenv('KUBERNETES_SERVICE_HOST'):
    logger.info("KUBERNETES_SERVICE_HOST detected, atempting to load in pod config... ")
    config.load_incluster_config() 
else:
    logger.info("KUBERNETES_SERVICE_HOST is not set, loading kubeconfig from localhost...")
    config.load_kube_config()
v1 = client.CoreV1Api()

allRunningPods = []
scannedImages = []


#Retry logic
retry_strategy = Retry(
    total=5,  # Maximum number of retries
    status_forcelist=[429, 500, 502, 503, 504],  # HTTP status codes to retry on
    backoff_factor=5
    )
adapter = HTTPAdapter(max_retries=retry_strategy)
session = reqs.Session()
session.mount('https://', adapter)


for pod in v1.list_pod_for_all_namespaces().items:

    multiContainerPod = pod.status.container_statuses
    podAnnotations = pod.metadata.annotations
    podLabels = pod.metadata.labels
    ownerReference = "deployment-Name=None"
    if pod._metadata._owner_references is not None:
        ownerReference = pod._metadata._owner_references[0].name.rpartition('-')
        ownerReference = "deployment-Name=" + ownerReference[0]
    for container in pod.spec.containers:

        if container.image in scannedImages or container.image + ":latest" in scannedImages:
            logger.info("Skipping duplicate image: {}".format(container.image))
            continue
        
        image = container.image
        logger.info("Attempting to pull {}, depending on the size this may take some time..".format(image))
        subprocess.run(['docker', 'pull', image], shell=False, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
        output = subprocess.run(['docker', 'inspect', image], shell=False, capture_output=True, text=True)
        dockerImageID = json.loads(output.stdout)
        dockerImageID = dockerImageID[0]['Id'].replace(":", "%3A")

        if ':' not in image:
            for imagesInContainer in multiContainerPod:
                if image in imagesInContainer.image:
                    image = imagesInContainer.image

        podHasCPULimit = ["PodHasCPULimit","FAIL"]
        podHasMemoryLimit = ["podHasMemoryLimit","FAIL"]
        podIsPrivileged = ["podIsPrivileged","FAIL"]
        podIsRoot = ["podIsRoot","FAIL"]
        podFSSafe= ["podFileSystemReadOnly","FAIL"]
        podDropsCapabilities = ["podDropsCapabilities","FAIL"]
        
        podSecurityData = [podHasCPULimit, podHasMemoryLimit, podIsPrivileged, podIsRoot, podFSSafe, podDropsCapabilities]
        if container.resources._limits is not None:
            for limit in container.resources._limits:
                if limit == 'memory':
                    podHasMemoryLimit[1] = "PASS"
                if limit == 'cpu':
                    podHasCPULimit[1] = "PASS"

        if container.security_context is not None:
            if container.security_context.privileged == False:
                podIsPrivileged[1] = "PASS"

            if container.security_context.run_as_non_root == True:
                podIsRoot[1] = "PASS"

            if container.security_context.read_only_root_filesystem == True:
                podFSSafe[1] = "PASS"

            if container.security_context.capabilities is not None:
                for entry in container.security_context.capabilities.drop:
                    if entry.lower() == "all":
                        podDropsCapabilities[1] = "PASS"
                if container.security_context.capabilities.add is not None:
                    if 'CAP_SYS_ADMIN' in container.security_context.capabilities.add:
                        podDropsCapabilities[1] = "FAIL"

        if image in allRunningPods:
            continue
        allRunningPods.append(image)
        
        encodedImage = image.replace(":", "%3A").replace("/", "%2F").replace("@", "%40")
        URL = "https://api.snyk.io/rest/orgs/{}/container_images?image_ids={}&version={}".format(ORGID, dockerImageID, SNYKAPIVERSION)
        try:
            logger.info("Sending request to the container images endpoint for {}".format(image))
            containerReponse = session.get(URL, headers={'Authorization': APIKEY})
            containerIDResponseJSON = containerReponse.json()
        except reqs.RequestException as ex:
            logger.warning("Some issue calling the container_images endpoint the exception: {}".format(ex))
            logger.warning("If this error looks abnormal please check https://status.snyk.io/ for any incidents")
            continue

        URL = "https://api.snyk.io/rest/orgs/{}/projects?names={}&version={}".format(ORGID, encodedImage, SNYKAPIVERSION)
        try:
            logger.info("Sending request to the projects endpoint for {}".format(image))
            projectResponse = session.get(URL, headers={'Authorization': APIKEY})
            projectResponse = projectResponse.json()
        except reqs.RequestException as ex:
            logger.warning("Some issue calling the projects endpoint the exception: {}".format(ex))
            logger.warning("If this error looks abnormal please check https://status.snyk.io/ for any incidents")
            continue
        podObject = podMetadata(image, podLabels, podAnnotations, podSecurityData, ownerReference)

        try:
            if not containerIDResponseJSON.get('data') or not projectResponse.get('data'):
                scanMissingImages(podObject)
        except KeyError as e:
            logger.warning("Missing data field for object response from Snyk API, attempting to scan {}...".format(image))
            scanMissingImages(podObject)

        logger.info("Removing downloaded image {}".format(image))
        subprocess.run(['docker', 'rmi', image], shell=False, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
        scannedImages.append(image)

deleteNonRunningTargets()
session.close()
sys.exit()