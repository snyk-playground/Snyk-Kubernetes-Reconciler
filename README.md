[<img alt="alt_text" src="https://raw.githubusercontent.com/snyk-labs/oss-images/main/oss-example.jpg" />](https://raw.githubusercontent.com/snyk-labs/oss-images/main/oss-example.jpg)

# Snyk-Kubernetes-reconciler
Stop-gap visibility while V3 of the enterprise monitor is not GA

This tool provides stop-gap visibility while the Snyk-Monitor V3 is not GA. This script uses, the K8s API to validate what is currently running in the cluster, then reaches out to Snyk via API to validate the difference between what is currently being scanned and what is not. Once this is done, it uploads (Via Snyk container monitor) container images to the UI, then proceeds to remove any images that are present within Snyk but not running on the cluster.

# Approach

The general idea is to query the Kubernetes API server (once), and validate what is running against the Snyk projects API by the name of the image. If the image name is not currently in Snyk, then it is added to a queue to be scanned along with the pods labels and annotations. Once a list of missing image objects has been created, we then run scan each image with the `snyk container monitor` command with relevant metadata. We make use of the `--project-name` flag to ensure that we can create individual projects per image tag/digest. After all images have been scanned, we then pull all images from the Snyk `container_images` endpoint, then check this against all of the projects within Snyk. Once we have that information, we check the `container_images` we have gathered against the running pods in the cluster, if that `container_image` from Snyk is not present in the list of running pods, we then attempt to delete the associated target within Snyk. 

# How to Deploy

To run this script you will need to set the below environment variables: 

`SNYK_TOKEN` environment variable set with the relevant API token from the Snyk tennant.

`SNYK_CFG_ORG_ID` environment variable set with the relevant organization ID from the Snyk tennant.

A local Docker client running, that has access to the private repositories that your pods are running images from. If desired, you can also set the `DOCKERUSER` and `DOCKERPASSWORD` environment variables to pass to the Snyk CLI.

The Snyk CLI is available on the machine, pathing is based on the command `which snyk`.

Python available on the local machine, with the appropriate requirements installed. These can be installed by running `pip install -r requirements.txt` in the root directory of this project.
Once you have set the appropriate variables, you can run the script with `python main.py`.

# Insights Support

[Insights](https://docs.snyk.io/manage-risk/prioritize-issues-for-fixing/set-up-insights-for-snyk-apprisk) container label gathering is supported by this project. This is controlled by two labels:

```
org.opencontainers.image.source=<Your Repo Source>
io.snyk.containers.repo.branch=<Your Custom Branch>
```

By OCI standards, the source label will not contain the branch, though Snyk needs this information to correlate Container projects back to its source repository. Because of this, this project looks for a custom Snyk Label to be added to the container source to specify the branch. If this label is not found when running `docker inspect` after pulling your image, it will be assumed that the project is being built from `main`.

# Running on a local machine

1. `SNYK_TOKEN` environment variable set with the relevant API token from the Snyk tennant.
2. `SNYK_CFG_ORG_ID` environment variable set with the relevant organization ID from the Snyk tennant.
3. A local Docker client running, that has access to the private repositories that your pods are running images from. If desired, you can also set the `DOCKERUSER` and `DOCKERPASSWORD` environment variables to pass to the Snyk CLI.
4. The Snyk CLI is available on the machine, pathing is based on the command `which snyk`.
5. Python available on the local machine, with the appropriate requirements installed. These can be installed by running `pip install -r requirements.txt` in the root directory of this project.

Once you have set the appropriate variables, you can run the script with `python main.py`.


# Contributing

Contributors are welcome! Feel free to raise questions, feature requests or change sets in this Github Repository!

To test your changes, fork the Snyk-Kubernetes-Reconciler repository and add your changes there then open a PR when you are ready for review.
