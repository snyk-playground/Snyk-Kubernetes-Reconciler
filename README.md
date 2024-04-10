# Snyk-Kubernetes-reconciler
Stop-gap visibility while V3 of the enterprise monitor is not GA

[<img alt="alt_text" src="https://raw.githubusercontent.com/snyk-labs/oss-images/main/oss-example.jpg" />](https://raw.githubusercontent.com/snyk-labs/oss-images/main/oss-example.jpg)

# How to Deploy

Currently this project runs as a python script on a local machine (see ReadMe within Kubernetes-Resources for information on running this as a pod). This requires a few things to be done prior:

1. APITOKEN environment variable set with the relevant API token from the Snyk tennant.
2. ORGID environment variable set with the relevant organization ID from the Snyk tennant.
3. A local Docker client running, that has access to the private repositories that your pods are running images from.
4. The Snyk CLI is available on the machine, pathing is based on the command 'which snyk'
