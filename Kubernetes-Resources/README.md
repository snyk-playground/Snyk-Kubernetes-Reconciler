[<img alt="alt_text" src="https://raw.githubusercontent.com/snyk-labs/oss-images/main/oss-example.jpg" />](https://raw.githubusercontent.com/snyk-labs/oss-images/main/oss-example.jpg)

# How to Deploy

To deploy the K8s reconciler, you will first need to create the relevant Role resources; within the K8s folder, there is a file roleResources.yaml which contains: A serviceAccount, ClusterRole, ClusterRoleBinding. The serviceAccount gets mounted into the pod and the cluster scope is needed to grab all pods. After you download the repo to your workstation, you will need to move your terminal to the root of the project and run all commands from there:

1. `docker build . -t YourImageName:YourImageTag`. This will build using the local Dockerfile and tag the image with the relevant name for your organization

2. `docker push YourImageName:YourImageTag`. This will push the image we just created to your repository to be pulled by the Cron Job/Job resource that we will deploy later.

3. After doing so, you will need to edit the `image` entry within the Job.yaml to point to the image that you pushed to your registry.

4. `kubectl create ns snyk-reconciler`. This creates a namespace so we can deploy our resources separated from the rest of the cluster.

5. `kubectl apply -f Kubernetes-Resources/roleResources.yaml -n snyk-reconciler`. These are the Kubernetes role resources needed to deploy, this requires cluster scope and the ability to list pods in all namespaces. If there is an issue deploying this file, you can apply them individually as well.

6. Once the Resources are created you will need to create a secret named `snyk-creds` in the namespace your job runs. If you require that the Reconciler pulls from private repositories, you can instead point the dockercfg.json at a config file that has credentials that can access all repositories. The following command can be used to generate the secret, there is no need to include the `Token` prefix for your APITOKEN:

```
kubectl create secret generic snyk-creds -n snyk-reconciler --from-file=dockercfg.json={} --from-literal=SNYK_CFG_ORG_ID={} --from-literal=SNYK_TOKEN={}
```

Currently, this is limited to basic authentication.

7. After creating your secret, you can run a job with `kubectl apply -f Kubernetes-resources/job.yaml`. If you are looking to do cadenced runs you can easily convert this to a cronjob (https://kubernetes.io/docs/concepts/workloads/controllers/cron-jobs/)


# Insights Support

[Insights](https://docs.snyk.io/manage-risk/prioritize-issues-for-fixing/set-up-insights-for-snyk-apprisk) container label gathering is supported by this project. This is controlled by two labels:

```
org.opencontainers.image.source=<Your Repo Source>
io.snyk.containers.repo.branch=<Your Custom Branch>
```

By OCI standards, the source label will not contain the branch, though Snyk needs this information to correlate Container projects back to its source repository. Because of this, this project looks for a custom Snyk Label to be added to the container source to specify the branch. If this label is not found when running `docker inspect` after pulling your image, it will be assumed that the project is being built from `main`.

# Contributing

Contributors are welcome! Feel free to raise questions, feature requests or change sets in this Github Repository!

To test your changes, fork the Snyk-Kubernetes-Reconciler repository and add your changes there then open a PR when you are ready for review.