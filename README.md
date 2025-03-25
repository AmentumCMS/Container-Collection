# What is this?

This is a project that automatically collects and creates artifacts to ease in air-gapped transfer of the catest conainer images from the internet.

It runs actions as needed/manually, on GIT Commit Push, or automatically on Mondays at 00:00 

In this case, it:

- collects container images
- creates a set of ISO Files for release on Sharepoint

## Images include:

### Disk 1 - _Base-Images-\<DATE>.iso_

- UBI 8 & 9 latest images from DSO.mil IronBank
- JDK 8, 11, & 17 latest images from DSO.mil IronBank
- nginx latest images from DSO.mil IronBank
- RHEL BootC from Redhat

### Disk 2 - _Pipeline-Images-\<DATE>.iso_

- Maven latest images from DSO.mil IronBank
- Skopeo latest images from DSO.mil IronBank
- Kaniko latest images from DSO.mil IronBank
- Checkmarx CXCLI latest images from DSO.mil IronBank
- Checkmarx OWASP ZAP latest image from DSO.mil IronBank
- Keysight Eggplant Fusion Engine latest images from DSO.mil IronBank

### Disk 3 - _Service-Images-\<DATE>.iso_

- PostGRE SQL Latest images from DSO.mil Ironbank
- Kafka Latest images from DSO.mil Ironbank
- Redis Latest images from DSO.mil Ironbank
- Sonatype Nexus latest images from DSO.mil IronBank
- RabbitMQ Latest images from DSO.mil Ironbank
- ArgoCD Latest images from DSO.mil Ironbank
- Keycloak Latest images from DSO.mil Ironbank

### Disk 4 - _Support-Images-\<DATE>.iso_

- KinD for K8s Cluster Testing
- K9s CLI for K8s Cluster management
- Helm CLI for K8s Helm Chart Management
- PlantUML Software for UML Diagramming

### Disk 5 - _Atlassian-Images-\<DATE>.iso_

- Atlassian Jira latest images from DSO.mil IronBank
- Atlassian Confluence latest images from DSO.mil IronBank
- Atlassian Bitbucket latest images from DSO.mil IronBank
- Atlassian Support latest images from DSO.mil IronBank