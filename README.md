# awsr

awsr is a package for easily connecting to, managing and working on Amazon Web Services, in particular EC2 and S3.

## Features (currently, goals)

* View the status of EC2 instances, start/stop them, and launch more as necessary
* Send SSH commands to an EC2 instance
* Transfer files to and from an EC2 or S3 server, either locally or between each other

The aim is to be able to easily store data and results on S3 and work with that data on a powerful EC2 instance, either using R scripts as batch jobs or interactively using RStudio Server.