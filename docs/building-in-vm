# Building the library in a Linux VM

The project can be built and tested in a Linux virtual machine using Vagrant for VM management and provisioning. 

* Install a [supported hypervisor](https://www.vagrantup.com/docs/providers/), such as Virtual Box. 
* [Install Vagrant](https://www.vagrantup.com/docs/installation/). 

## Preparing the VM

This part only needs to be performed once. 

* `cd` to the project root (the directory that contains `pom.xml` and `src/`) and run the command `vagrant up`.
* Wait for Vagrant to download the VM image (called `box`) 
* Run `vagrant provision` to install software on the VM, such as git, the JDK, and Maven. These are specified in the Vagrantfile in the project root. 
* Run `vagrant halt` to stop the virtual machine. 

## Running the Maven build in the VM

* Run `vagrant up` to start the VM
* Run `vagrant ssh` to log into the VM via the command line
* Run `cd lib-jose` to go the automatically attached project directory
* Run `mvn install` to run the Maven build
* The `exit` command can be used to leave the VM shell and `vagrant halt` to stop the VM. 
