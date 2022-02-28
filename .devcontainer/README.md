# CS Ansible Docker in Docker

*Create child containers _inside_ a container, independent from the host's docker instance. Installs Docker extension in the container along with needed CLIs.*

## Description

This container provides a solid foundation for developing and testing Ansible content using the DinD approach to facilitate molecule testing via Docker. More information relating to DinD in regards to VScode devcontainers can be found [here](https://github.com/microsoft/vscode-dev-containers/tree/main/containers/docker-in-docker).

The main purpose of this container is to provide the necessary bits needed to develop and test Ansible content. What's included:
* Container is based on: `willhallonline/ansible:2.12.2-ubuntu-20.04`
> You can substitute the version of Ansible if needed. You can view more tags [here](https://github.com/willhallonline/docker-ansible#immutable-images).
* The following mount provides a location for the Ansible Collection:
  * `/usr/share/ansible/collections/ansible_collections/crowdstrike/falcon`
* The following VScode extensions are installed:
  * redhat.ansible
  * shd101wyy.markdown-preview-enhanced
  * ms-python.python
  * redhat.vscode-yaml
  * ms-azuretools.vscode-docker
* Oh-my-zsh is installed and enabled by default
> View the [devcontainer.json](./devcontainer.json) file for more details

### Usage and Caveats

When opening up a folder with a `.devcontainer` directory, VScode should prompt you if you would like to open the workspace in the remote container. Otherwise you can also do the following:

* press <kbd>F1</kbd> or <kbd>shift+command+p</kbd> and run **Remote-Containers: Reopen Folder in Container** or **Remote-Containers: Rebuild Container** to start using the definition.

>When openinig up for the first time, it might take a few minutes for the container to be built.

##### Caveats
* After the container is built, some extensions and settings might not take effect right away. Restart the remote-connection:
  * Click the bottom left <kbd>Dev Container: Ansible DinD</kbd> and select `Reopen Folder Locally`
  * The reopen again in the remote-container.

* Molecule testing only supports using the Docker provider. If you need to test against Windows systems, you will need to use your localhost + vagrant.
* If you need to run tests with `ansible-test` suite:
  1. Navigate to `/usr/share/ansible/collections/ansible_collections/crowdstrike/falcon`
  2. Execute the following for a sanity test:
      ```bash
      $ ansible-test sanity -v
      ```
      > Do not use --docker as it will not work in this configuration.
