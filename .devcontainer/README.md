# Ansible Development Container

This is a development container for working with Ansible. It provides an environment for running Ansible playbooks and managing infrastructure.

## Getting Started

To get started, follow these steps:

1. Install [Visual Studio Code](https://code.visualstudio.com/)
2. Install the [Remote - Containers](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers) extension for Visual Studio Code.
3. Clone this repository to your local machine.
4. Open the repository in Visual Studio Code.
5. When prompted, click on the green "Open in Container" button in the lower right corner of Visual Studio Code.

## Container Configuration

The container is based on the `mcr.microsoft.com/devcontainers/base:bullseye` image. It has the following configuration:

- Installs zsh (if enabled in devcontainer.json)
- Upgrades OS packages to their latest versions (if enabled in devcontainer.json)
- Enables non-root Docker access in the container (if enabled in devcontainer.json)
- Uses the OSS Moby Engine instead of the licensed Docker Engine (if enabled in devcontainer.json)
- Uses the specified Docker version (if specified in devcontainer.json)
- Installs the required packages and sets up the non-root user
- Installs Ansible and its dependencies from the `requirements.txt` file
- Mounts the local workspace folder to `/usr/share/ansible/collections/ansible_collections/crowdstrike/falcon` in the container

## Shell Customization

The container is configured to use zsh as the default shell. It includes the following customizations:

- Files with the extension `.yml` in the `defaults`, `group_vars`, `host_vars`, `vars`, `tasks`, `handlers`, `meta`, `roles`, and `playbooks` folders are associated with the `jinja-yaml` language mode.
- Files named `hosts` or `inventory` in the `ansible` folder are associated with the `ini` language mode.
- The default profile for the integrated terminal is set to `zsh` for Linux.

## Extensions

The following extensions are installed in the container:

- shd101wyy.markdown-preview-enhanced
- ms-python.python
- redhat.vscode-yaml
- redhat.ansible
- GitHub.copilot
- bierner.github-markdown-preview
- GitHub.vscode-pull-request-github

## Port Forwarding

Port forwarding is not enabled by default in the container. If you need to forward ports, you can add them to the `forwardPorts` section in the devcontainer.json file.

## Post-Create Command

You can run additional commands after the container is created by adding them to the `postCreateCommand` section in the devcontainer.json file.

Currently, the following commands are run after the container is created:

```bash
pre-commit install --install-hooks
```
