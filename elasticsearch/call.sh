#Shell script for calling playbooks

#Playbooks Name Strings
name='Playbook Name String'

ansible-playbook -i hosts ./'$name'.yml