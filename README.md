# ARP SSH

## Notice

This is provided without warranty or support of any kind.

## Instructions

Install by putting the contents of `custom_components` in your `config/custom_components` directory and then restarting Home Assistant.

Add to your Home Assistant configuration.yaml:
```
device_tracker:
  - platform: arp_ssh
    host: 192.168.0.1
    username: root
    password: ./ssh_keys/id_rsa
```

* host is the address of the device to login to
* username is the username
* password is a path to SSH key