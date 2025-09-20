Net cut application written in rust

1) First of all clone this repo and build project with <i>release</i> flag.

```
cargo build --release

```

2) Then go to ```target``` folder and execute binary file as below

```
sudo ./netcut -i wlan0 -g 192.168.18.1 -t 192.168.18.54

```

```-i``` flag is interface of the network. Type ```ifconfig``` or ```iwconfig``` on terminal to get network interface. ```-g``` flag is gateway of the router ```(Admin gateway)```).  ```-t``` flag is ip address of targeted user. To target multiple client we can use ```-t 192.168.18.54,192.168.18.152,192.168.18.78```.
