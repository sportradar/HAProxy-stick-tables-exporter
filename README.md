# HAProxy stick table exporter

This is a [prometheus](https://prometheus.io/) exporter for [HAProxy](https://www.haproxy.org/) stick table.
Exporter will provide stick table metrics provided by `echo "show table" | socat stdio /tmp/sock1` and `cho "show table tablename" | socat stdio /tmp/sock1`.
Futher details provided by [HAProxy docs](https://cbonte.github.io/haproxy-dconv/1.8/management.html#9.3-show%20table).

## Install

```
$ pip3 install -r requirements.txt
```

## Running
```
$ python3 HAProxy-stick-tables-exporter.py -m 9366
```


### Flags

Name | Description | Default
-----|-------------|--------
-m --metrics-port | The port that the metrics exporter will listen on | 9366


## Stats socket
This exporter expects to find HAProxy config file under /etc/haproxy/haproxy.cfg, and finds the socket in the config file.
The user running the exporter needs permissions rw on this socket.

