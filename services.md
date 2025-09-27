```
/etc/systemd/system/asblock-fetch.service

[Unit]
Description=Fetch AS prefixes into per-AS files

[Service]
Type=oneshot
ExecStart=/etc/as-blocklist/asblock_fetch.py
User=root
Group=root
```


```
/etc/systemd/system/asblock-fetch.timer

[Unit]
Description=Run asblock-fetch periodically

[Timer]
OnBootSec=2min
OnUnitActiveSec=15min
Unit=asblock-fetch.service

[Install]
WantedBy=timers.target
```


```
/etc/systemd/system/asblock-apply.service

[Unit]
Description=Apply per-AS CIDR files to ipset/iptables

[Service]
Type=oneshot
ExecStart=/etc/as-blocklist/asblock_apply.py
User=root
Group=root
```


```
/etc/systemd/system/asblock-apply.timer

[Unit]
Description=Run asblock-apply periodically

[Timer]
OnBootSec=3min
OnUnitActiveSec=15min
Unit=asblock-apply.service

[Install]
WantedBy=timers.target
```



enable:

```
sudo systemctl daemon-reload
sudo systemctl enable --now asblock-fetch.timer asblock-apply.timer
sudo systemctl status asblock-fetch.timer asblock-apply.timer
```