## Suricata Alert Notifier - GitHub Documentation

### Description

This C program is designed to parse Suricata's `eve.json` log file, filter alerts, and trigger desktop notifications for alerts that occurred within the last X seconds. It utilizes the `jansson.h` library for JSON parsing and the `notify-send` command-line tool for desktop notifications.

## Introduction

Suricata IDS Notification

This documentation provides instructions and guidelines for using Suricata, a powerful Intrusion Detection System (IDS), in a local Linux environment. Suricata offers robust network traffic inspection and intrusion detection capabilities to enhance the security of your Linux system.

### Purpose

The primary purpose of this setup is to deploy Suricata as an effective IDS for monitoring network traffic and detecting potential security threats. Suricata generates an output file called "eve.json," which contains detailed information about network events and alerts.

### Configuring eve.json for Optimal Performance

To ensure optimal performance and reduce resource overhead, Suricata's eve.json is configured to maintain a compact format. This compact format ensures that the log file does not consume excessive disk space and facilitates quicker processing.

### Log Rotation for Efficient File Management

To further manage the size of the eve.json file, I recommend implementing proper log rotation mechanisms. A well-configured log rotation strategy helps keep the eve.json file size within manageable limits, enhancing the performance of subsequent log file reads and analysis.

### Suricata-Notify for Real-Time Alerting

I have developed this "suricata-notify" utility, which continuously monitors the eve.json file for new alerts. When an alert is detected, suricata-notify triggers a real-time desktop notification, providing timely information about potential security incidents.

This documentation covers the installation and configuration of Suricata, setting up the suricata-notify utility, and integrating the entire solution with the systemd scheduler for automatic execution.

Please follow the instructions carefully to deploy Suricata effectively in your Linux environment and enhance your system's security with advanced intrusion detection capabilities.

### Building the Program

To build the program, ensure you have the necessary dependencies installed:

- jansson library
- notify-send command-line tool
- jq command-line tool (for viewing the eve.json)
- curl or wget (for testing suricata detection)

Compile the program using the following command:

```bash
gcc -o suricata-notify suricata-notify.c -ljansson
```

### Running the Program

To test the desktop notification functionality, run the following command:

```bash
./suricata-notify
```

This will parse the Suricata log file (`/var/log/suricata/eve.json` by default), filter alerts, and trigger notifications for valid alerts within the last 60 seconds.

### Viewing Suricata Log with jq

To view the Suricata log in real-time, use the following command:

```bash
tail -f /var/log/suricata/eve.json | jq 'select(.event_type=="alert")' | jq -r -C
```

This command will continuously display only the alert events from the `eve.json` file in a readable and colored format.

### Integrating with systemd

To run the program periodically with systemd, follow these steps:

1. Create a service file named `suricata-notify.service` in `/etc/systemd/system` or `~/.config/systemd/user/` (if using `--user`).

2. Place the following content inside the `suricata-notify.service` file:

```ini
[Unit]
Description=Suricata Alert Notifier
After=network.target

[Service]
Type=simple
ExecStart=/path/to/suricata-notify
Restart=always
# Add here your alert window in seconds
RestartSec=60
# Add Environment if required
# Environment=DISPLAY=:0  # Example for X11-based systems

[Install]
# On systemd --user set this to user or default
WantedBy=multi-user.target
```

3. Ensure that the `suricata-notify` binary is accessible from the specified path in the `ExecStart` directive.

4. Start the service and enable it to run at boot:

```bash
sudo systemctl start suricata-notify.service
sudo systemctl enable suricata-notify.service
```

### Using the `--user` Flag with systemd

To run the program as a specific user with `systemd --user`, follow these steps:

1. Place the `suricata-notify.service` file inside `~/.config/systemd/user/`.

2. Use the following command to start the service:

```bash
systemctl --user start suricata-notify.service
```

### Logging Service Output

To view the logs of the `suricata-notify.service`, use `journalctl`:

```bash
journalctl -u suricata-notify.service
```

### Verification

To verify that Suricata is running, use the following command:

```bash
sudo systemctl status suricata
```

To trigger a fresh logrotate circuit (if logrotate is configured) and verify the output, use:

```bash
sudo logrotate /etc/logrotate.d/suricata 
```

To test a desktop notification, use the following command:

```bash
notify-send "Alert Test"
```

To test suricata alert trigger and notification curl the following url:

```bash
curl http://testmynids.org/uid/index.html
```


### Disclaimer

This project is provided as-is without any warranty or liability. Use it at your own risk.

Feel free to extend or customize the program based on your requirements.

---

Please note that the paths and specific details in the above documentation need to be adjusted based on your actual setup and requirements. The `suricata-notify.c` file should be compiled and placed in a location accessible to the user or system running the program. Additionally, the `suricata-notify.service` file should be created in the appropriate systemd location.