#define _XOPEN_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#define MAX_LINE_LENGTH 4096
#define TIMEZONE_OFFSET_SECONDS 3600
#define ALERT_WINDOW_SECONDS 60

// Function prototypes
void send_notification(const char *alert_message);
time_t convert_iso8601_to_unix(const char *iso8601_timestamp);
void process_alerts(const char *log_file);

// Function to send a desktop notification with signature and category
void send_notification(const char *alert_message)
{
    pid_t pid = fork();

    if (pid < 0)
    {
        perror("fork failed");
        return;
    }

    if (pid == 0)
    { // Child process
        execlp("notify-send", "notify-send", "Suricata Alert", alert_message, (char *)NULL);
        perror("execlp failed");
        exit(EXIT_FAILURE);
    }
    else
    { // Parent process
        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status) && WEXITSTATUS(status) != 0)
        {
            fprintf(stderr, "notify-send failed with exit code %d\n", WEXITSTATUS(status));
        }
    }
}

// Function to convert ISO 8601 timestamp to time_t (Unix timestamp)
time_t convert_iso8601_to_unix(const char *iso8601_timestamp)
{
    struct tm tm_time;
    memset(&tm_time, 0, sizeof(struct tm));

    if (strptime(iso8601_timestamp, "%Y-%m-%dT%H:%M:%S.%6N%z", &tm_time) == NULL)
    {
        fprintf(stderr, "Failed to parse timestamp: %s\n", iso8601_timestamp);
        return (time_t)-1;
    }

    return mktime(&tm_time) - TIMEZONE_OFFSET_SECONDS;
}

// Function to process Suricata alerts and trigger notifications
void process_alerts(const char *log_file)
{
    FILE *file = fopen(log_file, "r");
    if (file == NULL)
    {
        perror("Error opening file");
        return;
    }

    char line[MAX_LINE_LENGTH];
    time_t current_time = time(NULL); // Get the current time

    while (fgets(line, sizeof(line), file) != NULL)
    {
        // Load the JSON object from the line
        json_error_t error;
        json_t *root = json_loads(line, 0, &error);
        if (root == NULL)
        {
            // Handle invalid JSON line gracefully
            fprintf(stderr, "Error parsing JSON: %s\n", error.text);
            continue;
        }

        // Check if the JSON object has the "event_type" field and it is "alert"
        json_t *event_type = json_object_get(root, "event_type");
        if (json_is_string(event_type) && strcmp(json_string_value(event_type), "alert") == 0)
        {
            // Extract the timestamp
            json_t *alert_timestamp_json = json_object_get(root, "timestamp");
            if (json_is_string(alert_timestamp_json))
            {
                time_t alert_timestamp = convert_iso8601_to_unix(json_string_value(alert_timestamp_json));

                // Check if the alert occurred within the last ALERT_WINDOW_SECONDS
                if (difftime(current_time, alert_timestamp) <= ALERT_WINDOW_SECONDS)
                {
                    json_t *alert = json_object_get(root, "alert");
                    if (json_is_object(alert))
                    {
                        // Extract the signature and category
                        json_t *signature_json = json_object_get(alert, "signature");
                        json_t *category_json = json_object_get(alert, "category");

                        if (json_is_string(signature_json) && json_is_string(category_json))
                        {
                            // Create the alert message
                            char alert_message[MAX_LINE_LENGTH];
                            snprintf(alert_message, sizeof(alert_message), "Category: %s\nSignature: %s", json_string_value(category_json), json_string_value(signature_json));
                            send_notification(alert_message);
                        }
                    }
                }
            }
        }

        json_decref(root);
    }

    fclose(file);
}

int main(int argc, char *argv[])
{
    const char *default_log_file = "/var/log/suricata/eve.json";
    const char *log_file = default_log_file;

    // Check if a log file path is provided as a command-line argument
    if (argc > 1)
    {
        log_file = argv[1];
    }

    process_alerts(log_file);
    return 0;
}
