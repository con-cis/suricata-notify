#define _XOPEN_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>
#include <time.h>

#define MAX_LINE_LENGTH 4096
#define SEEK_SET 1000
#define TIMEZONE_OFFSET_SECONDS 3600
#define ALERT_WINDOW_SECONDS 60

// Function prototypes
void send_notification(const char *alert_message);
time_t convert_iso8601_to_unix(const char *iso8601_timestamp);
void process_alerts(const char *log_file);

// Function to send a desktop notification with signature and category
void send_notification(const char *alert_message)
{
    char command[MAX_LINE_LENGTH];
    snprintf(command, sizeof(command), "notify-send \"Suricata Alert\" \"%s\"", alert_message);
    system(command);
}

// Function to convert ISO 8601 timestamp to time_t (Unix timestamp)
// Example Timestamp: "timestamp": "2023-08-02T00:05:06.384656+0200",
time_t convert_iso8601_to_unix(const char *iso8601_timestamp)
{
    struct tm tm_time;
    memset(&tm_time, 0, sizeof(struct tm));
    strptime(iso8601_timestamp, "%Y-%m-%dT%H:%M:%S.%6N%z", &tm_time);
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

    // Move the file pointer to the start of the last N lines
    fseek(file, 0, SEEK_END);
    long int total_lines = 0;
    long int pos = ftell(file) - 1;
    while (pos > 0 && total_lines < MAX_LINES_TO_PARSE)
    {
        fseek(file, pos, SEEK_SET);
        if (fgetc(file) == '\n')
        {
            total_lines++;
        }
        pos--;
    }

    // Create a temporary file for the last N lines
    FILE *temp_file = tmpfile();
    if (temp_file == NULL)
    {
        perror("Error creating temporary file");
        fclose(file);
        return;
    }

    // Copy the last N lines into the temporary file
    char line[MAX_LINE_LENGTH];
    while (fgets(line, sizeof(line), file) != NULL)
    {
        fputs(line, temp_file);
    }

    time_t current_time = time(NULL); // Get the current time

    // Process the temporary file
    fseek(temp_file, 0, SEEK_SET); // Reset the temporary file to the beginning
    while (fgets(line, sizeof(line), temp_file) != NULL)
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
        if (event_type && json_is_string(event_type) && strcmp(json_string_value(event_type), "alert") == 0)
        {
            // Extract the timestamp
            json_t *alert_timestamp_json = json_object_get(root, "timestamp");
            if (alert_timestamp_json && json_is_string(alert_timestamp_json))
            {
                time_t alert_timestamp = convert_iso8601_to_unix(json_string_value(alert_timestamp_json));

                // Check if the alert occurred within the last ALERT_WINDOW_SECONDS
                if (difftime(current_time, alert_timestamp) <= ALERT_WINDOW_SECONDS)
                {
                    json_t *alert = json_object_get(root, "alert");
                    if (alert && json_is_object(alert))
                    {
                        // Extract the signature and category
                        json_t *signature_json = json_object_get(alert, "signature");
                        json_t *category_json = json_object_get(alert, "category");

                        if (signature_json && json_is_string(signature_json) && json_is_string(category_json))
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
    fclose(temp_file);
}

int main()
{
    const char *suricata_log = "/var/log/suricata/eve.json";
    process_alerts(suricata_log);
    return 0;
}