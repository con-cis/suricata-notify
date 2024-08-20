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

// Global verbose flag
int verbose = 0;

// Function prototypes
void send_notification(const char *alert_message);
time_t convert_iso8601_to_unix(const char *iso8601_timestamp);
void process_alerts(const char *log_file);

// Function to send a desktop notification with signature and category
void send_notification(const char *alert_message)
{
    if (verbose)
    {
        printf("[DEBUG] Sending notification: %s\n", alert_message);
    }

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

    if (verbose)
    {
        printf("[DEBUG] Converting timestamp: %s\n", iso8601_timestamp);
    }

    if (strptime(iso8601_timestamp, "%Y-%m-%dT%H:%M:%S.%6N%z", &tm_time) == NULL)
    {
        fprintf(stderr, "Failed to parse timestamp: %s\n", iso8601_timestamp);
        return (time_t)-1;
    }

    time_t converted_time = mktime(&tm_time) - TIMEZONE_OFFSET_SECONDS;

    if (verbose)
    {
        printf("[DEBUG] Converted time: %ld\n", converted_time);
    }

    return converted_time;
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

    if (verbose)
    {
        printf("[DEBUG] Processing alerts from log file: %s\n", log_file);
    }

    char line[MAX_LINE_LENGTH];
    time_t current_time = time(NULL); // Get the current time

    while (fgets(line, sizeof(line), file) != NULL)
    {
        if (verbose)
        {
            printf("[DEBUG] Reading line: %s\n", line);
        }

        // Load the JSON object from the line
        json_error_t error;
        json_t *root = json_loads(line, 0, &error);
        if (root == NULL)
        {
            // Handle invalid JSON line gracefully
            fprintf(stderr, "Error parsing JSON: %s\n", error.text);
            continue;
        }

        if (verbose)
        {
            printf("[DEBUG] Successfully parsed JSON object.\n");
        }

        // Check if the JSON object has the "event_type" field and it is "alert"
        json_t *event_type = json_object_get(root, "event_type");
        if (event_type && json_is_string(event_type))
        {
            if (verbose)
            {
                printf("[DEBUG] Event type found: %s\n", json_string_value(event_type));
            }

            if (strcmp(json_string_value(event_type), "alert") == 0)
            {
                // Extract the timestamp
                json_t *alert_timestamp_json = json_object_get(root, "timestamp");
                if (alert_timestamp_json && json_is_string(alert_timestamp_json))
                {
                    if (verbose)
                    {
                        printf("[DEBUG] Alert timestamp found: %s\n", json_string_value(alert_timestamp_json));
                    }

                    time_t alert_timestamp = convert_iso8601_to_unix(json_string_value(alert_timestamp_json));

                    // Check if the alert occurred within the last ALERT_WINDOW_SECONDS
                    if (difftime(current_time, alert_timestamp) <= ALERT_WINDOW_SECONDS)
                    {
                        if (verbose)
                        {
                            printf("[DEBUG] Alert occurred within the last %d seconds.\n", ALERT_WINDOW_SECONDS);
                        }

                        json_t *alert = json_object_get(root, "alert");
                        if (alert && json_is_object(alert))
                        {
                            // Extract the signature and category
                            json_t *signature_json = json_object_get(alert, "signature");
                            json_t *category_json = json_object_get(alert, "category");

                            if (signature_json && json_is_string(signature_json) && json_is_string(category_json))
                            {
                                if (verbose)
                                {
                                    printf("[DEBUG] Alert signature: %s\n", json_string_value(signature_json));
                                    printf("[DEBUG] Alert category: %s\n", json_string_value(category_json));
                                }

                                // Create the alert message
                                char alert_message[MAX_LINE_LENGTH];
                                snprintf(alert_message, sizeof(alert_message), "Category: %s\nSignature: %s", json_string_value(category_json), json_string_value(signature_json));

                                if (verbose)
                                {
                                    printf("[DEBUG] Sending notification: %s\n", alert_message);
                                }

                                send_notification(alert_message);
                            }
                            else
                            {
                                if (verbose)
                                {
                                    printf("[DEBUG] Missing or invalid 'signature' or 'category' field in alert.\n");
                                }
                            }
                        }
                        else
                        {
                            if (verbose)
                            {
                                printf("[DEBUG] 'alert' field is missing or is not an object.\n");
                            }
                        }
                    }
                    else
                    {
                        if (verbose)
                        {
                            printf("[DEBUG] Alert is older than %d seconds, skipping notification.\n", ALERT_WINDOW_SECONDS);
                        }
                    }
                }
                else
                {
                    if (verbose)
                    {
                        printf("[DEBUG] Missing or invalid 'timestamp' field in alert.\n");
                    }
                }
            }
        }
        else
        {
            if (verbose)
            {
                printf("[DEBUG] 'event_type' field is missing or is not a string.\n");
            }
        }

        json_decref(root);
    }

    if (verbose)
    {
        printf("[DEBUG] Finished processing alerts.\n");
    }

    fclose(file);
}

int main(int argc, char *argv[])
{
    int is_test = 0;
    const char *suricata_log = "/var/log/suricata/eve.json"; // Default log file path

    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0)
        {
            verbose = 1;
        }
        else if (strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--test") == 0)
        {
            is_test = 1;
        }
        else if (strcmp(argv[i], "-e") == 0 || strcmp(argv[i], "--eve-json") == 0)
        {
            if (i + 1 < argc)
            {
                suricata_log = argv[i + 1]; // Get the log file name
                i++;                        // Skip the log file argument
            }
            else
            {
                fprintf(stderr, "Error: Missing argument for %s\n", argv[i]);
                return EXIT_FAILURE;
            }
        }
        else
        {
            fprintf(stderr, "Unknown argument: %s\n", argv[i]);
            return EXIT_FAILURE;
        }
    }

    if (is_test)
    {
        // Test mode doesn't need the log file, so ignore the -e argument if present
        send_notification("Test notification");
    }
    else
    {
        // Process the alerts from the specified log file
        process_alerts(suricata_log);
    }

    return 0;
}
