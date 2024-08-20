#define _XOPEN_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>

#define DEFAULT_MAX_LINE_LENGTH 4096
#define DEFAULT_TIMEZONE_OFFSET_SECONDS 3600
#define DEFAULT_ALERT_WINDOW_SECONDS 60

// Global variables for configuration
int verbose = 0;
size_t max_line_length = DEFAULT_MAX_LINE_LENGTH;
int timezone_offset_seconds = DEFAULT_TIMEZONE_OFFSET_SECONDS;
int alert_window_seconds = DEFAULT_ALERT_WINDOW_SECONDS;

// Function prototypes
void send_notification(const char *alert_message);
time_t convert_iso8601_to_unix(const char *iso8601_timestamp);
void process_alerts(const char *log_file);
void print_help(void);

// Add the help message function
void print_help(void)
{
    printf("Usage: suricata-notify [options]\n");
    printf("Options:\n");
    printf("  -h, --help                 Show this help message and exit\n");
    printf("  -v, --verbose              Enable verbose output\n");
    printf("  -t, --test                 Run in test mode (send a test notification)\n");
    printf("  -e, --eve-json <file>      Specify the Suricata EVE JSON log file (default: /var/log/suricata/eve.json)\n");
    printf("  -l, --line-length <length> Set the maximum line length for reading the log file (default: %d)\n", DEFAULT_MAX_LINE_LENGTH);
    printf("  -z, --timezone-offset <s>  Set the timezone offset in seconds (default: %d)\n", DEFAULT_TIMEZONE_OFFSET_SECONDS);
    printf("  -w, --alert-window <s>     Set the alert window in seconds (default: %d)\n", DEFAULT_ALERT_WINDOW_SECONDS);
}

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

    // Parse the timestamp up to seconds
    if (strptime(iso8601_timestamp, "%Y-%m-%dT%H:%M:%S", &tm_time) == NULL)
    {
        fprintf(stderr, "Failed to parse timestamp: %s\n", iso8601_timestamp);
        return (time_t)-1;
    }

    // Convert to time_t (Unix timestamp)
    time_t converted_time = mktime(&tm_time);

    if (verbose)
    {
        printf("[DEBUG] Converted time: %ld\n", (long)converted_time);
    }

    return converted_time;
}

void get_iso8601_timestamp(char *buffer, size_t buffer_size)
{
    struct timeval tv;
    gettimeofday(&tv, NULL); // Get the current time including microseconds

    struct tm tm_info;
    gmtime_r(&tv.tv_sec, &tm_info); // Convert to UTC

    // Format date and time including seconds
    strftime(buffer, buffer_size, "%Y-%m-%dT%H:%M:%S", &tm_info);

    // Append microseconds and timezone
    snprintf(buffer + strlen(buffer), buffer_size - strlen(buffer), ".%06ld+0000", tv.tv_usec);
}

int sanitize_file_input(const char *log_file)
{
    if (log_file == NULL)
    {
        fprintf(stderr, "Error: log_file is NULL.\n");
        return -1;
    }

    // Check for potential path traversal (../)
    if (strstr(log_file, "../") != NULL)
    {
        fprintf(stderr, "Error: log_file path contains path traversal components.\n");
        return -1;
    }

    // Check file permissions and type
    struct stat file_stat;
    if (stat(log_file, &file_stat) != 0)
    {
        perror("Error: stat failed");
        return -1;
    }

    // Ensure it's a regular file
    if (!S_ISREG(file_stat.st_mode))
    {
        fprintf(stderr, "Error: log_file is not a regular file.\n");
        return -1;
    }

    // Ensure the file is readable
    if ((file_stat.st_mode & S_IRUSR) == 0)
    {
        fprintf(stderr, "Error: log_file is not readable by the user.\n");
        return -1;
    }

    return 0; // Return 0 if all checks pass
}

// Function to process Suricata alerts and trigger notifications
void process_alerts(const char *log_file)
{
    // Sanitize the file path before opening
    if (sanitize_file_input(log_file) != 0)
    {
        exit(EXIT_FAILURE);
    }
    
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

    char *line = (char *)malloc(max_line_length);
    if (line == NULL)
    {
        perror("Error allocating memory for line buffer");
        fclose(file);
        return;
    }

    time_t current_time = time(NULL); // Get the current time

    if (verbose)
    {
        printf("[DEBUG] Current Time: %ld\n", (long)current_time);
        char iso8601_timestamp[40];
        get_iso8601_timestamp(iso8601_timestamp, sizeof(iso8601_timestamp));

        printf("[DEBUG] Current Time: %s\n", iso8601_timestamp);
    }

    while (fgets(line, max_line_length, file) != NULL)
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
                    if (difftime(current_time, alert_timestamp) <= alert_window_seconds)
                    {
                        if (verbose)
                        {
                            double diff = difftime(current_time, alert_timestamp);
                            printf("[DEBUG] Alert occurred within the last %d seconds with a diff of %.0f seconds.\n", alert_window_seconds, diff);
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
                                char alert_message[max_line_length];
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
                            printf("[DEBUG] Alert is older than %d seconds, skipping notification.\n", alert_window_seconds);
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

    free(line);
    fclose(file);
}

int main(int argc, char *argv[])
{
    int is_test = 0;
    const char *suricata_log = "/var/log/suricata/eve.json"; // Default log file path

    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0)
        {
            print_help();
            return EXIT_SUCCESS;
        }
        else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0)
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
        else if (strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "--line-length") == 0)
        {
            if (i + 1 < argc)
            {
                max_line_length = strtoul(argv[i + 1], NULL, 10);
                i++;
            }
            else
            {
                fprintf(stderr, "Error: Missing argument for %s\n", argv[i]);
                return EXIT_FAILURE;
            }
        }
        else if (strcmp(argv[i], "-z") == 0 || strcmp(argv[i], "--timezone-offset") == 0)
        {
            if (i + 1 < argc)
            {
                timezone_offset_seconds = atoi(argv[i + 1]);
                i++;
            }
            else
            {
                fprintf(stderr, "Error: Missing argument for %s\n", argv[i]);
                return EXIT_FAILURE;
            }
        }
        else if (strcmp(argv[i], "-w") == 0 || strcmp(argv[i], "--alert-window") == 0)
        {
            if (i + 1 < argc)
            {
                alert_window_seconds = atoi(argv[i + 1]);
                i++;
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
