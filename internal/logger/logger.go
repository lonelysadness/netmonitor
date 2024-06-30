package logger

import (
    "log"
    "os"
)

var (
    // Log is the main logger for the application
    Log *log.Logger
)

func init() {
    logFile, err := os.OpenFile("netmonitor.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
    if err != nil {
        log.Fatalf("Failed to open log file: %v", err)
    }

    Log = log.New(logFile, "", log.Ldate|log.Ltime|log.Lshortfile)

    // Redirect the standard logger output to the custom logger
    log.SetOutput(Log.Writer())
}

