// main.go
package main

import (
	"fmt"
	"os"
	"time"

	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/cmd"
)

func main() {
	startTime := time.Now()

	// Print banner
	printBanner()

	// Execute the root command
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	elapsedTime := time.Since(startTime)
	fmt.Printf("\nTotal execution time: %s\n", elapsedTime)
}

func printBanner() {
	banner := `
  _____  _    _  ______  _       _    _            _   _   _      _____ _               _    
 |  __ \| |  | ||  ____|| |     | |  | |          | | | | | |    / ____| |             | |   
 | |__) | |__| || |__   | |     | |__| | ___  __ _| |_| |_| |__ | |    | |__   ___  ___| | __
 |  _  /|  __  ||  __|  | |     |  __  |/ _ \/ _' | __| __| '_ \| |    | '_ \ / _ \/ __| |/ /
 | | \ \| |  | || |____ | |____ | |  | |  __/ (_| | |_| |_| | | | |____| | | |  __/ (__|   < 
 |_|  \_\_|  |_||______||______||_|  |_|\___|\__,_|\__|\__|_| |_|\_____|_| |_|\___|\___|_|\_\
                                                                                            
 Version: 1.0.0
 By: Amjad Yaseen <ayaseen@redhat.com>
 Started at: %s
`
	fmt.Printf(banner, time.Now().Format("2006-01-02 15:04:05"))
}
