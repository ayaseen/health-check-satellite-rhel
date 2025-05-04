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
 ____  _   _ _____ _     
|  _ \| | | | ____| |    
| |_) | |_| |  _| | |    
|  _ <|  _  | |___| |___ 
|_| \_\_| |_|_____|_____|
 ____    _  _____ _____ _     _     ___ _____ _____ 
/ ___|  / \|_   _| ____| |   | |   |_ _|_   _| ____|
\___ \ / _ \ | | |  _| | |   | |    | |  | | |  _|  
 ___) / ___ \| | | |___| |___| |___ | |  | | | |___ 
|____/_/   \_\_| |_____|_____|_____|___| |_| |_____|
 _   _ _____    _    _   _____ _   _    ____ _   _ _____ ____ _  __
| | | | ____|  / \  | | |_   _| | | |  / ___| | | | ____/ ___| |/ /
| |_| |  _|   / _ \ | |   | | | |_| | | |   | |_| |  _|| |   | ' / 
|  _  | |___ / ___ \| |___| | |  _  | | |___|  _  | |__| |___| . \ 
|_| |_|_____/_/   \_\_____|_| |_| |_|  \____|_| |_|_____\____|_|\_\
                                                                                            
 Version: 1.0.0
 By: Amjad Yaseen <ayaseen@redhat.com>
 Started at: %s
`
	fmt.Printf(banner, time.Now().Format("2006-01-02 15:04:05"))
}
