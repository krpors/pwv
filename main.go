package main

// https://documenter.getpostman.com/view/998920/cyberark-rest-api-v10-public/2QrXnF#397e7f83-7605-d1b3-8077-9fd65f978537

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"syscall"

	"golang.org/x/crypto/ssh/terminal"
)

var (
	flagBaseURL         = flag.String("url", "https://pwv.europe.intranet", "The base URL for the PasswordVault")
	flagUsername        = flag.String("username", "", "The username to login with into CyberArk")
	flagPassword        = flag.String("password", "", "The password. If not given, it's requested by the program")
	flagAllowedCorpKeys = flag.String("allowedusers", "", "The allowed users, separated by commas")
	flagConfirmReason   = flag.String("reason", "Automatically accepted! You're welcome.", "Confirmation reason.")
	flagOperation       = flag.String("operation", "list", "Operation to execute (list|approve|retrieve)")
)

func usage() {
	fmt.Fprintf(os.Stderr, "pwv: \n")
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, "Examples:\n\n")
	fmt.Fprintf(os.Stderr, "pwv -username CORPKEY -operation approve -allowedusers KEY1,Key2,KEY3\n")
	fmt.Fprintf(os.Stderr, "pwv -username CORPKEY -operation list\n")
}

func listIncoming(api *caAPI) {
	incomingRequests, err := api.IncomingRequests()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	} else {
		if len(incomingRequests.IncomingRequests) == 0 {
			fmt.Println("There are no incoming requests.")
		} else {
			for _, a := range incomingRequests.IncomingRequests {
				fmt.Printf("Incoming: %s, '%s' ('%s')\n",
					a.RequestorUserName,
					a.AccountDetails.Properties.Name,
					a.UserReason)
			}
		}
	}
}

func approveIncoming(api *caAPI, allowedCorporateKeys string) {
	corpkeys := strings.Trim(allowedCorporateKeys, " ")
	if corpkeys == "" {
		fmt.Fprintf(os.Stderr, "No corporate keys specified using `-users'.\n")
		os.Exit(1)
	}

	users := make(map[string]bool)
	_ = users
	for _, u := range strings.Split(corpkeys, ",") {
		u = strings.Trim(u, " ")
		u = strings.ToUpper(u)
		users[u] = true
	}

	incomingRequests, err := api.IncomingRequests()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	} else {
		if len(incomingRequests.IncomingRequests) == 0 {
			fmt.Println("There are no incoming requests.")
		} else {
			for _, a := range incomingRequests.IncomingRequests {
				requestor := strings.ToUpper(a.RequestorUserName)
				if _, ok := users[requestor]; ok {
					fmt.Printf("Confirming: %s, '%s' ('%s')... ", requestor, a.AccountDetails.Properties.Name, a.UserReason)
					err := api.ConfirmRequest(a, *flagConfirmReason)
					if err != nil {
						fmt.Println("failed!")
						fmt.Fprintf(os.Stderr, "Unable to confirm request: %s\n", err)
					} else {
						fmt.Println("ok!")
					}
				} else {
					fmt.Printf("Ignoring: %s, \"%s\" from %v to %v\n", requestor, a.UserReason, a.AccessFrom, a.AccessTo)
				}
			}
		}
	}
}

func retrieve(ca *caAPI) {
	reqs, err := ca.MyRequests()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	if len(reqs.MyRequests) == 0 {
		fmt.Println("There are no requests.")
		os.Exit(0)
	}

	for _, r := range reqs.MyRequests {
		passwd, err := ca.GetPassword(r)
		if err != nil {
			// what
			continue
		}
		fmt.Printf("%s = %s\n", r.AccountDetails.Properties.Name, passwd)
	}
}

func logout(api *caAPI) {
	err := api.Logout()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to logout: %s\n", err)
	}
}

func main() {
	flag.Usage = usage
	flag.Parse()

	if *flagUsername == "" {
		fmt.Fprintln(os.Stderr, "No username given with -username")
		os.Exit(1)
	}

	var password string

	if *flagPassword != "" {
		password = *flagPassword
	} else {
		fmt.Printf("%s's Password: ", *flagUsername)
		pwd, err := terminal.ReadPassword(int(syscall.Stdin))
		password = string(pwd)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Println()
	}

	// Create our own transport to discard any certificate errors since some
	// companies injects their own cruft anyway.
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	api := caAPI{}
	api.Base = *flagBaseURL
	api.Client = http.Client{Transport: tr}

	err := api.Login(*flagUsername, password)
	if err != nil {
		fmt.Printf("Could not login: %s\n", err)
		os.Exit(1)
	}
	defer logout(&api)

	if *flagOperation == "list" {
		listIncoming(&api)
	} else if *flagOperation == "approve" {
		approveIncoming(&api, *flagAllowedCorpKeys)
	} else if *flagOperation == "retrieve" {
		retrieve(&api)
	}
}
