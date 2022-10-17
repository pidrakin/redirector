package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var GlobalRedriects map[string]string
var ApiKey string
var Hooks []string

func setupSocket(socketPath string) (listener net.Listener, err error) {
	os.Remove(socketPath)

	listener, err = net.Listen("unix", socketPath)
	if err != nil {
		log.Debug().Err(err).Str("socket", socketPath).Msg("Could not create socket")
		return nil, err
	}
	os.Chmod(socketPath, 0770)

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		<-c
		os.Remove(socketPath)
		os.Exit(0)
	}()
	return listener, err
}

func IsIPv4(address string) bool {
	return strings.Count(address, ":") < 2
}

func getListener(socketPath string, address string) (listener net.Listener) {
	if socketPath != "" {
		listener, err := setupSocket(socketPath)
		if err == nil {
			return listener
		}
	}
	network := "tcp"
	if IsIPv4(address) {
		network = "tcp4"
	}
	listener, err := net.Listen(network, address)
	if err != nil {
		log.Fatal().Err(err).Str("address", address).Msg("Could not create socket")
		return
	}
	return listener
}

func httpListener(listener net.Listener) {
	defer listener.Close()
	err := http.Serve(listener, nil)
	if err != nil {
		log.Fatal().Err(err).Msg("Could not start HTTP server")
	}
}

func checkDomainTXT(domain string, url string) (record string) {
	clean_url := "redirector"
	if len(url) > 1 {
		clean_url = fmt.Sprintf("%s.redirector", strings.Replace(url[1:], "/", "_", -1))
	}
	txtDomain := fmt.Sprintf("%s.%s", clean_url, domain)
	records, err := net.LookupTXT(txtDomain)
	if err != nil {
		log.Warn().Err(err).Msg("DNS Lookup failed")
	}
	if len(records) > 0 {
		log.Debug().Msgf("Found DNS records: %s", records)
		return records[0]
	}
	return ""
}

func handler(w http.ResponseWriter, r *http.Request) {
	uri := r.Host + r.URL.Path

	log.Debug().Str("URI", uri).Msg("Handling Request")

	switch r.Method {
	case "GET", "HEAD":
		if dest, ok := GlobalRedriects[uri]; ok {
			log.Debug().Msgf("Redirect To: %s", dest)
			http.Redirect(w, r, dest, http.StatusFound)
			return
		}
		if record := checkDomainTXT(r.Host, r.URL.Path); record != "" {
			log.Debug().Msgf("Redirect To: %s", record)
			http.Redirect(w, r, record, http.StatusFound)
			return
		}
	case "POST":
		api := r.Header.Get("APIKEY")
		if api != ApiKey {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Auth Failed"))
			return
		}
		redirectDestination, err := ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		responseBody := fmt.Sprintf("Redirect from %s to %s created successfully\n", uri, redirectDestination)
		destinationDomain, _ := url.Parse(string(redirectDestination))
		err = executeHook(uri, destinationDomain.Hostname())
		if err != nil {
			responseBody = fmt.Sprintf("Hook for Redirect from %s to %s Failed: %s\n", uri, redirectDestination, err.Error())
		}

		GlobalRedriects[uri] = string(redirectDestination)
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/text")
		w.Write([]byte(responseBody))
		return
	}
	w.WriteHeader(http.StatusNotFound)
	w.Header().Set("Content-Type", "application/text")
	w.Write([]byte("Not Found"))
}

func LookupEnvOrString(key string, defaultVal string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return defaultVal
}

func tokenGenerator() string {
	b := make([]byte, 16)
	rand.Read(b)
	token := fmt.Sprintf("%X-%X-%X-%X", b[0:4], b[4:8], b[8:12], b[12:])
	return token
}

func findHooks(path string) (hooks []string) {
	files, err := os.ReadDir(path)
	if err != nil {
		return
	}

	for _, file := range files {
		filePath, _ := filepath.Abs(filepath.Join(path, file.Name()))
		hooks = append(hooks, filePath)
	}
	log.Debug().Msgf("Hooks loaded: %v", hooks)

	return
}

func findHook(hostname string) (found bool, hookName string) {
	for _, hook := range Hooks {
		if strings.Contains(hook, "default") {
			hookName = hook
		}
		if strings.Contains(hook, hostname) {
			hookName = hook
		}
	}

	if info, osErr := os.Stat(hookName); !os.IsNotExist(osErr) {
		if isExecutable(info.Mode()) {
			return true, hookName
		}
	}
	return false, hookName
}

func isExecutable(mode os.FileMode) bool {
	return mode&0111 != 0
}

func executeHook(uri string, destination string) error {
	found, hook := findHook(destination)
	if !found {
		log.Debug().Msg("No hook found")
		return nil
	}
	log.Debug().Msgf("Executing hook: %s", hook)

	cmd := exec.Command(hook, uri, destination)
	err := cmd.Run()
	return err
}

func main() {
	var (
		socketFile string
		address    string
		hookspath  string
		debug      bool
	)

	flag.StringVar(&socketFile, "socket", LookupEnvOrString("SOCKET_FILE", "/run/redirector/socket"), "The TCP Socket to open")
	flag.StringVar(&address, "address", LookupEnvOrString("LISTEN_ADDRESS", "127.0.0.1:8000"), "The TCP Socket to listen on [e.g: 127.0.0.1:8000]")
	flag.StringVar(&ApiKey, "apikey", LookupEnvOrString("APIKEY", tokenGenerator()), "API Key to update records")
	flag.StringVar(&hookspath, "hooks", LookupEnvOrString("HOOKS_PATH", "hooks"), "Path to hooks to call on update")

	flag.BoolVar(&debug, "debug", false, "Run in Debug mode")
	flag.Parse()

	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	if debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
		log.Debug().Msg("Debug Mode enabled")
	}

	log.Info().Str("API-Key", ApiKey).Msg("API-KEY")

	GlobalRedriects = make(map[string]string)
	Hooks = findHooks(hookspath)
	listener := getListener(socketFile, address)
	http.HandleFunc("/", handler)
	log.Info().Str("listener", listener.Addr().String()).Msg("Started Listening")
	httpListener(listener)
}
