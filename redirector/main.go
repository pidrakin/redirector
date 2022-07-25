package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/signal"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var GlobalRedriects map[string]string
var ApiKey string

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

func getListener(socketPath string, address string) (listener net.Listener) {
	if socketPath != "" {
		listener, err := setupSocket(socketPath)
		if err == nil {
			return listener
		}
	}
	listener, err := net.Listen("tcp", address)
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
	case "POST":
		api := r.Header.Get("APIKEY")
		if api != ApiKey {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Auth Failed"))
			return
		}
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		GlobalRedriects[uri] = string(body)
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/text")
		successMsg := fmt.Sprintf("Redirect from %s to %s created successfully", uri, body)
		w.Write([]byte(successMsg))
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

func main() {
	var (
		socketFile string
		address    string
		debug      bool
	)

	flag.StringVar(&socketFile, "socket", LookupEnvOrString("SOCKET_FILE", "/run/redirector/socket"), "The TCP Socket to open")
	flag.StringVar(&address, "address", LookupEnvOrString("LISTEN_ADDRESS", "127.0.0.1:8000"), "The TCP Socket to listen on [e.g: 127.0.0.1:8000]")
	flag.StringVar(&ApiKey, "apikey", LookupEnvOrString("APIKEY", tokenGenerator()), "The config File to read in")
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

	listener := getListener(socketFile, address)
	http.HandleFunc("/", handler)
	log.Info().Str("listener", listener.Addr().String()).Msg("Started Listening")
	httpListener(listener)
}
