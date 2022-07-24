# Redirector

This service allows for temporary http redirects ( 302 Follow ) configureable via API.

## Usage

```bash
go run . --apikey test

curl -XPOST -d 'https://pidrak.in' -H 'APIKEY: test' localhost:8000/test
# Redirect from localhost:8000/test to https://pidrak.in created successfully

curl -I localhost:8000/test
# HTTP/1.1 302 Found
# Content-Type: text/html; charset=utf-8
# Location: https://pidrak.in

```
