package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/aykay76/pki-go/pkg/core/pki"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// TODO: make my root directory configurable
		filename := "./web" + r.URL.Path

		// add default document
		if filename == "./web/" {
			filename = "./web/index.html"
		}

		// TODO: maybe improve the logging a bit ;)
		fmt.Println(filename)

		body, _ := ioutil.ReadFile(filename)

		if strings.HasSuffix(filename, ".css") {
			w.Header().Set("Content-Type", "text/css")
		} else if strings.HasSuffix(filename, ".svg") {
			w.Header().Set("Content-Type", "image/svg+xml")
		} else if strings.HasSuffix(filename, ".html") {
			w.Header().Set("Content-Type", "text/html")

			// convert to string and do some basic SSI
			bodyString := string(body)

			idx := strings.Index(bodyString, "<!--#include file=")
			for idx != -1 {
				idx2 := strings.Index(bodyString, "-->")
				subfile := bodyString[idx+19 : idx2-1]

				subfileContent, _ := ioutil.ReadFile("./web" + subfile)

				newBodyString := bodyString[0:idx] + string(subfileContent) + bodyString[idx2+3:len(bodyString)]
				bodyString = newBodyString
				idx = strings.Index(bodyString, "<!--#include file=")
			}

			body = []byte(bodyString)
		} else if strings.HasSuffix(filename, ".js") {
			w.Header().Set("Content-Type", "text/javascript")
		}

		w.Write(body)
	})

	// TODO: move these to controllers that will return views in the form of template or static file; or execute code that returns free content
	//       this enforces a structure to the urls so that they can be parsed, but that's no different to ASP or other frameworks

	http.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("Inside generic API handler")
		if r.Method == "POST" {
			r.ParseForm()
		}
		fmt.Println(r.Method)
		fmt.Println(r.URL.Path)
		fmt.Println(r.PostForm.Get("commonName"))
	})

	http.HandleFunc("/api/v1/pki/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("Inside generic PKI handler")
		fmt.Println(r)
	})

	http.HandleFunc("/api/v1/pki/root/create", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			r.ParseForm()

			commonName := r.PostForm.Get("commonName")
			organisation := r.PostForm.Get("organisation")
			organisationalUnit := r.PostForm.Get("organisationalUnit")
			province := r.PostForm.Get("province")
			locality := r.PostForm.Get("locality")
			streetAddress := r.PostForm.Get("streetAddress")
			postalCode := r.PostForm.Get("postalCode")

			pki.NewCA(commonName, organisation, organisationalUnit, province, locality, streetAddress, postalCode)
		}
	})

	http.HandleFunc("/api/v1/pki/root/list", func(w http.ResponseWriter, r *http.Request) {
		roots := pki.ListCA()

		json, _ := json.Marshal(roots)

		w.Write(json)
	})

	http.HandleFunc("/api/v1/pki/root/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			w.WriteHeader(403)
		}

		id := strings.Replace(r.URL.EscapedPath(), "/api/v1/pki/root/", "", 1)
		cert := pki.GetCACert(id)
		fmt.Fprintf(w, cert)
	})

	// /api/v1/pki/csr/{authority}
	http.HandleFunc("/api/v1/pki/csr/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.Replace(r.URL.EscapedPath(), "/api/v1/pki/csr/", "", 1)

		if r.Method == "GET" {
			// TODO: get a CSR from this instance to be signed by a higher level authority
		} else if r.Method == "POST" {
			// post a CSR to an authority to get it signed
			csr, _ := ioutil.ReadAll(r.Body)
			fmt.Println(csr)
			cert := pki.SignCSR(id, string(csr))
			fmt.Fprintf(w, cert)
		}
	})

	http.HandleFunc("/api/v1/pki/cert/", func(w http.ResponseWriter, r *http.Request) {
		params := strings.Replace(r.URL.EscapedPath(), "/api/v1/pki/", "", 1)

		var parms map[string]string
		parms = make(map[string]string)
		parts := strings.Split(params, "/")
		key := true
		k := ""
		for _, p := range parts {
			if key {
				k = p
			} else {
				parms[k] = p
			}
			key = !key
		}

		fmt.Println(parms)

		// TODO: need to split the rest of the path to get CA identifier and Cert SN

		if r.Method == "DELETE" {
			// revoke the cert
			pki.RevokeCertificate(parms["ca"], parms["cert"])
		}
	})

	fmt.Println("Listening on http://localhost:8080")
	http.ListenAndServe(":8080", nil)
}
