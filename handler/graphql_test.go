package handler

import (
	"context"
	"github.com/stretchr/testify/require"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHandlerPOST(t *testing.T) {
	h := GraphQL(&executableSchemaStub{})

	t.Run("success", func(t *testing.T) {
		resp := doRequest(h, "POST", "/graphql", `{"query":"{ me { name } }"}`)
		assert.Equal(t, http.StatusOK, resp.Code)
		assert.Equal(t, `{"data":{"name":"test"}}`, resp.Body.String())
	})

	t.Run("query caching", func(t *testing.T) {
		// Run enough unique queries to evict a bunch of them
		for i := 0; i < 2000; i++ {
			query := `{"query":"` + strings.Repeat(" ", i) + "{ me { name } }" + `"}`
			resp := doRequest(h, "POST", "/graphql", query)
			assert.Equal(t, http.StatusOK, resp.Code)
			assert.Equal(t, `{"data":{"name":"test"}}`, resp.Body.String())
		}

		t.Run("evicted queries run", func(t *testing.T) {
			query := `{"query":"` + strings.Repeat(" ", 0) + "{ me { name } }" + `"}`
			resp := doRequest(h, "POST", "/graphql", query)
			assert.Equal(t, http.StatusOK, resp.Code)
			assert.Equal(t, `{"data":{"name":"test"}}`, resp.Body.String())
		})

		t.Run("non-evicted queries run", func(t *testing.T) {
			query := `{"query":"` + strings.Repeat(" ", 1999) + "{ me { name } }" + `"}`
			resp := doRequest(h, "POST", "/graphql", query)
			assert.Equal(t, http.StatusOK, resp.Code)
			assert.Equal(t, `{"data":{"name":"test"}}`, resp.Body.String())
		})
	})

	t.Run("decode failure", func(t *testing.T) {
		resp := doRequest(h, "POST", "/graphql", "notjson")
		assert.Equal(t, http.StatusBadRequest, resp.Code)
		assert.Equal(t, `{"errors":[{"message":"json body could not be decoded: invalid character 'o' in literal null (expecting 'u')"}],"data":null}`, resp.Body.String())
	})

	t.Run("parse failure", func(t *testing.T) {
		resp := doRequest(h, "POST", "/graphql", `{"query": "!"}`)
		assert.Equal(t, http.StatusUnprocessableEntity, resp.Code)
		assert.Equal(t, `{"errors":[{"message":"Unexpected !","locations":[{"line":1,"column":1}]}],"data":null}`, resp.Body.String())
	})

	t.Run("validation failure", func(t *testing.T) {
		resp := doRequest(h, "POST", "/graphql", `{"query": "{ me { title }}"}`)
		assert.Equal(t, http.StatusUnprocessableEntity, resp.Code)
		assert.Equal(t, `{"errors":[{"message":"Cannot query field \"title\" on type \"User\".","locations":[{"line":1,"column":8}]}],"data":null}`, resp.Body.String())
	})

	t.Run("invalid variable", func(t *testing.T) {
		resp := doRequest(h, "POST", "/graphql", `{"query": "query($id:Int!){user(id:$id){name}}","variables":{"id":false}}`)
		assert.Equal(t, http.StatusUnprocessableEntity, resp.Code)
		assert.Equal(t, `{"errors":[{"message":"cannot use bool as Int","path":["variable","id"]}],"data":null}`, resp.Body.String())
	})

	t.Run("execution failure", func(t *testing.T) {
		resp := doRequest(h, "POST", "/graphql", `{"query": "mutation { me { name } }"}`)
		assert.Equal(t, http.StatusOK, resp.Code)
		assert.Equal(t, `{"errors":[{"message":"mutations are not supported"}],"data":null}`, resp.Body.String())
	})
}

func TestHandlerGET(t *testing.T) {
	h := GraphQL(&executableSchemaStub{})

	t.Run("success", func(t *testing.T) {
		resp := doRequest(h, "GET", "/graphql?query={me{name}}", ``)
		assert.Equal(t, http.StatusOK, resp.Code)
		assert.Equal(t, `{"data":{"name":"test"}}`, resp.Body.String())
	})

	t.Run("decode failure", func(t *testing.T) {
		resp := doRequest(h, "GET", "/graphql?query=me{id}&variables=notjson", "")
		assert.Equal(t, http.StatusBadRequest, resp.Code)
		assert.Equal(t, `{"errors":[{"message":"variables could not be decoded"}],"data":null}`, resp.Body.String())
	})

	t.Run("invalid variable", func(t *testing.T) {
		resp := doRequest(h, "GET", `/graphql?query=query($id:Int!){user(id:$id){name}}&variables={"id":false}`, "")
		assert.Equal(t, http.StatusUnprocessableEntity, resp.Code)
		assert.Equal(t, `{"errors":[{"message":"cannot use bool as Int","path":["variable","id"]}],"data":null}`, resp.Body.String())
	})

	t.Run("parse failure", func(t *testing.T) {
		resp := doRequest(h, "GET", "/graphql?query=!", "")
		assert.Equal(t, http.StatusUnprocessableEntity, resp.Code)
		assert.Equal(t, `{"errors":[{"message":"Unexpected !","locations":[{"line":1,"column":1}]}],"data":null}`, resp.Body.String())
	})

	t.Run("no mutations", func(t *testing.T) {
		resp := doRequest(h, "GET", "/graphql?query=mutation{me{name}}", "")
		assert.Equal(t, http.StatusUnprocessableEntity, resp.Code)
		assert.Equal(t, `{"errors":[{"message":"GET requests only allow query operations"}],"data":null}`, resp.Body.String())
	})
}

func TestHandlerOptions(t *testing.T) {
	h := GraphQL(&executableSchemaStub{})

	resp := doRequest(h, "OPTIONS", "/graphql?query={me{name}}", ``)
	assert.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, "OPTIONS, GET, POST", resp.HeaderMap.Get("Allow"))
}

func TestHandlerHead(t *testing.T) {
	h := GraphQL(&executableSchemaStub{})

	resp := doRequest(h, "HEAD", "/graphql?query={me{name}}", ``)
	assert.Equal(t, http.StatusMethodNotAllowed, resp.Code)
}

func TestHandlerSSE(t *testing.T) {
	next := make(chan struct{})
	h := GraphQL(&executableSchemaStub{next})

	srv := httptest.NewServer(h)
	defer srv.Close()

	const query = `subscription{user{title}}`

	t.Run("connection must be kept alive", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/graphql?query="+query, nil)
		w := httptest.NewRecorder()

		h.ServeHTTP(w, r)

		require.Equal(t, http.StatusBadRequest, w.Code)
		require.Equal(t, `{"data":null,"errors":[{"message":"connection must be \"keep-alive\""}]}`, w.Body.String())
	})

	t.Run("request must be accept event stream", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/graphql?query="+query, nil)
		w := httptest.NewRecorder()

		r.Header.Set("Connection", "keep-alive")

		h.ServeHTTP(w, r)

		require.Equal(t, http.StatusBadRequest, w.Code)
		require.Equal(t, `{"data":null,"errors":[{"message":"request must accept \"text/event-stream\""}]}`, w.Body.String())
	})

	t.Run("client can receive data", func(t *testing.T) {
		read, cancel := sseConnect(h, "/graphql?query="+query)
		defer cancel()

		for i := 0; i < 2; i++ {
			next <- struct{}{}
			data, err := read()
			require.NoError(t, err)
			require.Equal(t, data, `{"data":{"name":"test"}}`)
		}
	})
}

func doRequest(handler http.Handler, method string, target string, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)
	return w
}

func sseConnect(handler http.Handler, target string) (func() (string, error), func()) {
	r := httptest.NewRequest(http.MethodGet, target, nil)
	w := httptest.NewRecorder()

	r.Header.Set("Connection", "keep-alive")
	r.Header.Set("Accept", "text/event-stream")

	cctx, cancel := context.WithCancel(r.Context())

	done := make(chan struct{})
	go func() {
		handler.ServeHTTP(w, r.WithContext(cctx))
		close(done)
	}()

	return func() (string, error) {
		defer w.Body.Reset()
		var s string
		for s == "" {
			runtime.Gosched()
			select {
			case <-done:
				return "", io.EOF
			default:
				s = w.Body.String()
			}
		}
		return s[6 : len(s)-2], nil
	}, cancel
}
