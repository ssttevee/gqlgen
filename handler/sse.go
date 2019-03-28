package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"regexp"
	"sync"
	"time"

	"github.com/99designs/gqlgen/graphql"
	"github.com/vektah/gqlparser/ast"
)

const pingInterval = 60 * time.Second

var sseContentTypePattern = regexp.MustCompile("(?:^|,)(?:text/event-stream|\\*/\\*)(?:$|,|;)")

func (gh *graphqlHandler) Close() {
	gh.mu.Lock()
	defer gh.mu.Unlock()

	for _, closeFunc := range gh.closeFuncs {
		closeFunc()
	}

	gh.closeFuncs = map[int64]func(){}
}

func (gh *graphqlHandler) registerCloser(f func()) int64 {
	gh.mu.Lock()
	defer gh.mu.Unlock()

	var id int64
	for {
		id = rand.Int63()
		if _, ok := gh.closeFuncs[id]; !ok {
			break
		}
	}

	gh.closeFuncs[id] = f

	return id
}

func (gh *graphqlHandler) unregisterCloser(id int64) {
	gh.mu.Lock()
	defer gh.mu.Unlock()

	delete(gh.closeFuncs, id)
}

func (gh *graphqlHandler) connectSSE(ctx context.Context, w http.ResponseWriter, op *ast.OperationDefinition) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		panic("w must implement http.Flusher")
	}

	if gh.cfg.subscriptionHook != nil {
		var err error
		ctx, err = gh.cfg.subscriptionHook(ctx, func(ctx context.Context) (context.Context, error) {
			return ctx, nil
		})
		if err != nil {
			sendErrorf(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Connection", "keep-alive")

	flusher.Flush()

	done := make(chan struct{})
	defer gh.unregisterCloser(gh.registerCloser(func() {
		close(done)
	}))

	// connection is ready

	var mu sync.Mutex
	push := func(data *graphql.Response) {
		mu.Lock()
		defer mu.Unlock()

		b, _ := json.Marshal(data)
		fmt.Fprintf(w, "data: %s\n\n", b)
		flusher.Flush()
	}

	results := make(chan *graphql.Response)
	go func() {
		defer close(results)

		for next := gh.exec.Subscription(ctx, op); ; {
			result := next()
			if result == nil {
				return
			}

			results <- result
		}
	}()

	t := time.NewTimer(pingInterval)
	for {
		select {
		case result, ok := <-results:
			if !ok {
				return
			}

			push(result)

			if !t.Stop() {
				<-t.C
			}

		case <-t.C:
			push(&graphql.Response{Data: []byte(`"ping"`)})

		case <-ctx.Done():
			return

		case <-done:
			return

		}

		t.Reset(pingInterval)
	}
}
