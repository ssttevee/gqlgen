package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/99designs/gqlgen/graphql"
	"net/http"
	"regexp"
	"sync"
	"time"

	"github.com/vektah/gqlparser/ast"
)

const pingInterval = 60 * time.Second

var sseContentTypePattern = regexp.MustCompile("(?:^|,)(?:text/event-stream|\\*/\\*)(?:$|,|;)")

func connectSSE(ctx context.Context, w http.ResponseWriter, gh *graphqlHandler, op *ast.OperationDefinition) {
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

	// connection is ready
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
		}

		t.Reset(pingInterval)
	}
}
