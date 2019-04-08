package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/99designs/gqlgen/complexity"
	"github.com/99designs/gqlgen/graphql"
	"github.com/gorilla/websocket"
	"github.com/hashicorp/golang-lru"
	"github.com/vektah/gqlparser/ast"
	"github.com/vektah/gqlparser/gqlerror"
	"github.com/vektah/gqlparser/parser"
	"github.com/vektah/gqlparser/validator"
	"io"
	"net/http"
	"strings"
	"sync"
)

type params struct {
	ID            string                 `json:"id"`
	Query         string                 `json:"query"`
	OperationName string                 `json:"operationName"`
	Variables     map[string]interface{} `json:"variables"`
}

type Config struct {
	cacheSize            int
	upgrader             websocket.Upgrader
	recover              graphql.RecoverFunc
	errorPresenter       graphql.ErrorPresenterFunc
	resolverHook         graphql.FieldMiddleware
	requestHook          graphql.RequestMiddleware
	subscriptionHook     graphql.SubscriptionMiddleware
	tracer               graphql.Tracer
	complexityLimit      int
	disableIntrospection bool
}

func (c *Config) newRequestContext(es graphql.ExecutableSchema, doc *ast.QueryDocument, op *ast.OperationDefinition, query string, variables map[string]interface{}) *graphql.RequestContext {
	reqCtx := graphql.NewRequestContext(doc, query, variables)
	reqCtx.DisableIntrospection = c.disableIntrospection

	if hook := c.recover; hook != nil {
		reqCtx.Recover = hook
	}

	if hook := c.errorPresenter; hook != nil {
		reqCtx.ErrorPresenter = hook
	}

	if hook := c.resolverHook; hook != nil {
		reqCtx.ResolverMiddleware = hook
	}

	if hook := c.requestHook; hook != nil {
		reqCtx.RequestMiddleware = hook
	}

	if hook := c.tracer; hook != nil {
		reqCtx.Tracer = hook
	} else {
		reqCtx.Tracer = &graphql.NopTracer{}
	}

	if c.complexityLimit > 0 {
		reqCtx.ComplexityLimit = c.complexityLimit
		operationComplexity := complexity.Calculate(es, op, variables)
		reqCtx.OperationComplexity = operationComplexity
	}

	return reqCtx
}

type Option func(cfg *Config)

func WebsocketUpgrader(upgrader websocket.Upgrader) Option {
	return func(cfg *Config) {
		cfg.upgrader = upgrader
	}
}

func RecoverFunc(recover graphql.RecoverFunc) Option {
	return func(cfg *Config) {
		cfg.recover = recover
	}
}

// ErrorPresenter transforms errors found while resolving into errors that will be returned to the user. It provides
// a good place to add any extra fields, like error.type, that might be desired by your frontend. Check the default
// implementation in graphql.DefaultErrorPresenter for an example.
func ErrorPresenter(f graphql.ErrorPresenterFunc) Option {
	return func(cfg *Config) {
		cfg.errorPresenter = f
	}
}

// IntrospectionEnabled = false will forbid clients from calling introspection endpoints. Can be useful in prod when you dont
// want clients introspecting the full schema.
func IntrospectionEnabled(enabled bool) Option {
	return func(cfg *Config) {
		cfg.disableIntrospection = !enabled
	}
}

// ComplexityLimit sets a maximum query complexity that is allowed to be executed.
// If a query is submitted that exceeds the limit, a 422 status code will be returned.
func ComplexityLimit(limit int) Option {
	return func(cfg *Config) {
		cfg.complexityLimit = limit
	}
}

// ResolverMiddleware allows you to define a function that will be called around every resolver,
// useful for logging.
func ResolverMiddleware(middleware graphql.FieldMiddleware) Option {
	return func(cfg *Config) {
		if cfg.resolverHook == nil {
			cfg.resolverHook = middleware
			return
		}

		lastResolve := cfg.resolverHook
		cfg.resolverHook = func(ctx context.Context, next graphql.Resolver) (res interface{}, err error) {
			return lastResolve(ctx, func(ctx context.Context) (res interface{}, err error) {
				return middleware(ctx, next)
			})
		}
	}
}

// RequestMiddleware allows you to define a function that will be called around the root request,
// after the query has been parsed. This is useful for logging
func RequestMiddleware(middleware graphql.RequestMiddleware) Option {
	return func(cfg *Config) {
		if cfg.requestHook == nil {
			cfg.requestHook = middleware
			return
		}

		lastResolve := cfg.requestHook
		cfg.requestHook = func(ctx context.Context, next func(ctx context.Context) []byte) []byte {
			return lastResolve(ctx, func(ctx context.Context) []byte {
				return middleware(ctx, next)
			})
		}
	}
}

func SubscriptionMiddleware(middleware graphql.SubscriptionMiddleware) Option {
	return func(cfg *Config) {
		if cfg.subscriptionHook == nil {
			cfg.subscriptionHook = middleware
			return
		}

		lastResolve := cfg.subscriptionHook
		cfg.subscriptionHook = func(ctx context.Context, next func(ctx context.Context) (context.Context, error)) (context.Context, error) {
			return lastResolve(ctx, func(ctx context.Context) (context.Context, error) {
				return middleware(ctx, next)
			})
		}
	}
}

// Tracer allows you to add a request/resolver tracer that will be called around the root request,
// calling resolver. This is useful for tracing
func Tracer(tracer graphql.Tracer) Option {
	return func(cfg *Config) {
		if cfg.tracer == nil {
			cfg.tracer = tracer

		} else {
			lastResolve := cfg.tracer
			cfg.tracer = &tracerWrapper{
				tracer1: lastResolve,
				tracer2: tracer,
			}
		}

		opt := RequestMiddleware(func(ctx context.Context, next func(ctx context.Context) []byte) []byte {
			ctx = tracer.StartOperationExecution(ctx)
			resp := next(ctx)
			tracer.EndOperationExecution(ctx)

			return resp
		})
		opt(cfg)
	}
}

type tracerWrapper struct {
	tracer1 graphql.Tracer
	tracer2 graphql.Tracer
}

func (tw *tracerWrapper) StartOperationParsing(ctx context.Context) context.Context {
	ctx = tw.tracer1.StartOperationParsing(ctx)
	ctx = tw.tracer2.StartOperationParsing(ctx)
	return ctx
}

func (tw *tracerWrapper) EndOperationParsing(ctx context.Context) {
	tw.tracer2.EndOperationParsing(ctx)
	tw.tracer1.EndOperationParsing(ctx)
}

func (tw *tracerWrapper) StartOperationValidation(ctx context.Context) context.Context {
	ctx = tw.tracer1.StartOperationValidation(ctx)
	ctx = tw.tracer2.StartOperationValidation(ctx)
	return ctx
}

func (tw *tracerWrapper) EndOperationValidation(ctx context.Context) {
	tw.tracer2.EndOperationValidation(ctx)
	tw.tracer1.EndOperationValidation(ctx)
}

func (tw *tracerWrapper) StartOperationExecution(ctx context.Context) context.Context {
	ctx = tw.tracer1.StartOperationExecution(ctx)
	ctx = tw.tracer2.StartOperationExecution(ctx)
	return ctx
}

func (tw *tracerWrapper) StartFieldExecution(ctx context.Context, field graphql.CollectedField) context.Context {
	ctx = tw.tracer1.StartFieldExecution(ctx, field)
	ctx = tw.tracer2.StartFieldExecution(ctx, field)
	return ctx
}

func (tw *tracerWrapper) StartFieldResolverExecution(ctx context.Context, rc *graphql.ResolverContext) context.Context {
	ctx = tw.tracer1.StartFieldResolverExecution(ctx, rc)
	ctx = tw.tracer2.StartFieldResolverExecution(ctx, rc)
	return ctx
}

func (tw *tracerWrapper) StartFieldChildExecution(ctx context.Context) context.Context {
	ctx = tw.tracer1.StartFieldChildExecution(ctx)
	ctx = tw.tracer2.StartFieldChildExecution(ctx)
	return ctx
}

func (tw *tracerWrapper) EndFieldExecution(ctx context.Context) {
	tw.tracer2.EndFieldExecution(ctx)
	tw.tracer1.EndFieldExecution(ctx)
}

func (tw *tracerWrapper) EndOperationExecution(ctx context.Context) {
	tw.tracer2.EndOperationExecution(ctx)
	tw.tracer1.EndOperationExecution(ctx)
}

// CacheSize sets the maximum size of the query cache.
// If size is less than or equal to 0, the cache is disabled.
func CacheSize(size int) Option {
	return func(cfg *Config) {
		cfg.cacheSize = size
	}
}

const DefaultCacheSize = 1000

func New(exec graphql.ExecutableSchema, options ...Option) *Handler {
	cfg := &Config{
		cacheSize: DefaultCacheSize,
		upgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
		},
	}

	for _, option := range options {
		option(cfg)
	}

	var cache *lru.Cache
	if cfg.cacheSize > 0 {
		var err error
		cache, err = lru.New(DefaultCacheSize)
		if err != nil {
			// An error is only returned for non-positive cache size
			// and we already checked for that.
			panic("unexpected error creating cache: " + err.Error())
		}
	}
	if cfg.tracer == nil {
		cfg.tracer = &graphql.NopTracer{}
	}

	return &Handler{
		cfg:        cfg,
		cache:      cache,
		exec:       exec,
		closeFuncs: map[int64]func(){},
	}
}

func GraphQL(exec graphql.ExecutableSchema, options ...Option) http.Handler {
	return New(exec, options...)
}

var _ http.Handler = (*Handler)(nil)

type Handler struct {
	cfg   *Config
	cache *lru.Cache
	exec  graphql.ExecutableSchema

	mu         sync.Mutex
	closeFuncs map[int64]func()
}

func (gh *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.Header().Set("Allow", "OPTIONS, GET, POST")
		w.WriteHeader(http.StatusOK)
		return
	}

	if strings.Contains(r.Header.Get("Upgrade"), "websocket") {
		connectWs(gh.exec, w, r, gh.cfg)
		return
	}

	var batch []params
	var reqParams params

	switch r.Method {
	case http.MethodGet:
		reqParams.Query = r.URL.Query().Get("query")
		reqParams.OperationName = r.URL.Query().Get("operationName")

		if variables := r.URL.Query().Get("variables"); variables != "" {
			if err := jsonDecode(strings.NewReader(variables), &reqParams.Variables); err != nil {
				sendErrorf(w, http.StatusBadRequest, "variables could not be decoded")
				return
			}
		}
	case http.MethodPost:
		var buf bytes.Buffer
		if _, err := buf.ReadFrom(r.Body); err != nil {
			sendErrorf(w, http.StatusBadRequest, "json body could not be decoded: %s", err)
		}

		if err := jsonDecode(bytes.NewBuffer(buf.Bytes()), &batch); err != nil {
			if err := jsonDecode(&buf, &reqParams); err != nil {
				sendErrorf(w, http.StatusBadRequest, "json body could not be decoded: %s", err)
				return
			}
		}
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	ctx := r.Context()

	var status int
	var response interface{}
	if batch == nil {
		pr, errs := gh.prepareRequest(ctx, r.Method, &reqParams)
		if errs != nil {
			sendError(w, http.StatusUnprocessableEntity, errs...)
			return
		}

		if pr.isSubscription() {
			if !sseContentTypePattern.MatchString(r.Header.Get("Accept")) {
				sendErrorf(w, http.StatusBadRequest, `request must accept "text/event-stream"`)
				return
			}

			gh.subscribe(ctx, pr, w)
			return
		}

		status, response = gh.execute(ctx, pr)

		response.(*graphql.Response).ID = reqParams.ID
		if response.(*graphql.Response).ID == "" {
			response.(*graphql.Response).ID = reqParams.OperationName
		}
	} else {
		var mu sync.Mutex
		var wg sync.WaitGroup

		wg.Add(len(batch))

		responses := make([]*graphql.Response, len(batch))
		for i := range batch {
			go func(i int) {
				defer wg.Done()

				var code int

				defer func() {
					responses[i].ID = batch[i].ID
					if responses[i].ID == "" {
						responses[i].ID = batch[i].OperationName
					}

					mu.Lock()
					defer mu.Unlock()

					if status == 0 {
						status = code
					} else if status != code {
						status = http.StatusMultiStatus
					}
				}()

				pr, errs := gh.prepareRequest(ctx, r.Method, &batch[i])
				if errs != nil {
					status = http.StatusUnprocessableEntity
					responses[i] = fail(errs...)
					return
				}

				if pr.isSubscription() {
					status = http.StatusBadRequest
					responses[i] = failf("batched subscriptions are not supported")
					return
				}

				code, responses[i] = gh.execute(ctx, pr)
			}(i)
		}

		response = responses

		wg.Wait()
	}

	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		panic(err)
	}
}

func (gh *Handler) prepareRequest(ctx context.Context, method string, reqParams *params) (*preparedRequest, gqlerror.List) {
	var doc *ast.QueryDocument
	var cacheHit bool
	if gh.cache != nil {
		val, ok := gh.cache.Get(reqParams.Query)
		if ok {
			doc = val.(*ast.QueryDocument)
			cacheHit = true
		}
	}

	ctx, doc, gqlErr := gh.parseOperation(ctx, &parseOperationArgs{
		Query:     reqParams.Query,
		CachedDoc: doc,
	})
	if gqlErr != nil {
		return nil, gqlerror.List{gqlErr}
	}

	ctx, op, vars, listErr := gh.validateOperation(ctx, &validateOperationArgs{
		Doc:           doc,
		OperationName: reqParams.OperationName,
		CacheHit:      cacheHit,
		Method:        method,
		Variables:     reqParams.Variables,
	})
	if len(listErr) != 0 {
		return nil, listErr
	}

	if gh.cache != nil && !cacheHit {
		gh.cache.Add(reqParams.Query, doc)
	}

	return &preparedRequest{
		doc:   doc,
		op:    op,
		query: reqParams.Query,
		vars:  vars,
	}, nil
}

type preparedRequest struct {
	doc   *ast.QueryDocument
	op    *ast.OperationDefinition
	query string
	vars  map[string]interface{}
}

func (pr *preparedRequest) isSubscription() bool {
	return pr.op.Operation == ast.Subscription
}

func (pr *preparedRequest) context(ctx context.Context, gh *Handler) (context.Context, *graphql.RequestContext) {
	reqCtx := gh.cfg.newRequestContext(gh.exec, pr.doc, pr.op, pr.query, pr.vars)
	return graphql.WithRequestContext(ctx, reqCtx), reqCtx
}

func (gh *Handler) subscribe(ctx context.Context, pr *preparedRequest, w http.ResponseWriter) {
	ctx, _ = pr.context(ctx, gh)
	gh.connectSSE(ctx, w, pr.op)
}

func (gh *Handler) execute(ctx context.Context, pr *preparedRequest) (code int, resp *graphql.Response) {
	ctx, reqCtx := pr.context(ctx, gh)

	defer func() {
		if err := recover(); err != nil {
			userErr := reqCtx.Recover(ctx, err)
			code = http.StatusUnprocessableEntity
			resp = failf(userErr.Error())
		}
	}()

	if reqCtx.ComplexityLimit > 0 && reqCtx.OperationComplexity > reqCtx.ComplexityLimit {
		return http.StatusUnprocessableEntity, failf("operation has complexity %d, which exceeds the limit of %d", reqCtx.OperationComplexity, reqCtx.ComplexityLimit)
	}

	switch pr.op.Operation {
	case ast.Query:
		return http.StatusOK, gh.exec.Query(ctx, pr.op)
	case ast.Mutation:
		return http.StatusOK, gh.exec.Mutation(ctx, pr.op)
	}

	return http.StatusBadRequest, failf("unsupported operation type")
}

type parseOperationArgs struct {
	Query     string
	CachedDoc *ast.QueryDocument
}

func (gh *Handler) parseOperation(ctx context.Context, args *parseOperationArgs) (context.Context, *ast.QueryDocument, *gqlerror.Error) {
	ctx = gh.cfg.tracer.StartOperationParsing(ctx)
	defer func() { gh.cfg.tracer.EndOperationParsing(ctx) }()

	if args.CachedDoc != nil {
		return ctx, args.CachedDoc, nil
	}

	doc, gqlErr := parser.ParseQuery(&ast.Source{Input: args.Query})
	if gqlErr != nil {
		return ctx, nil, gqlErr
	}

	return ctx, doc, nil
}

type validateOperationArgs struct {
	Doc           *ast.QueryDocument
	OperationName string
	CacheHit      bool
	Method        string
	Variables     map[string]interface{}
}

func (gh *Handler) validateOperation(ctx context.Context, args *validateOperationArgs) (context.Context, *ast.OperationDefinition, map[string]interface{}, gqlerror.List) {
	ctx = gh.cfg.tracer.StartOperationValidation(ctx)
	defer func() { gh.cfg.tracer.EndOperationValidation(ctx) }()

	if !args.CacheHit {
		listErr := validator.Validate(gh.exec.Schema(), args.Doc)
		if len(listErr) != 0 {
			return ctx, nil, nil, listErr
		}
	}

	op := args.Doc.Operations.ForName(args.OperationName)
	if op == nil {
		return ctx, nil, nil, gqlerror.List{gqlerror.Errorf("operation %s not found", args.OperationName)}
	}

	vars, err := validator.VariableValues(gh.exec.Schema(), op, args.Variables)
	if err != nil {
		return ctx, nil, nil, gqlerror.List{err}
	}

	return ctx, op, vars, nil
}

func jsonDecode(r io.Reader, val interface{}) error {
	dec := json.NewDecoder(r)
	dec.UseNumber()
	return dec.Decode(val)
}

func errorf(format string, args ...interface{}) *gqlerror.Error {
	return &gqlerror.Error{Message: fmt.Sprintf(format, args...)}
}

func fail(errs ...*gqlerror.Error) *graphql.Response {
	return &graphql.Response{Errors: errs}
}

func failf(format string, args ...interface{}) *graphql.Response {
	return fail(errorf(format, args))
}

func sendError(w http.ResponseWriter, code int, errors ...*gqlerror.Error) {
	w.WriteHeader(code)
	b, err := json.Marshal(&graphql.Response{Errors: errors})
	if err != nil {
		panic(err)
	}
	w.Write(b)
}

func sendErrorf(w http.ResponseWriter, code int, format string, args ...interface{}) {
	sendError(w, code, errorf(format, args))
}
