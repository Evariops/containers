package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

type State string

const (
	StateIdle    State = "idle"
	StateRunning State = "running"
	StateDone    State = "done"
)

type Status struct {
	State     State      `json:"state"`
	ExitCode  *int       `json:"exit_code,omitempty"`
	StartedAt *time.Time `json:"started_at,omitempty"`
	StoppedAt *time.Time `json:"stopped_at,omitempty"`
	Args      []string   `json:"args,omitempty"`
}

type Controller struct {
	mu          sync.RWMutex
	cmd         *exec.Cmd
	status      Status
	outputBuf   *OutputBuffer
	done        chan struct{}
	defaultArgs []string
}

// OutputBuffer is a thread-safe buffer that captures fio output.
type OutputBuffer struct {
	mu   sync.Mutex
	data []byte
	max  int
}

func NewOutputBuffer(max int) *OutputBuffer {
	return &OutputBuffer{max: max, data: make([]byte, 0, max)}
}

func (b *OutputBuffer) Write(p []byte) (n int, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.data = append(b.data, p...)
	if len(b.data) > b.max {
		b.data = b.data[len(b.data)-b.max:]
	}
	return len(p), nil
}

func (b *OutputBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	cp := make([]byte, len(b.data))
	copy(cp, b.data)
	return cp
}

func (b *OutputBuffer) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.data = b.data[:0]
}

// blockedDirectives are fio job file directives that allow arbitrary command execution.
var blockedDirectives = regexp.MustCompile(`(?im)^\s*(exec_prerun|exec_postrun|exec_prerun|ioengine\s*=\s*exec)\s*=`)

// blockedArgs are CLI arguments that could enable command execution or escape.
var blockedArgs = []string{
	"--exec_prerun",
	"--exec_postrun",
	"--trigger",
	"--trigger-remote",
}

func validateJobContent(job string) error {
	if blockedDirectives.MatchString(job) {
		return fmt.Errorf("job contains blocked directive (exec_prerun/exec_postrun/ioengine=exec)")
	}
	return nil
}

func validateArgs(args []string) error {
	for _, arg := range args {
		lower := strings.ToLower(arg)
		for _, blocked := range blockedArgs {
			if strings.HasPrefix(lower, blocked) {
				return fmt.Errorf("blocked argument: %s", blocked)
			}
		}
		// Block ioengine=exec via CLI
		if strings.Contains(lower, "ioengine=exec") {
			return fmt.Errorf("blocked ioengine: exec")
		}
	}
	return nil
}

// authMiddleware validates the Bearer token if AUTH_TOKEN is set.
func authMiddleware(next http.Handler, token string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if token == "" {
			// No token configured — skip auth (rely on network policy)
			next.ServeHTTP(w, r)
			return
		}
		auth := r.Header.Get("Authorization")
		expected := "Bearer " + token
		if subtle.ConstantTimeCompare([]byte(auth), []byte(expected)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func NewController(defaultArgs []string) *Controller {
	return &Controller{
		outputBuf:   NewOutputBuffer(10 * 1024 * 1024), // 10 MB
		defaultArgs: defaultArgs,
		status:      Status{State: StateIdle},
	}
}

type StartRequest struct {
	// Args: raw fio CLI arguments (e.g. ["--bs=4k", "--rw=randread", ...])
	Args []string `json:"args,omitempty"`

	// Job: inline fio job file content (INI format)
	Job string `json:"job,omitempty"`

	// ExtraArgs: additional CLI args appended after the job file
	// (e.g. ["--output-format=json+"])
	ExtraArgs []string `json:"extra_args,omitempty"`
}

func (c *Controller) Start(args []string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.status.State == StateRunning {
		return fmt.Errorf("fio is already running")
	}

	if len(args) == 0 {
		args = c.defaultArgs
	}
	if len(args) == 0 {
		return fmt.Errorf("no fio arguments provided")
	}

	c.outputBuf.Reset()
	c.done = make(chan struct{})

	c.cmd = exec.Command("/usr/local/bin/fio", args...)
	stdout, err := c.cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}
	stderr, err := c.cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("stderr pipe: %w", err)
	}

	if err := c.cmd.Start(); err != nil {
		return fmt.Errorf("start fio: %w", err)
	}

	now := time.Now()
	c.status = Status{
		State:     StateRunning,
		StartedAt: &now,
		Args:      args,
	}

	// Stream output to both stdout/stderr and the capture buffer
	go func() {
		_, _ = io.Copy(io.MultiWriter(os.Stdout, c.outputBuf), stdout)
	}()
	go func() {
		_, _ = io.Copy(io.MultiWriter(os.Stderr, c.outputBuf), stderr)
	}()

	// Wait for fio to exit
	go func() {
		err := c.cmd.Wait()
		c.mu.Lock()
		defer c.mu.Unlock()
		now := time.Now()
		c.status.State = StateDone
		c.status.StoppedAt = &now
		code := 0
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				code = exitErr.ExitCode()
			} else {
				code = -1
			}
		}
		c.status.ExitCode = &code
		close(c.done)
	}()

	return nil
}

func (c *Controller) Stop() error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.status.State != StateRunning || c.cmd == nil || c.cmd.Process == nil {
		return fmt.Errorf("fio is not running")
	}

	// SIGTERM triggers fio's graceful shutdown — it finishes current I/O,
	// collects statistics, and outputs full results (including JSON).
	return c.cmd.Process.Signal(syscall.SIGTERM)
}

func (c *Controller) GetStatus() Status {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.status
}

func (c *Controller) IsRunning() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.status.State == StateRunning
}

func (c *Controller) WaitDone() <-chan struct{} {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.done
}

func main() {
	listenAddr := flag.String("listen", "0.0.0.0:8080", "HTTP API listen address")
	flag.Parse()

	// Default fio args can be provided at container startup
	defaultArgs := flag.Args()

	ctrl := NewController(defaultArgs)

	mux := http.NewServeMux()

	// POST /start — start fio (optionally with custom args in JSON body)
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var args []string
		if r.Body != nil && r.ContentLength > 0 {
			var req StartRequest
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
				http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
				return
			}

			if req.Job != "" {
				// Validate job content for dangerous directives
				if err := validateJobContent(req.Job); err != nil {
					http.Error(w, "security: "+err.Error(), http.StatusForbidden)
					return
				}
				if err := validateArgs(req.ExtraArgs); err != nil {
					http.Error(w, "security: "+err.Error(), http.StatusForbidden)
					return
				}

				jobPath := "/tmp/fio-job.fio"
				if err := os.WriteFile(jobPath, []byte(req.Job), 0600); err != nil {
					http.Error(w, "failed to write job file: "+err.Error(), http.StatusInternalServerError)
					return
				}
				args = append([]string{jobPath}, req.ExtraArgs...)
			} else if len(req.Args) > 0 {
				if err := validateArgs(req.Args); err != nil {
					http.Error(w, "security: "+err.Error(), http.StatusForbidden)
					return
				}
				args = req.Args
			}
		}

		if err := ctrl.Start(args); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "started"})
	})

	// POST /stop — graceful stop (sends SIGTERM to fio)
	mux.HandleFunc("/stop", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := ctrl.Stop(); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "stopping"})
	})

	// GET /status — current fio status
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ctrl.GetStatus())
	})

	// GET /output — get captured fio output
	mux.HandleFunc("/output", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(ctrl.outputBuf.Bytes())
	})

	// GET /health — liveness probe
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	// Auth token from environment variable
	authToken := os.Getenv("FIO_AUTH_TOKEN")
	if authToken != "" {
		log.Printf("API authentication enabled (Bearer token)")
	} else {
		log.Printf("WARNING: no FIO_AUTH_TOKEN set — relying on network-level access control")
	}

	server := &http.Server{
		Addr:         *listenAddr,
		Handler:      authMiddleware(mux, authToken),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	log.Printf("fio-controller listening on %s", *listenAddr)
	if len(defaultArgs) > 0 {
		log.Printf("default fio args: %v", defaultArgs)
	}

	// Start HTTP server
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	// Handle OS signals — forward SIGTERM to fio if running, then exit
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	sig := <-sigCh
	log.Printf("Received signal %v", sig)

	if ctrl.IsRunning() {
		log.Printf("Forwarding signal to fio for graceful shutdown")
		_ = ctrl.Stop()
		<-ctrl.WaitDone()
	}

	// Shutdown HTTP server
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = server.Shutdown(ctx)

	status := ctrl.GetStatus()
	if status.ExitCode != nil {
		os.Exit(*status.ExitCode)
	}
}
