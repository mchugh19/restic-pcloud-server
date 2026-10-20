// restic-pcloud-server: a restic REST-protocol server backed by pCloud via rclone,
// with verify-after-write: every Save is independently re-checked against what pCloud
// actually stored (both its size and its content hash, which pCloud reports in its file
// metadata), and retried fresh (delete + re-upload) on mismatch, instead of trusting
// rclone/pCloud's own "success" response. This exists because pCloud has been observed
// reporting a successful upload for objects that come back wrong-sized or missing
// entirely on read-back - restic's own retry logic assumes a clean pass/fail from the
// backend, so a backend that silently lies about success needs its own verification layer.
package main

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

// version is set at build time via -ldflags "-X main.version=<short-sha>" (see Dockerfile/CI
// workflow); it stays "dev" for a local `go build` so that's never mistaken for a real build.
var version = "dev"

var (
	rcloneRoot   string // fixed rclone remote:path root, e.g. "pcloud:Backups/restic" - each restic repo gets its own subfolder under this, named by the URL path segment the client requests
	rcloneConfig string
	caCertPath   string
	transport    string // "exec": spawn an rclone process per operation; "rcd": keep one rclone daemon alive and drive it over its RC API
	rcAddr       string // listen address of the rclone daemon when -transport=rcd; loopback only, it is unauthenticated by design
	rcClient     *http.Client
	rcdDone      chan error // receives the daemon's exit result once it dies
	maxRetries   int
	requireHash  bool
	verifyWait   time.Duration
	listenAddr   string
	debug        bool
	authUser     string
	authPass     string
	showVersion  bool

	inFlight int64 // number of requests currently being handled, for correlating slow requests with concurrency
	saveSeq  int64 // monotonic counter for req IDs, so concurrent SAVE sequences for the same path are distinguishable in the log
)

func init() {
	flag.StringVar(&rcloneRoot, "remote-root", "pcloud:Backups/restic", "fixed rclone remote:path root; each restic repo is a subfolder under this, chosen by the client via its repo URL (rest:http://host:port/<repo-name>/)")
	flag.StringVar(&rcloneConfig, "rclone-config", "", "path to rclone.conf")
	flag.StringVar(&transport, "transport", "rcd", "how to drive rclone: \"rcd\" starts a single long-lived rclone daemon at startup and talks to it over its loopback RC API, so DNS, TLS and config setup are paid once instead of per object; \"exec\" spawns one rclone process per operation (the original behaviour, kept as a fallback)")
	flag.StringVar(&rcAddr, "rc-addr", "127.0.0.1:5572", "listen address for the rclone daemon when -transport=rcd (loopback only: the RC API is unauthenticated)")
	flag.StringVar(&caCertPath, "ca-cert", "", "CA bundle for rclone's TLS verification (only needed when the platform's own verifier is blocked, e.g. macOS sandbox testing: /etc/ssl/cert.pem; leave unset on a normal Linux host)")
	flag.IntVar(&maxRetries, "max-retries", 3, "max fresh re-upload retries after a failed verify (so the initial write plus this many retries is the total number of tries)")
	flag.BoolVar(&requireHash, "require-hash", true, "fail verification when pCloud reports no content hash for a saved object, so size is the only thing that can be checked (pCloud reports at least one of sha256/sha1/md5 in both regions, so this should not happen; turn off only for a remote that cannot report hashes at all)")
	flag.DurationVar(&verifyWait, "verify-wait", 5*time.Minute, "how long verification waits for pCloud to make a just-written object visible and report its content hash before the write is treated as failed (pCloud has been seen to hide a stored object from listings and hash reads for minutes at a time); a visible object with the wrong size or hash fails immediately, only absence waits")
	flag.StringVar(&listenAddr, "listen", "127.0.0.1:8080", "address to listen on")
	flag.BoolVar(&debug, "debug", false, "log per-request/per-stage timing and concurrency, not just errors")
	flag.StringVar(&authUser, "auth-user", os.Getenv("RESTIC_PCLOUD_AUTH_USER"), "if set together with -auth-pass, require HTTP Basic Auth (defaults from RESTIC_PCLOUD_AUTH_USER env var) - required once this server is reachable from anywhere other than localhost, restic has no protocol-level auth of its own")
	flag.StringVar(&authPass, "auth-pass", os.Getenv("RESTIC_PCLOUD_AUTH_PASS"), "password for -auth-user (defaults from RESTIC_PCLOUD_AUTH_PASS env var)")
	flag.BoolVar(&showVersion, "version", false, "print the build version and exit")
}

// authMiddleware enforces HTTP Basic Auth when -auth-user/-auth-pass (or their env-var
// equivalents) are set. restic's REST backend supports basic auth natively via the repository
// URL (rest:http://user:pass@host/), so clients need no special handling. If neither is set,
// this is a no-op - matches the plain localhost testing done so far.
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	if authUser == "" && authPass == "" {
		return next
	}
	return func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || subtle.ConstantTimeCompare([]byte(u), []byte(authUser)) != 1 || subtle.ConstantTimeCompare([]byte(p), []byte(authPass)) != 1 {
			logf("AUTH failed: %s %s from %s (user %q)", r.Method, r.URL.Path, r.RemoteAddr, u)
			w.Header().Set("WWW-Authenticate", `Basic realm="restic-pcloud-server"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func rcloneBaseArgs() []string {
	args := []string{}
	if rcloneConfig != "" {
		args = append(args, "--config", rcloneConfig)
	}
	if caCertPath != "" {
		args = append(args, "--ca-cert", caCertPath)
	}
	return args
}

func runRclone(args ...string) ([]byte, error) {
	full := append(rcloneBaseArgs(), args...)
	cmd := exec.Command("rclone", full...)
	out, err := cmd.CombinedOutput()
	return out, err
}

// --- rclone daemon (rcd) transport ---
//
// With -transport=rcd the server keeps one rclone daemon alive and drives it
// over its RC API instead of spawning an rclone process per operation, so the
// per-process costs (config load, DNS resolution, TLS setup, token check)
// are paid once. The RC contracts used here were verified against rclone
// 1.60 (the contracts are stable across current releases):
//   - operations/stat returns {"item": {...}}, with item null (HTTP 200) for
//     a missing object.
//   - operations/list only includes content hashes when opt.showHash is set,
//     and it errors on a file path, so single-object metadata is fetched by
//     listing the object's parent directory and picking its entry.
//   - uploads are an RC sync/copy whose source is a staging directory that
//     holds exactly the one object under its final name (there is no
//     single-file copy endpoint in the RC API).
//   - downloads use the daemon's --rc-serve file endpoint, which streams and
//     honours Range itself.

var rcdCmd *exec.Cmd

// splitRemotePath splits an rclone path ("remote:dir/sub/name") into the
// directory part (itself a valid rclone fs string) and the final name, which
// is the shape the RC API's fs+remote parameters take.
func splitRemotePath(path string) (dir, name string) {
	i := strings.LastIndex(path, "/")
	if i < 0 {
		return path, ""
	}
	return path[:i], path[i+1:]
}

// rcCall performs one RC API call and returns the raw response body. An RC
// error (a non-200 status, or an "error" field in the body) becomes a Go
// error carrying rclone's own message.
func rcCall(method string, params map[string]interface{}) (json.RawMessage, error) {
	body, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	resp, err := rcClient.Post("http://"+rcAddr+"/"+method, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var rcErr struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(raw, &rcErr)
	if resp.StatusCode != http.StatusOK || rcErr.Error != "" {
		return nil, fmt.Errorf("rc %s: %s (status %d)", method, rcErr.Error, resp.StatusCode)
	}
	return raw, nil
}

// rcRel returns path relative to rcloneRoot. Every RC call addresses
// rcloneRoot itself as the fs and passes the object or directory as a
// path relative to it, so the daemon keeps ONE backend instance (and
// one HTTP connection pool) for the whole server. Addressing objects by
// their parent directory instead would make the daemon build a separate
// backend per directory, and a restic repository has hundreds of leaf
// directories, so connections, and the DNS lookups each new connection
// needs, would never be reused.
func rcRel(path string) string {
	if path == rcloneRoot {
		return ""
	}
	return strings.TrimPrefix(path, rcloneRoot+"/")
}

func rcStat(path string) (*lsjsonEntry, bool) {
	raw, err := rcCall("operations/stat", map[string]interface{}{"fs": rcloneRoot, "remote": rcRel(path)})
	if err != nil {
		return nil, false
	}
	var out struct {
		Item *lsjsonEntry `json:"item"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || out.Item == nil {
		return nil, false
	}
	return out.Item, true
}

func rcList(dir string, recurse, showHash bool) ([]lsjsonEntry, error) {
	raw, err := rcCall("operations/list", map[string]interface{}{
		"fs":     rcloneRoot,
		"remote": rcRel(dir),
		"opt":    map[string]interface{}{"recurse": recurse, "showHash": showHash},
	})
	if err != nil {
		return nil, err
	}
	var out struct {
		List []lsjsonEntry `json:"list"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out.List, nil
}

// rcUpload copies a staging directory holding exactly one object, laid
// out at the object's path relative to rcloneRoot, to the root fs. The
// object lands at its full remote path because the copy preserves the
// layout below the staging root.
func rcUpload(stageDir string) error {
	_, err := rcCall("sync/copy", map[string]interface{}{
		"srcFs": stageDir,
		"dstFs": rcloneRoot,
	})
	return err
}

func rcDelete(remotePath string) error {
	_, err := rcCall("operations/deletefile", map[string]interface{}{"fs": rcloneRoot, "remote": rcRel(remotePath)})
	return err
}

// rcServeURL returns the daemon's --rc-serve URL for one object. Go's URL
// escaping turns the square brackets into %5B/%5D, which is the form the
// daemon's file server accepts.
func rcServeURL(remotePath string) string {
	u := url.URL{Scheme: "http", Host: rcAddr, Path: "/[" + rcloneRoot + "]/" + rcRel(remotePath)}
	return u.String()
}

// uploadFile copies one staged file to a remote path through the active
// transport, returning output text suitable for error messages. The rcd
// transport copies the whole staging directory (see rcUpload); the exec
// transport copies the file itself.
func uploadFile(stageDir, localPath, remotePath string) (string, error) {
	if transport == "rcd" {
		if err := rcUpload(stageDir); err != nil {
			return err.Error(), err
		}
		return "", nil
	}
	out, err := runRclone("copyto", localPath, remotePath)
	return string(out), err
}

// deleteRemote removes one remote object through the active transport.
func deleteRemote(remotePath string) error {
	if transport == "rcd" {
		return rcDelete(remotePath)
	}
	_, err := runRclone("deletefile", remotePath)
	return err
}

// startRCD launches the rclone daemon as a child process, waits until its RC
// API answers, and arms supervision: if the daemon later dies, this process
// exits too, so the service supervisor restarts the pair together rather
// than leaving a server whose every operation would fail.
func startRCD() error {
	bin, err := exec.LookPath("rclone")
	if err != nil {
		return fmt.Errorf("rclone not found in PATH: %v", err)
	}
	args := append([]string{"rcd", "--rc-addr", rcAddr, "--rc-no-auth", "--rc-serve"}, rcloneBaseArgs()...)
	rcdCmd = exec.Command(bin, args...)
	rcdCmd.Stdout = os.Stderr // the daemon's logs interleave with this server's own log
	rcdCmd.Stderr = os.Stderr
	if err := rcdCmd.Start(); err != nil {
		return fmt.Errorf("starting rclone daemon: %v", err)
	}
	rcdDone = make(chan error, 1)
	go func() { rcdDone <- rcdCmd.Wait() }()

	probeClient := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(30 * time.Second)
	for {
		select {
		case err := <-rcdDone:
			return fmt.Errorf("rclone daemon exited during startup: %v", err)
		default:
		}
		resp, err := probeClient.Post("http://"+rcAddr+"/core/version", "application/json", bytes.NewReader([]byte("{}")))
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("rclone daemon did not answer on %s within 30s", rcAddr)
		}
		time.Sleep(200 * time.Millisecond)
	}
	go func() {
		err := <-rcdDone
		log.Fatalf("rclone daemon exited: %v - exiting so the supervisor restarts both", err)
	}()
	// Clean up the daemon on SIGINT/SIGTERM instead of orphaning it (mostly
	// for local runs; a container stop takes the whole cgroup anyway).
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigc
		if rcdCmd.Process != nil {
			rcdCmd.Process.Kill()
		}
		os.Exit(0)
	}()
	return nil
}

// repoRoot returns the rclone path for one restic repo: the fixed server-side root plus the
// client-chosen repo name. repo is already validated by pathRE/repoCreateRE's charset
// ([a-zA-Z0-9_-] only, no dots or slashes) before this is called, so there's no path-traversal
// risk in letting the client pick it - it can only ever select a direct subfolder of
// rcloneRoot, never a different rclone remote or an arbitrary path.
func repoRoot(repo string) string {
	return fmt.Sprintf("%s/%s", rcloneRoot, repo)
}

// restic's sharding: "data" objects live under a 2-hex-char prefix subfolder, everything
// else (config, index, keys, locks, snapshots) is flat.
func remotePath(repo, kind, name string) string {
	base := repoRoot(repo)
	if kind == "config" {
		return fmt.Sprintf("%s/config", base)
	}
	if kind == "data" && len(name) >= 2 {
		return fmt.Sprintf("%s/data/%s/%s", base, name[:2], name)
	}
	return fmt.Sprintf("%s/%s/%s", base, kind, name)
}

func remoteDir(repo, kind string) string {
	return fmt.Sprintf("%s/%s", repoRoot(repo), kind)
}

type lsjsonEntry struct {
	Path   string            `json:"Path"`
	Name   string            `json:"Name"`
	Size   int64             `json:"Size"`
	IsDir  bool              `json:"IsDir"`
	Hashes map[string]string `json:"Hashes"` // only present with `lsjson --hash`; keys are rclone's hash names ("sha256", "sha1", "md5", ...), values lowercase hex
}

// remoteSizeOnce returns the size of a single object, or -1 if it doesn't exist - a single
// attempt, no retry.
func remoteSizeOnce(path string) int64 {
	if transport == "rcd" {
		if item, ok := rcStat(path); ok {
			return item.Size
		}
		return -1
	}
	out, err := runRclone("lsjson", path)
	if err != nil {
		return -1
	}
	var entries []lsjsonEntry
	if err := json.Unmarshal(out, &entries); err != nil || len(entries) == 0 {
		return -1
	}
	return entries[0].Size
}

// remoteSize is remoteSizeOnce with retries on a "not found" result. Confirmed in real-world
// testing that pCloud can report an object as not-found on one stat call and then immediately
// show it again on the next independent one - the same eventual-consistency
// behavior already known to affect writes, now confirmed on reads too. restic treats a clean
// 404 as authoritative ("no repository here") and won't retry it itself, so a false negative
// here is worse than a false negative on write: it fails the whole operation outright instead
// of just costing a slower upload. Retry a few times before actually reporting not-found.
func remoteSize(path string) int64 {
	const attempts = 4
	const delay = 800 * time.Millisecond
	var size int64 = -1
	for attempt := 1; attempt <= attempts; attempt++ {
		size = remoteSizeOnce(path)
		if size >= 0 {
			if attempt > 1 {
				debugf("STAT %s: found on attempt %d/%d after earlier not-found (%d bytes)", path, attempt, attempts, size)
			}
			return size
		}
		if attempt < attempts {
			time.Sleep(delay)
		}
	}
	return -1
}

// remoteMeta is what one `lsjson --hash` on a single object reports: its size and the
// content hashes the backend computed for it. pCloud reports sha256 (and sha1) in the EU
// region and sha1 (and md5) in the US region, so at least one hash restic's objects can be
// checked against is always expected on this backend.
type remoteMeta struct {
	size   int64
	hashes map[string]string
}

// remoteMetaOnce is a single attempt at fetching an object's metadata, mirroring
// remoteSizeOnce: ok=false means the object doesn't exist or the call itself failed.
func remoteMetaOnce(path string) (remoteMeta, bool) {
	if transport == "rcd" {
		// The RC API cannot stat hashes for a single object; list its parent
		// directory with hashes shown and pick the object's own entry.
		dir, name := splitRemotePath(path)
		entries, err := rcList(dir, false, true)
		if err != nil {
			return remoteMeta{}, false
		}
		for _, e := range entries {
			if e.Name == name && !e.IsDir {
				return remoteMeta{size: e.Size, hashes: e.Hashes}, true
			}
		}
		return remoteMeta{}, false
	}
	out, err := runRclone("lsjson", "--hash", path)
	if err != nil {
		return remoteMeta{}, false
	}
	var entries []lsjsonEntry
	if err := json.Unmarshal(out, &entries); err != nil || len(entries) == 0 {
		return remoteMeta{}, false
	}
	return remoteMeta{size: entries[0].Size, hashes: entries[0].Hashes}, true
}

// verifyPollInterval is how often the verify path re-checks an object pCloud is
// not showing yet.
const verifyPollInterval = 5 * time.Second

// pollMeta fetches an object's metadata, waiting for pCloud to make the object
// visible for up to verifyWait, the same patience verifySaved applies: pCloud's
// eventual consistency can hide a just-written object for minutes, far beyond a
// few quick retries.
func pollMeta(path string) (remoteMeta, bool) {
	deadline := time.Now().Add(verifyWait)
	for {
		if meta, ok := remoteMetaOnce(path); ok {
			return meta, true
		}
		if time.Now().After(deadline) {
			return remoteMeta{}, false
		}
		time.Sleep(verifyPollInterval)
	}
}

// hashFile computes the sha256, sha1 and md5 of a local file in one pass, keyed by
// rclone's hash names so the results compare directly against an lsjson Hashes map.
// Hashing a pack-sized temp file costs milliseconds; it is what lets verification check
// the actual bytes pCloud stored instead of only their count, without downloading the
// object back - pCloud reports its own hashes in the listing metadata.
func hashFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h256 := sha256.New()
	h1 := sha1.New()
	hm := md5.New()
	if _, err := io.Copy(io.MultiWriter(h256, h1, hm), f); err != nil {
		return nil, err
	}
	return map[string]string{
		"sha256": hex.EncodeToString(h256.Sum(nil)),
		"sha1":   hex.EncodeToString(h1.Sum(nil)),
		"md5":    hex.EncodeToString(hm.Sum(nil)),
	}, nil
}

// verifySaved checks what pCloud stored for one just-written object against what was
// sent: the size must match, and the strongest content hash both sides have (sha256 in
// the EU region, sha1 or md5 in the US) must match too. Exactly one of the two results
// is non-empty: the algorithm the object verified by ("size-only" when no comparable
// hash existed and -require-hash is off), or the reason verification failed.
//
// pCloud can take minutes to make a stored object verifiable: it is missing from
// listings at first, or listed before its content hashes are reported. Both states
// are waited out for up to verifyWait, because deleting and re-uploading only
// restarts that clock and the object usually appears unchanged. Wrong content never
// heals, so an object that IS visible with the wrong size, or with a hash that does
// not match, fails at once.
func verifySaved(path string, written int64, localHashes map[string]string) (string, string) {
	start := time.Now()
	deadline := start.Add(verifyWait)
	sawObject := false
	for {
		meta, found := remoteMetaOnce(path)
		if found {
			sawObject = true
			if meta.size != written {
				return "", fmt.Sprintf("size mismatch: wrote %d bytes, pCloud has %d", written, meta.size)
			}
			for _, algo := range []string{"sha256", "sha1", "md5"} {
				remote, okRemote := meta.hashes[algo]
				local, okLocal := localHashes[algo]
				if okRemote && okLocal {
					if !strings.EqualFold(remote, local) {
						return "", fmt.Sprintf("hash mismatch (%s): wrote %s, pCloud has %s", algo, local, remote)
					}
					if waited := time.Since(start); waited >= verifyPollInterval {
						logf("VERIFY %s: pCloud made the object verifiable after %s (verified by %s)", path, waited.Round(time.Second), algo)
					}
					return algo, ""
				}
			}
			if !requireHash {
				return "size-only", ""
			}
			// Visible but no comparable hash reported yet: the lag case, waited
			// out below like absence; the no-hash failure is returned if the
			// deadline passes in this state.
		}
		if time.Now().After(deadline) {
			if sawObject {
				return "", "pCloud reported no content hash for the object, so its bytes cannot be verified"
			}
			return "", fmt.Sprintf("wrote %d bytes but pCloud still shows it missing", written)
		}
		time.Sleep(verifyPollInterval)
	}
}

// repoNameRE matches a single client-chosen repo name segment: letters, digits, dash,
// underscore only - deliberately no dots or slashes, so this can never encode ".." or an
// absolute path and can only ever address a direct subfolder of rcloneRoot.
const repoNamePattern = `[a-zA-Z0-9_-]+`

var repoCreateRE = regexp.MustCompile(`^/(` + repoNamePattern + `)/?$`)
var pathRE = regexp.MustCompile(`^/(` + repoNamePattern + `)/([a-z]+)(?:/([0-9a-fA-F]+))?/?$`)

func logf(format string, a ...interface{}) {
	log.Printf("[info] "+format, a...)
}

// ANSI color codes for SAVE outcome lines, so a scrolling log makes it obvious at a glance
// whether an attempt succeeded, is retrying, or failed for good.
const (
	colorReset  = "\033[0m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorRed    = "\033[31m"
	colorCyan   = "\033[36m" // startup version line only, kept distinct from the SAVE outcome colors above
)

// debugf logs verbose per-stage/per-request detail, only when -debug is set. Always-relevant
// events (verify mismatches, giving up, startup) go through logf instead so they show up
// regardless of -debug.
func debugf(format string, a ...interface{}) {
	if debug {
		log.Printf("[debug] "+format, a...)
	}
}

// statusRecorder wraps http.ResponseWriter to capture the status code for logging, since
// http.ResponseWriter doesn't expose what was written.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// loggingMiddleware records, per request, how long it took and how many other requests were
// in flight at the same time - the concurrency number is what matters for diagnosing restic's
// client-side --stuck-request-timeout firing under load.
func loggingMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !debug {
			next(w, r)
			return
		}
		n := atomic.AddInt64(&inFlight, 1)
		defer atomic.AddInt64(&inFlight, -1)
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		debugf("-> %s %s (in-flight=%d)", r.Method, r.URL.Path, n)
		next(rec, r)
		debugf("<- %s %s status=%d duration=%s (in-flight was %d)", r.Method, r.URL.Path, rec.status, time.Since(start), n)
	}
}

func handler(w http.ResponseWriter, r *http.Request) {
	// restic issues POST /<repo>/?create=true once, before ever touching /<repo>/config.
	if r.Method == http.MethodPost && r.URL.Query().Get("create") == "true" {
		if m := repoCreateRE.FindStringSubmatch(r.URL.Path); m != nil {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.NotFound(w, r)
		return
	}

	m := pathRE.FindStringSubmatch(r.URL.Path)
	if m == nil {
		http.NotFound(w, r)
		return
	}
	repo, kind, name := m[1], m[2], m[3]

	// "config" is a single flat file, not a listable directory, so it has an implicit
	// empty name - HEAD/GET/POST must route to the single-object handlers for it even
	// though name == "" here (unlike data/index/keys/locks/snapshots, which use name == ""
	// to mean "list this kind").
	hasName := name != "" || kind == "config"

	switch {
	case r.Method == http.MethodHead && hasName:
		handleHead(w, repo, kind, name)
	case r.Method == http.MethodGet && hasName:
		handleGet(w, r, repo, kind, name)
	case r.Method == http.MethodGet && name == "":
		handleList(w, r, repo, kind)
	case r.Method == http.MethodPost && hasName:
		handleSave(w, r, repo, kind, name)
	case r.Method == http.MethodDelete && hasName:
		handleDelete(w, repo, kind, name)
	default:
		http.Error(w, "unsupported", http.StatusMethodNotAllowed)
	}
}

func handleHead(w http.ResponseWriter, repo, kind, name string) {
	size := remoteSize(remotePath(repo, kind, name))
	if size < 0 {
		http.NotFound(w, nil)
		return
	}
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	w.WriteHeader(http.StatusOK)
}

func handleGet(w http.ResponseWriter, r *http.Request, repo, kind, name string) {
	path := remotePath(repo, kind, name)
	size := remoteSize(path)
	if size < 0 {
		http.NotFound(w, r)
		return
	}

	if transport == "rcd" {
		// The daemon's file endpoint streams the object and computes Range
		// responses itself; forward the client's Range header verbatim and
		// relay its status and length headers.
		req, err := http.NewRequest(http.MethodGet, rcServeURL(path), nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if rng := r.Header.Get("Range"); rng != "" {
			req.Header.Set("Range", rng)
		}
		resp, err := rcClient.Do(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound {
			http.NotFound(w, r)
			return
		}
		for _, h := range []string{"Content-Length", "Content-Range", "Content-Type"} {
			if v := resp.Header.Get(h); v != "" {
				w.Header().Set(h, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
		return
	}

	args := []string{"cat", path}
	status := http.StatusOK
	if rng := r.Header.Get("Range"); rng != "" {
		var start, end int64
		if _, err := fmt.Sscanf(rng, "bytes=%d-%d", &start, &end); err == nil {
			count := end - start + 1
			args = append(args, "--offset", strconv.FormatInt(start, 10), "--count", strconv.FormatInt(count, 10))
			w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, size))
			w.Header().Set("Content-Length", strconv.FormatInt(count, 10))
			status = http.StatusPartialContent
		}
	} else {
		w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	}

	full := append(rcloneBaseArgs(), args...)
	cmd := exec.Command("rclone", full...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := cmd.Start(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(status)
	io.Copy(w, stdout)
	if err := cmd.Wait(); err != nil {
		logf("GET %s: rclone cat error after headers sent: %v", path, err)
	}
}

func handleList(w http.ResponseWriter, r *http.Request, repo, kind string) {
	// "data" objects live one level down, under 2-hex-char prefix subfolders, so listing
	// it needs a recursive lsjson; everything else (index/keys/locks/snapshots) is flat.
	var entries []lsjsonEntry
	if transport == "rcd" {
		entries, _ = rcList(remoteDir(repo, kind), kind == "data", false)
	} else {
		args := []string{"lsjson"}
		if kind == "data" {
			args = append(args, "-R")
		}
		args = append(args, remoteDir(repo, kind))
		out, err := runRclone(args...)
		if err == nil {
			json.Unmarshal(out, &entries)
		}
	}
	// restic REST v2 listing format
	type v2entry struct {
		Name string `json:"name"`
		Size int64  `json:"size"`
	}
	var result []v2entry
	for _, e := range entries {
		if e.IsDir {
			continue // skip the 2-hex-char subfolders themselves, keep only the files inside them
		}
		result = append(result, v2entry{Name: e.Name, Size: e.Size})
	}
	if result == nil {
		result = []v2entry{}
	}
	w.Header().Set("Content-Type", "application/vnd.x.restic.rest.v2")
	json.NewEncoder(w).Encode(result)
}

// handleSave is the important one: write, then independently verify against what pCloud
// actually stored (size and content hash), and retry fresh (delete + re-upload from the
// same local temp file) on any mismatch, instead of trusting rclone's own reported success.
func handleSave(w http.ResponseWriter, r *http.Request, repo, kind, name string) {
	reqID := atomic.AddInt64(&saveSeq, 1) // distinguishes concurrent SAVE sequences for the same path in the log
	saveStart := time.Now()
	path := remotePath(repo, kind, name)

	// The received bytes are staged in their own directory, laid out at the
	// object's path relative to the remote root: the rcd transport uploads
	// by copying that directory to the root fs, so the layout below the
	// staging root has to mirror the remote layout. The exec transport uses
	// the staged file directly and ignores the layout.
	stageDir, err := os.MkdirTemp("", "pcloud-save-*")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer os.RemoveAll(stageDir)
	localPath := filepath.Join(stageDir, filepath.FromSlash(rcRel(path)))
	if err := os.MkdirAll(filepath.Dir(localPath), 0o755); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tmp, err := os.Create(localPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer tmp.Close()

	recvStart := time.Now()
	written, err := io.Copy(tmp, r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tmp.Close()
	recvDur := time.Since(recvStart)

	// Hash the received bytes once, up front: every retry re-uploads this same
	// staged file, so its hashes are the reference for every attempt's verification.
	localHashes, err := hashFile(localPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// For the kinds restic names by content hash (data, index, snapshots, keys), the
	// received bytes should hash to the name they arrived under. This is only a
	// diagnostic - the gate in the loop below compares pCloud against the received
	// bytes, which is the guarantee that matters - but a mismatch here means something
	// upstream of pCloud is wrong in a way worth seeing in the log.
	switch kind {
	case "data", "index", "snapshots", "keys":
		if !strings.EqualFold(localHashes["sha256"], name) {
			logf("SAVE %s [req %05d]: WARNING received bytes hash to %s, not the requested name %s", path, reqID, localHashes["sha256"], name)
		}
	}

	var lastErr string
	// attempt 0 is the initial write - not a retry. attempts 1..maxRetries are the fresh
	// re-upload retries after a failed verify, so maxRetries retries means maxRetries+1
	// total tries, matching what the flag's name promises.
	for attempt := 0; attempt <= maxRetries; attempt++ {
		label := "initial attempt"
		if attempt > 0 {
			label = fmt.Sprintf("retry %d/%d", attempt, maxRetries)
		}
		willRetry := attempt < maxRetries

		copyStart := time.Now()
		out, err := uploadFile(stageDir, localPath, path)
		copyDur := time.Since(copyStart).Round(time.Second)
		if err != nil {
			lastErr = fmt.Sprintf("upload failed: %v: %s", err, out)
			if willRetry {
				logf("SAVE %s [req %05d] %s: %s%s%s - retrying (upload=%s)", path, reqID, label, colorRed, lastErr, colorReset, copyDur)
			}
			continue
		}

		verifyStart := time.Now()
		algo, failReason := verifySaved(path, written, localHashes)
		verifyDur := time.Since(verifyStart).Round(time.Second)
		debugf("SAVE %s [req %05d] %s: recv=%s copyto=%s verify=%s bytes=%d", path, reqID, label, recvDur, copyDur, verifyDur, written)
		if failReason == "" {
			if algo == "size-only" {
				logf("SAVE %s [req %05d] %s: WARNING verified by size only - pCloud reported no content hash for this object", path, reqID, label)
			}
			if attempt > 0 {
				logf("SAVE %s [req %05d] %s: %sverified OK%s (%d bytes, verified by %s, total %s)", path, reqID, label, colorGreen, colorReset, written, algo, time.Since(saveStart).Round(time.Second))
			}
			w.WriteHeader(http.StatusOK)
			return
		}
		lastErr = failReason
		if willRetry {
			logf("SAVE %s [req %05d] %s: %s%s%s - retrying fresh (upload=%s verify=%s)", path, reqID, label, colorYellow, lastErr, colorReset, copyDur, verifyDur)
		}
		// Always clean up the bad object, even when giving up for good - restic never got a
		// success response for it, so it won't reference it in any index/snapshot, and leaving
		// a wrong-size/corrupt object under its content-hash path is just orphaned garbage that
		// restic's own metadata-only check won't flag as corruption.
		deleteRemote(path) // best-effort cleanup; ignore error (may not exist)
		if willRetry {
			time.Sleep(time.Duration(attempt+1) * 500 * time.Millisecond)
		}
	}

	logf("SAVE %s [req %05d]: %sgiving up%s after %d retries: %s (total %s)", path, reqID, colorRed, colorReset, maxRetries, lastErr, time.Since(saveStart).Round(time.Second))
	http.Error(w, lastErr, http.StatusInternalServerError)
}

func handleDelete(w http.ResponseWriter, repo, kind, name string) {
	path := remotePath(repo, kind, name)
	if err := deleteRemote(path); err != nil {
		http.NotFound(w, nil)
		return
	}
	logf("DELETE %s", path)
	w.WriteHeader(http.StatusOK)
}

// startupProbe performs one real verified write against the remote root at
// startup and logs the outcome, so the log states up front which content hash
// verification will use (pCloud reports sha256 in the EU region, sha1 or md5
// in the US) and whether verified writes work at all. It reuses the same
// upload + verify path as a real save. It never fails startup: a remote that
// is briefly unreachable at boot must not crash-loop the service, and restic
// surfaces real errors at backup time regardless. The probe object is deleted
// again immediately.
func startupProbe() {
	probePath := fmt.Sprintf("%s/.restic-pcloud-probe", rcloneRoot)
	stageDir, err := os.MkdirTemp("", "pcloud-probe-*")
	if err != nil {
		logf("PROBE: could not create a probe staging dir: %v", err)
		return
	}
	defer os.RemoveAll(stageDir)
	localPath := filepath.Join(stageDir, ".restic-pcloud-probe")
	payload := []byte("restic-pcloud-server startup probe\n")
	if err := os.WriteFile(localPath, payload, 0o600); err != nil {
		logf("PROBE: could not write the probe file: %v", err)
		return
	}
	out, err := uploadFile(stageDir, localPath, probePath)
	if err != nil {
		logf("PROBE: upload to %s failed: %v: %s - verified writes are NOT confirmed; saves will fail until the remote works", rcloneRoot, err, out)
		return
	}
	defer deleteRemote(probePath) // best-effort cleanup, whatever the verdict
	localHashes, err := hashFile(localPath)
	if err != nil {
		logf("PROBE: could not hash the probe file: %v", err)
		return
	}
	meta, found := pollMeta(probePath)
	if !found {
		logf("PROBE: the uploaded probe object is not visible on the remote - verified writes are NOT confirmed")
		return
	}
	supported := make([]string, 0, len(meta.hashes))
	for k := range meta.hashes {
		supported = append(supported, k)
	}
	sort.Strings(supported)
	algo, failReason := verifySaved(probePath, int64(len(payload)), localHashes)
	if failReason != "" {
		if requireHash {
			logf("PROBE: verification failed: %s (remote reports hashes: %s) - with -require-hash=true every save will fail until this is fixed", failReason, strings.Join(supported, ", "))
		} else {
			logf("PROBE: verification failed: %s (remote reports hashes: %s) - saves will fall back to size-only checks", failReason, strings.Join(supported, ", "))
		}
		return
	}
	if algo == "size-only" {
		logf("PROBE: write OK but verified by size only - the remote reported no content hash for the probe object")
		return
	}
	logf("PROBE: verified write OK (%d bytes, verified by %s); remote reports hashes: %s", len(payload), algo, strings.Join(supported, ", "))
}

func main() {
	flag.Parse()
	if showVersion {
		fmt.Println(version)
		return
	}
	if rcloneConfig == "" {
		fmt.Fprintln(os.Stderr, "must pass -rclone-config")
		os.Exit(1)
	}
	if transport != "exec" && transport != "rcd" {
		fmt.Fprintf(os.Stderr, "unknown -transport %q (want \"exec\" or \"rcd\")\n", transport)
		os.Exit(1)
	}
	rcClient = &http.Client{} // no overall timeout: RC operations legitimately run for minutes at repository scale
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)
	transportDesc := "exec (one rclone process per operation)"
	if transport == "rcd" {
		transportDesc = fmt.Sprintf("rcd (one rclone daemon, RC API on %s)", rcAddr)
	}
	log.Printf("restic-pcloud-server %s%s%s listening on %s, remote root %s (max-retries=%d, debug=%v, require-hash=%v, transport=%s)", colorCyan, version, colorReset, listenAddr, rcloneRoot, maxRetries, debug, requireHash, transportDesc)
	if transport == "rcd" {
		if err := startRCD(); err != nil {
			log.Fatalf("could not start the rclone daemon transport: %v", err)
		}
	}
	startupProbe()
	log.Fatal(http.ListenAndServe(listenAddr, loggingMiddleware(authMiddleware(handler))))
}
