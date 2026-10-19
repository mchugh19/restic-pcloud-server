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
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// version is set at build time via -ldflags "-X main.version=<short-sha>" (see Dockerfile/CI
// workflow); it stays "dev" for a local `go build` so that's never mistaken for a real build.
var version = "dev"

var (
	rcloneRoot   string // fixed rclone remote:path root, e.g. "pcloud:Backups/restic" - each restic repo gets its own subfolder under this, named by the URL path segment the client requests
	rcloneConfig string
	caCertPath   string
	maxRetries   int
	requireHash  bool
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
	flag.StringVar(&caCertPath, "ca-cert", "", "CA bundle for rclone's TLS verification (only needed when the platform's own verifier is blocked, e.g. macOS sandbox testing: /etc/ssl/cert.pem; leave unset on a normal Linux host)")
	flag.IntVar(&maxRetries, "max-retries", 3, "max fresh re-upload retries after a failed verify (so the initial write plus this many retries is the total number of tries)")
	flag.BoolVar(&requireHash, "require-hash", true, "fail verification when pCloud reports no content hash for a saved object, so size is the only thing that can be checked (pCloud reports at least one of sha256/sha1/md5 in both regions, so this should not happen; turn off only for a remote that cannot report hashes at all)")
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

// remoteMetaWithRetry is remoteMetaOnce with the same retry-on-not-found behavior as
// remoteSize, for the same reason: pCloud's eventual consistency can hide a just-written
// object from one stat call and show it on the next.
func remoteMetaWithRetry(path string) (remoteMeta, bool) {
	const attempts = 4
	const delay = 800 * time.Millisecond
	for attempt := 1; attempt <= attempts; attempt++ {
		if meta, ok := remoteMetaOnce(path); ok {
			if attempt > 1 {
				debugf("STAT %s: metadata found on attempt %d/%d after earlier not-found", path, attempt, attempts)
			}
			return meta, true
		}
		if attempt < attempts {
			time.Sleep(delay)
		}
	}
	return remoteMeta{}, false
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
func verifySaved(path string, written int64, localHashes map[string]string) (string, string) {
	meta, found := remoteMetaWithRetry(path)
	if !found {
		// Same wording as the size-only version used: after the metadata call's own
		// internal retries the object still isn't visible (or the call itself failed).
		return "", fmt.Sprintf("wrote %d bytes but pCloud still shows it missing", written)
	}
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
			return algo, ""
		}
	}
	if requireHash {
		return "", "pCloud reported no content hash for the object, so its bytes cannot be verified"
	}
	return "size-only", ""
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
	args := []string{"lsjson"}
	if kind == "data" {
		args = append(args, "-R")
	}
	args = append(args, remoteDir(repo, kind))
	out, err := runRclone(args...)
	var entries []lsjsonEntry
	if err == nil {
		json.Unmarshal(out, &entries)
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
	tmp, err := os.CreateTemp("", "pcloud-repair-*.tmp")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()

	recvStart := time.Now()
	written, err := io.Copy(tmp, r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tmp.Close()
	recvDur := time.Since(recvStart)

	path := remotePath(repo, kind, name)

	// Hash the received bytes once, up front: every retry re-uploads this same temp
	// file, so its hashes are the reference for every attempt's verification.
	localHashes, err := hashFile(tmp.Name())
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
		out, err := runRclone("copyto", tmp.Name(), path)
		copyDur := time.Since(copyStart).Round(time.Second)
		if err != nil {
			lastErr = fmt.Sprintf("copyto failed: %v: %s", err, out)
			if willRetry {
				logf("SAVE %s [req %05d] %s: %s%s%s - retrying (copyto=%s)", path, reqID, label, colorRed, lastErr, colorReset, copyDur)
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
			logf("SAVE %s [req %05d] %s: %s%s%s - retrying fresh (copyto=%s verify=%s)", path, reqID, label, colorYellow, lastErr, colorReset, copyDur, verifyDur)
		}
		// Always clean up the bad object, even when giving up for good - restic never got a
		// success response for it, so it won't reference it in any index/snapshot, and leaving
		// a wrong-size/corrupt object under its content-hash path is just orphaned garbage that
		// restic's own metadata-only check won't flag as corruption.
		runRclone("deletefile", path) // best-effort cleanup; ignore error (may not exist)
		if willRetry {
			time.Sleep(time.Duration(attempt+1) * 500 * time.Millisecond)
		}
	}

	logf("SAVE %s [req %05d]: %sgiving up%s after %d retries: %s (total %s)", path, reqID, colorRed, colorReset, maxRetries, lastErr, time.Since(saveStart).Round(time.Second))
	http.Error(w, lastErr, http.StatusInternalServerError)
}

func handleDelete(w http.ResponseWriter, repo, kind, name string) {
	path := remotePath(repo, kind, name)
	if _, err := runRclone("deletefile", path); err != nil {
		http.NotFound(w, nil)
		return
	}
	w.WriteHeader(http.StatusOK)
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
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)
	log.Printf("restic-pcloud-server %s%s%s listening on %s, remote root %s (max-retries=%d, debug=%v, require-hash=%v)", colorCyan, version, colorReset, listenAddr, rcloneRoot, maxRetries, debug, requireHash)
	log.Fatal(http.ListenAndServe(listenAddr, loggingMiddleware(authMiddleware(handler))))
}
