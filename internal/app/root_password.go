package app

import (
	"encoding/json"
	"net/http"
	"strings"
)

// rootPasswordRequest sets a root password on a vanilla router whose empty
// shadow libssh2 rejects. It deliberately goes through the installer's
// Dropbear-compatible SSH path, not Archy's libssh2 path.
type rootPasswordRequest struct {
	IP          string `json:"ip"`
	Password    string `json:"password"`
	NewPassword string `json:"new_password"`
}

// validNewRootPassword rejects blanks and control characters. Quotes and
// spaces are allowed and are single-quoted by cleanSlatePasswordCommand.
func validNewRootPassword(pw string) bool {
	if len(pw) < 8 || len(pw) > 63 {
		return false
	}
	return !strings.ContainsAny(pw, "\x00\r\n")
}

func handleSetRootPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	var req rootPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if strings.TrimSpace(req.IP) == "" {
		writeError(w, http.StatusBadRequest, "ip is required")
		return
	}
	if !validNewRootPassword(req.NewPassword) {
		writeError(w, http.StatusBadRequest, "new_password must be 8-63 characters with no newlines or NUL")
		return
	}

	client := sshConnect(req.IP, req.Password)
	// An empty root shadow makes Dropbear accept any password; a blank attempt
	// is not proof the typed one was wrong.
	if client == nil && req.Password != "" {
		client = sshConnect(req.IP, "")
	}
	if client == nil {
		writeRouterDialFailure(w, req.IP, "", "cannot connect to router via SSH")
		return
	}
	defer client.Close()

	// Never log or echo the secret. The output only proves passwd accepted it.
	out := sshRun(client, cleanSlatePasswordCommand(req.NewPassword))
	if !strings.Contains(out, "password for root changed") {
		writeError(w, http.StatusBadGateway, "root password was not set: "+truncate(out, 160))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":              true,
		"ip":              req.IP,
		"password_status": "accepted",
	})
}
