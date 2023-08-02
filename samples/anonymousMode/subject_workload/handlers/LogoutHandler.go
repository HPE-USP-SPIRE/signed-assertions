package handlers

import "net/http"

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	session, err := sessionStore.Get(r, "okta-hosted-login-session-store")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	delete(session.Values, "id_token")
	delete(session.Values, "access_token")
	delete(session.Values, "DASVIDToken")

	session.Save(r, w)

	http.Redirect(w, r, "/", http.StatusFound)
}
