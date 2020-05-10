package pongo

import (
	"net"
	"net/http"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/gorilla/sessions"
)

const valueKey = "value"

// SessionProvider is an interface implemented by types that can track
// the active session of a user.
type SessionProvider struct {
	Store sessions.Store

	Name     string
	Domain   string
	HTTPOnly bool
	Secure   bool
	MaxAge   time.Duration
	Codec    samlsp.SessionCodec
}

// DefaultSessionProvider creates a new SessionProvider using the store and options provided
func DefaultSessionProvider(store sessions.Store, opts samlsp.Options) *SessionProvider {
	// for backwards compatibility, support CookieMaxAge
	maxAge := time.Hour
	if opts.CookieMaxAge > 0 {
		maxAge = opts.CookieMaxAge
	}

	// for backwards compatibility, support CookieName
	cookieName := "token"
	if opts.CookieName != "" {
		cookieName = opts.CookieName
	}

	// for backwards compatibility, support CookieDomain
	cookieDomain := opts.URL.Host
	if opts.CookieDomain != "" {
		cookieDomain = opts.CookieDomain
	}

	// for backwards compatibility, support CookieSecure
	cookieSecure := opts.URL.Scheme == "https"
	if opts.CookieSecure {
		cookieSecure = true
	}

	return &SessionProvider{
		Store: store,

		Name:     cookieName,
		Domain:   cookieDomain,
		MaxAge:   maxAge,
		HTTPOnly: true,
		Secure:   cookieSecure,
		Codec:    samlsp.DefaultSessionCodec(opts),
	}
}

// CreateSession is called when we have received a valid SAML assertion and
// should create a new session and modify the http response accordingly, e.g. by
// setting a cookie.
func (s *SessionProvider) CreateSession(w http.ResponseWriter, r *http.Request, assertion *saml.Assertion) error {
	// Cookies should not have the port attached to them so strip it off
	if domain, _, err := net.SplitHostPort(s.Domain); err == nil {
		s.Domain = domain
	}

	samlSess, err := s.Codec.New(assertion)
	if err != nil {
		return err
	}

	value, err := s.Codec.Encode(samlSess)
	if err != nil {
		return err
	}

	session, err := s.Store.New(r, s.Name)
	if err != nil {
		return err
	}

	session.Values[valueKey] = value

	session.Options.Domain = s.Domain
	session.Options.MaxAge = int(s.MaxAge.Seconds())
	session.Options.HttpOnly = s.HTTPOnly
	session.Options.Secure = s.Secure || r.URL.Scheme == "https"
	session.Options.Path = "/"

	return session.Save(r, w)
}

// DeleteSession is called to modify the response such that it removed the current
// session, e.g. by deleting a cookie.
func (s *SessionProvider) DeleteSession(w http.ResponseWriter, r *http.Request) error {
	session, err := s.Store.Get(r, s.Name)
	if err != nil {
		return err
	}

	session.Options.MaxAge = -1

	return session.Save(r, w)
}

// GetSession returns the current Session associated with the request, or
// ErrNoSession if there is no valid session.
func (s *SessionProvider) GetSession(r *http.Request) (samlsp.Session, error) {
	session, err := s.Store.Get(r, s.Name)
	if err != nil {
		return nil, err
	}

	v, ok := session.Values[valueKey]
	if !ok {
		return nil, samlsp.ErrNoSession
	}

	samlSession, err := s.Codec.Decode(v.(string))
	if err != nil {
		return nil, samlsp.ErrNoSession
	}

	return samlSession, nil
}
