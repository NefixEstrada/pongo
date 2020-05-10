package pongo

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/gorilla/sessions"
)

// RequestTracker tracks pending authentication requests.
type RequestTracker struct {
	Store sessions.Store

	ServiceProvider *saml.ServiceProvider
	NamePrefix      string
	Codec           samlsp.TrackedRequestCodec
	MaxAge          time.Duration
}

// DefaultRequestTracker creates a new RequestTracker using the store, the saml.SessionProvider and options provided
func DefaultRequestTracker(store sessions.Store, opts samlsp.Options, serviceProvider *saml.ServiceProvider) *RequestTracker {
	return &RequestTracker{
		Store: store,

		ServiceProvider: serviceProvider,
		NamePrefix:      "saml_",
		Codec:           samlsp.DefaultTrackedRequestCodec(opts),
		MaxAge:          saml.MaxIssueDelay,
	}
}

// TrackRequest starts tracking the SAML request with the given ID. It returns an
// `index` that should be used as the RelayState in the SAMl request flow.
func (t *RequestTracker) TrackRequest(w http.ResponseWriter, r *http.Request, samlRequestID string) (string, error) {
	trackedRequest := samlsp.TrackedRequest{
		Index:         base64.RawURLEncoding.EncodeToString(randomBytes(42)),
		SAMLRequestID: samlRequestID,
		URI:           r.URL.String(),
	}

	signedTrackedRequest, err := t.Codec.Encode(trackedRequest)
	if err != nil {
		return "", err
	}

	session, err := t.Store.New(r, t.name(trackedRequest.Index))
	if err != nil {
		return "", err
	}

	session.Values[valueKey] = signedTrackedRequest

	session.Options.MaxAge = int(t.MaxAge.Seconds())
	session.Options.HttpOnly = true
	session.Options.Secure = t.ServiceProvider.AcsURL.Scheme == "https"
	session.Options.Path = t.ServiceProvider.AcsURL.Path

	if err := session.Save(r, w); err != nil {
		return "", err
	}

	return trackedRequest.Index, nil
}

// StopTrackingRequest stops tracking the SAML request given by index, which is a string
// previously returned from TrackRequest
func (t *RequestTracker) StopTrackingRequest(w http.ResponseWriter, r *http.Request, index string) error {
	session, err := t.Store.Get(r, t.name(index))
	if err != nil {
		return err
	}

	session.Options.MaxAge = -1

	return session.Save(r, w)
}

// GetTrackedRequests returns all the pending tracked requests
func (t *RequestTracker) GetTrackedRequests(r *http.Request) []samlsp.TrackedRequest {
	reqs := []samlsp.TrackedRequest{}

	for _, cookie := range r.Cookies() {
		if !strings.HasPrefix(cookie.Name, t.NamePrefix) {
			continue
		}

		session, err := t.Store.Get(r, cookie.Name)
		if err != nil {
			continue
		}

		if len(session.Values) == 0 {
			session.Options.MaxAge = -1
			continue
		}

		trackedRequest, err := t.Codec.Decode(session.Values[valueKey].(string))
		if err != nil {
			continue
		}

		index := strings.TrimPrefix(cookie.Name, t.NamePrefix)
		if index != trackedRequest.Index {
			continue
		}

		reqs = append(reqs, *trackedRequest)
	}

	return reqs
}

// GetTrackedRequest returns a pending tracked request.
func (t *RequestTracker) GetTrackedRequest(r *http.Request, index string) (*samlsp.TrackedRequest, error) {
	session, err := t.Store.Get(r, t.name(index))
	if err != nil {
		return nil, err
	}

	if len(session.Values) == 0 {
		return nil, http.ErrNoCookie
	}

	trackedRequest, err := t.Codec.Decode(session.Values[valueKey].(string))
	if err != nil {
		return nil, err
	}

	if trackedRequest.Index != index {
		return nil, fmt.Errorf("expected index %q, got %q", index, trackedRequest.Index)
	}

	return trackedRequest, nil
}

func (t *RequestTracker) name(i string) string {
	return t.NamePrefix + i
}
