package pongo

import (
	"context"
	"net/http"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/logger"
	"github.com/crewjam/saml/samlsp"
	"github.com/gorilla/sessions"
)

// New creates a new Middleware with the default providers for the
// given options.
//
// You can customize the behavior of the middleware in more detail by
// replacing and/or changing Session, RequestTracker, and ServiceProvider
// in the returned Middleware.
func New(store sessions.Store, opts samlsp.Options) (*samlsp.Middleware, error) {
	// for backwards compatibility, support Logger
	onError := samlsp.DefaultOnError
	if opts.Logger != nil {
		onError = defaultOnErrorWithLogger(opts.Logger)
	}

	// for backwards compatibility, support IDPMetadataURL
	if opts.IDPMetadataURL != nil && opts.IDPMetadata == nil {
		httpClient := opts.HTTPClient
		if httpClient == nil {
			httpClient = http.DefaultClient
		}
		metadata, err := samlsp.FetchMetadata(context.Background(), httpClient, *opts.IDPMetadataURL)
		if err != nil {
			return nil, err
		}
		opts.IDPMetadata = metadata
	}

	m := &samlsp.Middleware{
		ServiceProvider: samlsp.DefaultServiceProvider(opts),
		OnError:         onError,
		Session:         DefaultSessionProvider(store, opts),
	}
	m.RequestTracker = DefaultRequestTracker(store, opts, &m.ServiceProvider)

	return m, nil
}

// defaultOnErrorWithLogger is like DefaultOnError but accepts a custom logger.
// This is a bridge for backward compatibility with people use provide the
// deprecated Logger options field to New().
func defaultOnErrorWithLogger(log logger.Interface) samlsp.ErrorFunction {
	return func(w http.ResponseWriter, r *http.Request, err error) {
		if parseErr, ok := err.(*saml.InvalidResponseError); ok {
			log.Printf("WARNING: received invalid saml response: %s (now: %s) %s",
				parseErr.Response, parseErr.Now, parseErr.PrivateErr)
		} else {
			log.Printf("ERROR: %s", err)
		}
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
	}
}
