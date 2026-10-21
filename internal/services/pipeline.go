package services

import (
	"log"
	"time"

	"github.com/KelvinNgeno/sentryhive/internal/alert"
	"github.com/KelvinNgeno/sentryhive/internal/geoip"
	"github.com/KelvinNgeno/sentryhive/internal/store"
)

// Pipeline is handed to every protocol listener so they all record events,
// resolve geo data, and fire alerts the same way. Keeping this in one
// place means adding a fifth protocol later doesn't mean re-wiring
// storage/alerting logic again.
type Pipeline struct {
	Store  *store.SQLiteStore
	Geo    geoip.Lookup
	Alerts *alert.Dispatcher
}

func (p *Pipeline) Record(e *store.Event) {
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}

	if res, err := p.Geo.Resolve(e.SourceIP); err == nil {
		e.Country, e.City, e.ASN, e.ISP = res.Country, res.City, res.ASN, res.ISP
	}

	if err := p.Store.Save(e); err != nil {
		log.Printf("[store] failed to save event: %v", err)
	}

	if err := p.Alerts.Notify(e); err != nil {
		log.Printf("[alert] failed to dispatch: %v", err)
	}

	log.Printf("[%s] %s (%s, %s) user=%q pass=%q severity=%s",
		e.Protocol, e.SourceIP, e.City, e.Country, e.Username, e.Password, e.Severity)
}
