package feed

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

var urlFmt = "https://osv-vulnerabilities.storage.googleapis.com/%s/modified_id.csv"

const delimiter = ","

func parseTime(val string) (time.Time, error) {
	return time.Parse(time.RFC3339, val)
}

type ModResult struct {
	Mod chan<- string
	Err error
}

func NewModResult() *ModResult {
	return &ModResult{
		Mod: make(chan<- string),
	}
}

func Modified(ctx context.Context, ecosystem osvschema.Ecosystem, cutoff time.Time) (*ModResult, error) {
	url := fmt.Sprintf(urlFmt, ecosystem)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	out := NewModResult()

	go func() {
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := scanner.Text()
			parts := strings.Split(line, delimiter)

			if len(parts) < 2 {
				out.Err = fmt.Errorf("invalid line '%s'", line)
				break
			}

			t, err := parseTime(parts[0])
			if err != nil {
				out.Err = fmt.Errorf("invalid line date '%s'", line)
				break
			}

			if t.Before(cutoff) {
				break
			}

			out.Mod <- parts[1]
		}

		if err := scanner.Err(); err != nil {
			out.Err = err
		}

		close(out.Mod)
	}()

	return out, nil
}
