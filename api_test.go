package main

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"testing"
	"time"
)

// Tests whether the unmarshalling of timestamps are working.
func TestTimeUnMarshalling(t *testing.T) {

	f, err := os.Open("response.json")
	if err != nil {
		t.Error(err)
	}
	defer f.Close()

	bytes, err := ioutil.ReadAll(f)
	if err != nil {
		t.Error(err)
	}

	resp := caIncomingRequestsResponse{}
	err = json.Unmarshal(bytes, &resp)
	if err != nil {
		t.Error(err)
	}

	if resp.IncomingRequests[0].AccessFrom.Time != time.Unix(1543388400, 0) {
		t.Error("incorrect fromtime")
	}
	if resp.IncomingRequests[0].AccessTo.Time != time.Unix(1543600800, 0) {
		t.Error("incorrect totime")
	}

	if resp.IncomingRequests[0].AccountDetails.Properties.LastUsedDate.Time != time.Unix(1543404976, 0) {
		t.Error("incorrect last used date")
	}
}
