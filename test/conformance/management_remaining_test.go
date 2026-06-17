package conformance_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"aggregator-provision/internal/httpapi"
)

func TestAGGRMGMT005(t *testing.T) { assertFlowNotAdvertised(t, "none") }
func TestAGGRMGMT006(t *testing.T) { assertFlowNotAdvertised(t, "none") }
func TestAGGRMGMT008(t *testing.T) { assertFlowNotAdvertised(t, "none") }
func TestAGGRMGMT009(t *testing.T) { assertFlowNotAdvertised(t, "none") }
func TestAGGRMGMT010(t *testing.T) { assertFlowNotAdvertised(t, "none") }

func TestAGGRMGMT015(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	desc := provision(t, server)

	rec := requestWithBearer(server, http.MethodDelete, mustPath(desc.ID), "", nil, "valid-management-token")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE aggregator status = %d, want 204", rec.Code)
	}
}

func TestAGGRMGMT016(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	desc := provision(t, server)

	deleteRec := requestWithBearer(server, http.MethodDelete, mustPath(desc.ID), "", nil, "valid-management-token")
	if deleteRec.Code != http.StatusNoContent {
		t.Fatalf("DELETE aggregator status = %d, want 204", deleteRec.Code)
	}
	rec := requestWithBearer(server, http.MethodGet, "/registration", "", nil, "valid-management-token")
	var aggregators []string
	if err := json.Unmarshal(rec.Body.Bytes(), &aggregators); err != nil {
		t.Fatalf("management GET must return JSON array of URLs: %v", err)
	}
	for _, agg := range aggregators {
		if agg == desc.ID {
			t.Fatalf("management GET still lists deleted aggregator %q", desc.ID)
		}
	}
}

func TestAGGRMGMT017(t *testing.T) { assertFlowNotAdvertised(t, "authorization_code") }
func TestAGGRMGMT018(t *testing.T) { assertFlowNotAdvertised(t, "authorization_code") }
func TestAGGRMGMT019(t *testing.T) { assertFlowNotAdvertised(t, "authorization_code") }
func TestAGGRMGMT020(t *testing.T) { assertUnsupportedFlowDoesNotLeakSecrets(t, "authorization_code") }
func TestAGGRMGMT021(t *testing.T) { assertFlowNotAdvertised(t, "device_code") }
func TestAGGRMGMT022(t *testing.T) { assertFlowNotAdvertised(t, "device_code") }
func TestAGGRMGMT023(t *testing.T) { assertFlowNotAdvertised(t, "device_code") }
func TestAGGRMGMT024(t *testing.T) { assertUnsupportedFlowDoesNotLeakSecrets(t, "device_code") }
func TestAGGRMGMT025(t *testing.T) { assertFlowNotAdvertised(t, "device_code") }
func TestAGGRMGMT026(t *testing.T) { assertFlowNotAdvertised(t, "authorization_code") }
func TestAGGRMGMT027(t *testing.T) { assertFlowNotAdvertised(t, "authorization_code") }
func TestAGGRMGMT028(t *testing.T) { assertFlowNotAdvertised(t, "authorization_code") }
func TestAGGRMGMT029(t *testing.T) { assertFlowNotAdvertised(t, "authorization_code") }
func TestAGGRMGMT030(t *testing.T) { assertFlowNotAdvertised(t, "authorization_code") }
func TestAGGRMGMT031(t *testing.T) { assertUnsupportedFlowDoesNotLeakSecrets(t, "authorization_code") }
func TestAGGRMGMT032(t *testing.T) { assertFlowNotAdvertised(t, "device_code") }
func TestAGGRMGMT033(t *testing.T) { assertUnsupportedFlowDoesNotLeakSecrets(t, "device_code") }
func TestAGGRMGMT034(t *testing.T) { assertFlowNotAdvertised(t, "device_code") }
func TestAGGRMGMT035(t *testing.T) { assertFlowNotAdvertised(t, "device_code") }
func TestAGGRMGMT036(t *testing.T) { assertFlowNotAdvertised(t, "device_code") }
func TestAGGRMGMT037(t *testing.T) { assertFlowNotAdvertised(t, "authorization_code") }
func TestAGGRMGMT038(t *testing.T) { assertUnsupportedFlowDoesNotLeakSecrets(t, "authorization_code") }
func TestAGGRMGMT039(t *testing.T) { assertFlowNotAdvertised(t, "device_code") }
func TestAGGRMGMT040(t *testing.T) { assertUnsupportedFlowDoesNotLeakSecrets(t, "device_code") }

func TestAGGRMGMT041(t *testing.T) {
	assertInvalidManagementRequest(t, `{"management_flow":"none","aggregator":"https://aggregator.example/aggregators/agg-1"}`)
}

func TestAGGRMGMT042(t *testing.T) {
	assertInvalidManagementRequest(t, `{"management_flow":"provision","aggregator":"https://aggregator.example/aggregators/agg-1"}`)
}

func TestAGGRMGMT043(t *testing.T) {
	assertInvalidManagementRequest(t, `{"management_flow":"authorization_code","state":"invalid","code":"valid","redirect_uri":"https://client.example/cb"}`)
}

func TestAGGRMGMT044(t *testing.T) {
	assertInvalidManagementRequest(t, `{"management_flow":"authorization_code","state":"valid","redirect_uri":"https://client.example/cb"}`)
}

func TestAGGRMGMT045(t *testing.T) {
	assertInvalidManagementRequest(t, `{"management_flow":"authorization_code","state":"valid","code":"valid","redirect_uri":"not a url"}`)
}

func TestAGGRMGMT046(t *testing.T) {
	assertInvalidManagementRequest(t, `{"management_flow":"device_code","state":"expired"}`)
}

func TestAGGRMGMT047(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	rec := request(server, http.MethodGet, "/aggregators/missing", "", nil)
	if rec.Code != http.StatusNotFound && rec.Code != http.StatusForbidden {
		t.Fatalf("unknown aggregator status = %d, want 404 or 403", rec.Code)
	}
}

func TestAGGRMGMT048(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	rec := request(server, http.MethodGet, "/aggregators/not-owned", "", nil)
	if rec.Code != http.StatusNotFound && rec.Code != http.StatusForbidden {
		t.Fatalf("other-subject aggregator status = %d, want 404 or 403", rec.Code)
	}
}

func TestAGGRMGMT049(t *testing.T) {
	assertInvalidManagementRequest(t, `{"management_flow":"authorization_code","state":"valid","code":"invalid","redirect_uri":"https://client.example/cb"}`)
}

func TestAGGRMGMT050(t *testing.T) {
	assertInvalidManagementRequest(t, `{"management_flow":"provision","aggregator":"not a url"}`)
}

func TestAGGRMGMT055(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	rec := request(server, http.MethodPost, "/registration", "application/json", []byte(`{"management_flow":"provision"}`))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized provision status = %d, want 401", rec.Code)
	}
	assertNoAggregators(t, server)
}

func TestAGGRMGMT056(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	rec := requestWithBearer(server, http.MethodPost, "/registration", "application/json", []byte(`{"management_flow":"provision"}`), "invalid-management-token")

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("invalid-token provision status = %d, want 401", rec.Code)
	}
	assertNoAggregators(t, server)
}

func TestAGGRMGMT057OnlyProvisioningOwnerCanDeleteAggregator(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	desc := provision(t, server)

	otherDelete := requestWithBearer(server, http.MethodDelete, mustPath(desc.ID), "", nil, "other-owner-token")
	if otherDelete.Code != http.StatusUnauthorized {
		t.Fatalf("other-owner DELETE status = %d, want 401", otherDelete.Code)
	}
	ownerDelete := requestWithBearer(server, http.MethodDelete, mustPath(desc.ID), "", nil, "valid-management-token")
	if ownerDelete.Code != http.StatusNoContent {
		t.Fatalf("owner DELETE status = %d, want 204", ownerDelete.Code)
	}
}

func assertFlowNotAdvertised(t *testing.T, flow string) {
	t.Helper()

	desc := httpapi.BuildServerDescription(httpapi.DefaultConfig("https://aggregator.example"))
	if contains(desc.SupportedManagementFlows, flow) {
		t.Fatalf("%s flow is advertised; this test must exercise the lifecycle instead of the guard", flow)
	}
}

func assertUnsupportedFlowDoesNotLeakSecrets(t *testing.T, flow string) {
	t.Helper()

	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	rec := requestWithBearer(server, http.MethodPost, "/registration", "application/json", []byte(`{"management_flow":"`+flow+`"}`), "valid-management-token")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("%s flow status = %d, want 400", flow, rec.Code)
	}
	body := strings.ToLower(rec.Body.String())
	for _, forbidden := range []string{"access_token", "refresh_token", "client_secret", "password", "credential", "device_code", "code_verifier"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("%s response leaks confidential field %q: %s", flow, forbidden, rec.Body.String())
		}
	}
}

func assertInvalidManagementRequest(t *testing.T, body string) {
	t.Helper()

	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	rec := requestWithBearer(server, http.MethodPost, "/registration", "application/json", []byte(body), "valid-management-token")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid management request status = %d, want 400; body: %s", rec.Code, rec.Body.String())
	}
}

func assertNoAggregators(t *testing.T, server *httpapi.Server) {
	t.Helper()

	rec := requestWithBearer(server, http.MethodGet, "/registration", "", nil, "valid-management-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("aggregator list status = %d, want 200", rec.Code)
	}
	var aggregators []httpapi.AggregatorDescription
	if err := json.Unmarshal(rec.Body.Bytes(), &aggregators); err != nil {
		t.Fatalf("management GET must return JSON array: %v", err)
	}
	if len(aggregators) != 0 {
		t.Fatalf("unauthorized provision created aggregators: %#v", aggregators)
	}
}
