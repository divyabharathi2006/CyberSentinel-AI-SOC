def test_json_csv_pdf_reports(client, analyst_headers):
    for format_name, content_type in (
        ("json", "application/json"), ("csv", "text/csv"), ("pdf", "application/pdf"),
    ):
        response = client.get(f"/api/reports?type=alerts&format={format_name}", headers=analyst_headers)
        assert response.status_code == 200
        assert content_type in response.headers["Content-Type"]
        assert "attachment" in response.headers["Content-Disposition"]
        if format_name == "pdf":
            assert response.data.startswith(b"%PDF-")
            assert len(response.data) > 1000


def test_invalid_report_type_and_format(client, analyst_headers):
    assert client.get("/api/reports?type=unknown", headers=analyst_headers).status_code == 400
    assert client.get("/api/reports?format=xml", headers=analyst_headers).status_code == 400
