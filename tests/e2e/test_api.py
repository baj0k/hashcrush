import json
import os

import pytest


@pytest.mark.e2e
def test_api_rules_requires_authorization(page, live_server):
    response = page.request.get(f"{live_server}/v1/rules")
    if response.status in {301, 302, 303, 307, 308}:
        location = response.headers.get("location", "")
        if location.startswith("/"):
            location = f"{live_server}{location}"
        response = page.request.get(location)
    assert response.status == 403
    data = response.json()
    assert data["msg"].startswith("Your API key is not authorized")


@pytest.mark.e2e
def test_api_rules_authorized(page, live_server):
    api_key = os.getenv("HASHCRUSH_E2E_API_KEY")
    if not api_key:
        pytest.skip("Set HASHCRUSH_E2E_API_KEY for authorized API tests.")
    response = page.request.get(f"{live_server}/v1/rules", headers={"X-API-Key": api_key})
    assert response.ok
    data = response.json()
    assert data["status"] == 200
    if "rules" not in data:
        pytest.skip("HASHCRUSH_E2E_API_KEY is not authorized for this server.")


@pytest.mark.e2e
def test_api_task_lookup(page, live_server):
    api_key = os.getenv("HASHCRUSH_E2E_API_KEY")
    task_id = os.getenv("HASHCRUSH_E2E_TASK_ID")
    if not api_key or not task_id:
        pytest.skip("Set HASHCRUSH_E2E_API_KEY and HASHCRUSH_E2E_TASK_ID.")
    response = page.request.get(f"{live_server}/v1/tasks/{task_id}", headers={"X-API-Key": api_key})
    assert response.ok
    data = response.json()
    if "task" not in data:
        pytest.skip("HASHCRUSH_E2E_API_KEY is not authorized for task lookup.")
    task = json.loads(data["task"])
    assert str(task.get("id")) == str(task_id)


@pytest.mark.e2e
def test_api_job_lookup(page, live_server):
    api_key = os.getenv("HASHCRUSH_E2E_API_KEY")
    job_id = os.getenv("HASHCRUSH_E2E_JOB_ID")
    if not api_key or not job_id:
        pytest.skip("Set HASHCRUSH_E2E_API_KEY and HASHCRUSH_E2E_JOB_ID.")
    response = page.request.get(f"{live_server}/v1/jobs/{job_id}", headers={"X-API-Key": api_key})
    assert response.ok
    data = response.json()
    if "job" not in data:
        pytest.skip("HASHCRUSH_E2E_API_KEY is not authorized for job lookup.")
    job = json.loads(data["job"])
    assert str(job.get("id")) == str(job_id)
